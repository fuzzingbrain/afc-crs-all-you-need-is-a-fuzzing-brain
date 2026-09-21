#!/usr/bin/env python3
"""Batch call-graph driver for the FBv2 arm (Arm B) of the CyberGym-E2E study.

Runs e2e_build_graph.sh for every task (bounded concurrency -- each is a memory-
heavy LTO bitcode build), then validates the produced graph and wires it into the
task JSON:

  graph OK  -> callgraph.json has >0 nodes AND the fuzzer entry
               (LLVMFuzzerTestOneInput) is present as a node
            -> task JSON: enable_static_analysis=true, prebuild_dir set
  graph BAD -> (autotools/LTO harvest failure, etc.)
            -> task JSON left enable_static_analysis=false (disclosed)

Also reports, per task, whether the GT crash function (first app frame of
gt_crash.log) appears as a graph node -- informational, NOT a gate (a valid graph
may reach the sink only via indirect calls).

    python build_graphs_arm.py --list sample_30_libfuzzer_seed42.txt --parallel 3
"""
import argparse, json, os, re, subprocess, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILDS = HERE / "builds"
ARM = Path(os.environ.get("FBV2_ARM_DIR", "/tmp/claude-1000/e2e-fbv2-arm"))
GRAPH_SH = HERE / "e2e_build_graph.sh"
SKIP_FRAME = re.compile(r"__sanitizer|fuzzer::|__asan|__msan|__ubsan|__interceptor|"
                        r"LLVMFuzzer|asan_|operator new|::malloc|__libc|^malloc$|^free$|"
                        r"MemcmpInterceptor|scanf|printf")


def work_id(task):
    proj, idpart = task.split("/", 1)
    return f"{proj}_{idpart.split('_')[-1]}"


# primary harness (repo-relative) per work_id, from build_fbv2_arm.py's manifest;
# passed to the graph script as HARNESS_REL so step-3 compiles the exact entry.
def _load_harness_map():
    mp = {}
    f = ARM / "build_manifest.json"
    if f.exists():
        for row in json.load(open(f)):
            if row.get("srcs"):
                mp[row["wid"]] = row["srcs"][0]
    return mp


HARNESS_MAP = _load_harness_map()

# Per-task extra include roots (container paths) for harnesses whose headers the
# generic + auto-resolver can't reach: transitive helper headers, no-slash or ..
# includes. Derived by reading the real "fatal error: X not found" per task.
#   kamailio  fuzz_parse_msg.c -> #include "../parser/sdp/sdp.h" (at src/core/)
#   yara      elf_fuzzer.cc    -> #include <yara.h>             (libyara/include/)
#   libspectre spectre.h (transitive) -> libspectre/spectre-status.h
#   ghostscript_414383025 gs_fuzzlib.h (transitive) -> base/gserrors.h (ghostpdl/)
EXTRA_INC = {
    "yara_13956": "-I/src/yara/libyara/include",
    "libspectre_21670": "-I/src/libspectre",          # + generated spectre-version.h
    "libheif_42536679": "-I/src/libheif/libheif/api",  # + generated heif_version.h
    "ghostscript_414383025": "-I/src/ghostpdl",
    # kamailio fuzz_parse_msg.c: relative ../parser include (needs -I a child of
    # src/core so `..` cancels) + the arch/lock defines its Makefile sets.
    "kamailio_38307": "-I/src/kamailio/src/core/parser -D__CPU_x86_64 -DFAST_LOCK "
                      "-D__OS_linux -DCC_GCC_LIKE_ASM -DNAME='\"k\"' -DVERSION='\"x\"' "
                      "-DARCH='\"x\"' -DOS='\"linux\"' -DOS_QUOTED='\"linux\"'",
    # ffmpeg: library harvested; the harness needs its per-target codec define
    # (build.sh FFMPEG_CODEC=AV_CODEC_ID_<c>) or IO_FLAT for the demuxer, + -Iffmpeg.
    "ffmpeg_42538001": "-DFFMPEG_CODEC=AV_CODEC_ID_NOTCHLC -I/src/ffmpeg",
    "ffmpeg_42537562": "-DFFMPEG_CODEC=AV_CODEC_ID_LSCR -I/src/ffmpeg",
    "ffmpeg_383825642": "-DIO_FLAT=1 -I/src/ffmpeg",
}

# Immediate library/wrapper sources to also compile to bitcode (glob, container
# paths) for projects whose build did not emit the API layer as bitcode, leaving
# the harness's direct callees as leaves (7/39-node graphs). Compiling the wrapper
# connects harness -> wrapper -> (already-harvested) backend.
EXTRA_SRC = {
    "libspectre_21670": "/src/libspectre/libspectre/*.c",
    "libheif_42536679": "/src/libheif/libheif/*.cc /src/libheif/libheif/*/*.cc",
}

# Per-task sed applied to build.sh before compile. ffmpeg's own ./configure only
# puts -I in --extra-cflags, so libavcodec builds native (no bitcode); inject -flto
# so the codec/demuxer sources are harvestable and the vuln decode is in the graph.
_FF_LTO = r's#--extra-cflags="#--extra-cflags="-flto -fno-inline-functions #g'
GRAPH_BUILD_SED = {
    "ffmpeg_42538001": _FF_LTO,
    "ffmpeg_42537562": _FF_LTO,
    "ffmpeg_383825642": _FF_LTO,
}


def gt_frame(task):
    p = BUILDS / task / "gt_crash.log"
    if not p.exists():
        return None
    txt = p.read_text(errors="replace")
    for m in re.finditer(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)", txt):
        if not SKIP_FRAME.search(m.group(1)):
            return m.group(1)
    return None


def run_graph(task, mem_mb, cpus, timeout):
    wid = work_id(task)
    ws = ARM / wid
    log = ws / "graphgen.log"
    env = dict(os.environ, GRAPH_MEM_MB=str(mem_mb), GRAPH_CPUS=str(cpus),
               HARNESS_REL=HARNESS_MAP.get(wid, ""),
               EXTRA_INC=EXTRA_INC.get(wid, ""),
               EXTRA_SRC=EXTRA_SRC.get(wid, ""),
               GRAPH_BUILD_SED=GRAPH_BUILD_SED.get(wid, ""))
    # Prefer the task's own arvo build_image for graph-gen: it has every project
    # dependency baked in (libarchive, libgcrypt, zlib, boost, correct meson...),
    # which base-builder lacks. Its oss-fuzz `compile` still honours our
    # FUZZING_ENGINE=libfuzzer + SANITIZER_FLAGS=-flto (the AFL hardcoding is in the
    # task's compile.sh, which we do not run). Fall back to the deps-augmented
    # e2e-graph-builder image when build_image is just base-builder. Explicit
    # GRAPH_IMG in the environment still overrides this.
    if "GRAPH_IMG" not in os.environ:
        try:
            bi = json.load(open(BUILDS / task / "meta.json")).get("build_image", "")
        except Exception:
            bi = ""
        # deps-baked task images (n132/arvo:* and cybergym/oss-fuzz:*) have every
        # project dependency + the right automake/meson; use them. Only the plain
        # base-builder sha lacks deps -> fall back to e2e-graph-builder (+prepare.sh).
        deps_baked = bi.startswith("n132/arvo") or bi.startswith("cybergym/")
        env["GRAPH_IMG"] = bi if deps_baked else "e2e-graph-builder:v3"
    t0 = time.time()
    try:
        with open(log, "w") as fh:
            subprocess.run(["bash", str(GRAPH_SH), task, str(ws)],
                           stdout=fh, stderr=subprocess.STDOUT, env=env,
                           timeout=timeout, check=False)
        note = ""
    except subprocess.TimeoutExpired:
        note = "timeout"
    dt = round((time.time() - t0) / 60.0, 1)
    r = validate(task, dt, note)
    # free the heavy, regenerable LTO intermediates immediately (docker created
    # some as root, so remove via a throwaway container). The graph we keep lives
    # in prebuild/<wid>/mongodb, NOT under graphgen, so this is safe.
    gg = ws / "graphgen"
    if gg.exists():
        subprocess.run(["docker", "run", "--rm", "-v", f"{ws}:/w",
                        "alpine", "sh", "-c", "rm -rf /w/graphgen"],
                       capture_output=True)
        subprocess.run(["rm", "-rf", str(gg)], capture_output=True)
    return r


def validate(task, minutes, note):
    wid = work_id(task)
    cg = ARM / wid / "prebuild" / wid / "mongodb" / "callgraph.json"
    fj = ARM / wid / "prebuild" / wid / "mongodb" / "functions.json"
    r = {"task": task, "wid": wid, "minutes": minutes, "note": note,
         "nodes": 0, "funcs": 0, "entry": False, "gt_frame": gt_frame(task),
         "gt_in_graph": False, "ok": False}
    if cg.exists():
        try:
            nodes = json.load(open(cg))
            r["nodes"] = len(nodes)
            names = {n.get("function_name", "") for n in nodes}
            r["entry"] = any("LLVMFuzzerTestOneInput" in n for n in names)
            if r["gt_frame"]:
                r["gt_in_graph"] = r["gt_frame"] in names
        except Exception as e:
            r["note"] = (r["note"] + f" cg-parse:{e}").strip()
    if fj.exists():
        try:
            r["funcs"] = len(json.load(open(fj)))
        except Exception:
            pass
    r["ok"] = r["nodes"] > 0 and r["entry"]
    return r


def attach(task, ok):
    """Flip enable_static_analysis + prebuild_dir in the task JSON."""
    wid = work_id(task)
    ws = ARM / wid
    proj = task.split("/", 1)[0]
    jp = ws / f"fbv2_{proj}.json"
    cfg = json.load(open(jp))
    if ok:
        cfg["enable_static_analysis"] = True
        cfg["prebuild_dir"] = str(ws / "prebuild" / wid)
    else:
        cfg["enable_static_analysis"] = False
        cfg.pop("prebuild_dir", None)
    json.dump(cfg, open(jp, "w"), indent=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", required=True)
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--mem-mb", type=int, default=14000)
    ap.add_argument("--cpus", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=2400, help="per-task seconds")
    ap.add_argument("--only", default=None)
    ap.add_argument("--revalidate", action="store_true",
                    help="skip building; just re-check + re-attach existing graphs")
    a = ap.parse_args()
    tasks = [l.strip() for l in open(a.list) if l.strip() and not l.startswith("#")]
    if a.only:
        tasks = [a.only]

    results = []
    if a.revalidate:
        for t in tasks:
            results.append(validate(t, 0.0, "revalidate"))
    else:
        print(f"[graph] {len(tasks)} tasks, parallel={a.parallel}, "
              f"mem={a.mem_mb}MB, cpus={a.cpus}", flush=True)
        with ThreadPoolExecutor(max_workers=a.parallel) as ex:
            futs = {ex.submit(run_graph, t, a.mem_mb, a.cpus, a.timeout): t
                    for t in tasks}
            for fut in as_completed(futs):
                r = fut.result()
                results.append(r)
                tag = "OK  " if r["ok"] else "FAIL"
                print(f"[graph] {tag} {r['wid']:26s} nodes={r['nodes']:5d} "
                      f"funcs={r['funcs']:5d} entry={int(r['entry'])} "
                      f"gt_in_graph={int(r['gt_in_graph'])} t={r['minutes']}m "
                      f"{r['note']}", flush=True)

    for r in results:
        attach(r["task"], r["ok"])

    results.sort(key=lambda x: x["task"])
    ok = sum(1 for r in results if r["ok"])
    print("\n=== call-graph status (Arm B) ===")
    print(f"{'work_id':26s} {'graph':5s} {'nodes':>6s} {'funcs':>6s} "
          f"{'entry':>5s} {'gt_reach':>8s}  note")
    for r in results:
        print(f"{r['wid']:26s} {'OK' if r['ok'] else 'FAIL':5s} {r['nodes']:6d} "
              f"{r['funcs']:6d} {int(r['entry']):5d} {int(r['gt_in_graph']):8d}  "
              f"{r['note']}")
    print(f"\ngraphs OK: {ok}/{len(results)}  "
          f"(static analysis ON for {ok}, OFF for {len(results)-ok})")
    json.dump(results, open(ARM / "graph_status.json", "w"), indent=2)
    print(f"wrote {ARM / 'graph_status.json'}")


if __name__ == "__main__":
    main()
