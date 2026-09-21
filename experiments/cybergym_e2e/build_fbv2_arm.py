#!/usr/bin/env python3
"""Assemble FBv2 arm (Arm B) workspaces for the CyberGym-E2E comparison.

For each libFuzzer task this builds the exact workspace FBv2 expects, getting
right the five things that matter (per the run owner):

  1. sanitizer name   -> sanitizers=[meta.sanitizer]            (address/memory/undefined)
  2. fuzzer name       -> fuzzers=[meta.target_prog]            (== graph fuzzer_id)
  3. ALL fuzzer code   -> fuzzer_sources={tp:[every harness file]}  (harness .c/.cc + its
                          local helpers/headers, mirroring AIxCC's html.c+fuzz.c+fuzz.h)
  4. built fuzzer      -> prebuilt_fuzzers={tp: saved gate build}  (+ _seed_corpus.zip/.options/.dict siblings)
  5. call graph        -> prebuild_dir/mongodb/{functions,callgraph}.json, ids prebuild_<work_id>
                          (format verified against fuzzingbrain/analyzer/importer.py)

Model: force_model=gpt-5.5 pins every role (STEP6 envelope). model_profile kept
(main.py requires it present) but force_model overrides it. docker_image = the
task's own build_image (n132/arvo:<id>) so the prebuilt binary runs in its native
env -- same image the pure-fuzzer and Codex arms used -- with base-runner as the
built-in GLIBC fallback (dispatcher.py). enable_static_analysis + prebuild_dir are
filled in later by attach_graph() once the graph is generated (autotools graph-gen
may fail -> that task runs with enable_static_analysis=false, disclosed).

    python build_fbv2_arm.py --list sample_30_libfuzzer_seed42.txt
"""
import argparse, json, os, re, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = Path(os.environ.get("CYBERGYM_REPO", "/tmp/claude-1000/cybergym-e2e-repo"))
BUILDS = HERE / "builds"
ARM = Path(os.environ.get("FBV2_ARM_DIR", "/tmp/claude-1000/e2e-fbv2-arm"))
SHARED_FT = ARM / "_shared_ft"

# harness entry point present iff a file defines LLVMFuzzerTestOneInput
ENTRY = re.compile(r"LLVMFuzzerTestOneInput")
SRC_EXT = (".c", ".cc", ".cpp", ".cxx", ".c++")
HDR_EXT = (".h", ".hpp", ".hh", ".hxx", ".inc")
HELPER_HINT = re.compile(r"fuzz|harness|common|helper|mutator|util", re.I)


# Harness-source overrides for tasks the LLVMFuzzerTestOneInput-grep picker gets
# wrong. Truth is each repo's oss-fuzz build.sh (which source -> which fuzzer):
#   ffmpeg: build.sh FUZZ_TARGET_SOURCE=$SRC/ffmpeg/tools/target_dec_fuzzer.c for
#           the AV_CODEC_ID_* decoders; target_dem_fuzzer.c for the DEMUXER fuzzer
#           (src.tgz bundles many projects, so grep matched libass by accident).
#   wolfssl: fuzzer-wolfssl-client-randomize = `make fuzzer-client` with
#            -DOSS_FUZZ_BUILD_RANDOMIZE (build_wolfssl_fuzzers.sh:51) -> client.c;
#            the LLVMFuzzerTestOneInput entry is a macro in include/fuzzers/shared.h
#            (so grep never saw it and fell back to a test_data/ example).
#   arrow: CMake/meson target parquet-arrow-fuzz -> parquet/arrow/fuzz.cc (the
#          9 same-dir .h are library headers, not harness code; drop them).
#   mruby: mruby_fuzzer target -> mruby_fuzzer.c only (mruby_proto_fuzzer.cpp is a
#          separate harness).
# Paths are relative to the extracted repo/ root; verified to exist per task.
HARNESS_OVERRIDE = {
    "ffmpeg_42538001": ["ffmpeg/tools/target_dec_fuzzer.c"],
    "ffmpeg_42537562": ["ffmpeg/tools/target_dec_fuzzer.c"],
    "ffmpeg_383825642": ["ffmpeg/tools/target_dem_fuzzer.c"],
    "wolfssl_445773944": [
        "wolf-ssl-ssh-fuzzers/oss-fuzz/projects/wolf-ssl-ssh/fuzzers/wolfssl-fuzzers/client.c",
        "wolf-ssl-ssh-fuzzers/oss-fuzz/projects/wolf-ssl-ssh/fuzzers/include/fuzzers/shared.h",
    ],
    "arrow_447480433": ["arrow/cpp/src/parquet/arrow/fuzz.cc"],
    "mruby_57037": ["mruby/oss-fuzz/mruby_fuzzer.c"],
    "mruby_18756": ["mruby/oss-fuzz/mruby_fuzzer.c"],
}


def meta(task):
    return json.load(open(BUILDS / task / "meta.json"))


def work_id(task):
    proj, idpart = task.split("/", 1)
    return f"{proj}_{idpart.split('_')[-1]}"


def find_entry_files(repo):
    """All source files that define LLVMFuzzerTestOneInput (the harness entries)."""
    hits = []
    for root, _, files in os.walk(repo):
        for fn in files:
            if fn.endswith(SRC_EXT):
                p = Path(root) / fn
                try:
                    if ENTRY.search(p.read_text(errors="replace")):
                        hits.append(p)
                except Exception:
                    pass
    return hits


def local_includes(harness, repo):
    """Headers the harness #includes that resolve to a file inside the repo."""
    out = []
    try:
        txt = harness.read_text(errors="replace")
    except Exception:
        return out
    for m in re.finditer(r'#\s*include\s+"([^"]+)"', txt):
        inc = m.group(1)
        for cand in (harness.parent / inc, repo / inc):
            cand = cand.resolve()
            if cand.exists() and str(cand).startswith(str(repo.resolve())):
                out.append(cand)
                break
    return out


def pick_harness(entries, target_prog, repo):
    """Choose the harness matching target_prog; return (primary, all_candidates)."""
    if not entries:
        return None, []
    if len(entries) == 1:
        return entries[0], entries
    tp = target_prog.lower()
    scored = []
    for e in entries:
        stem = e.stem.lower()
        s = 0
        if stem == tp:
            s += 100
        if stem in tp or tp in stem:
            s += 50
        # token overlap
        et = set(re.split(r"[_\-.]", stem))
        tt = set(re.split(r"[_\-.]", tp))
        s += 10 * len(et & tt)
        if re.search(r"fuzz|test", str(e).lower()):
            s += 5
        scored.append((s, e))
    scored.sort(key=lambda x: -x[0])
    return scored[0][1], entries


def harness_sources(repo, target_prog, wid=None):
    """ALL code for the harness: primary entry + its local #includes + sibling
    helper .c/.h in the same directory. De-duplicated, sorted, entry first.

    An explicit HARNESS_OVERRIDE (from build.sh truth) wins for tasks the grep
    picker cannot resolve (macro-defined entries, multi-project src.tgz)."""
    entries = find_entry_files(repo)
    if wid in HARNESS_OVERRIDE:
        out = []
        for rel in HARNESS_OVERRIDE[wid]:
            p = (repo / rel)
            if not p.exists():
                raise FileNotFoundError(f"override source missing: {wid} -> {rel}")
            out.append(str(p.resolve()))
        return out, entries
    primary, cands = pick_harness(entries, target_prog, repo)
    if not primary:
        return [], entries
    srcs = [primary]
    srcs += local_includes(primary, repo)
    # sibling helpers in the harness directory (shared fuzz utils / headers)
    for sib in sorted(primary.parent.iterdir()):
        if sib == primary or not sib.is_file():
            continue
        if sib.suffix in HDR_EXT:
            srcs.append(sib)  # headers are cheap context, include all in dir
        elif sib.suffix in SRC_EXT and HELPER_HINT.search(sib.name) and sib not in entries:
            srcs.append(sib)  # helper .c that is not itself another harness
    # de-dup preserving order, entry first
    seen, out = set(), []
    for p in srcs:
        rp = str(p.resolve())
        if rp not in seen:
            seen.add(rp); out.append(rp)
    return out, entries


def build_ws(task):
    m = meta(task)
    tp, san, lang, img = m["target_prog"], m["sanitizer"], m.get("language", "c"), m["build_image"]
    wid = work_id(task)
    ws = ARM / wid
    ws.mkdir(parents=True, exist_ok=True)
    proj = task.split("/", 1)[0]

    # 1. repo = extract src.tgz whole (build.sh + <proj>/ source)
    repo = ws / "repo"
    if repo.exists():
        shutil.rmtree(repo)
    repo.mkdir()
    subprocess.run(["tar", "xf", str(REPO / "data/projects" / task / "src.tgz"),
                    "-C", str(repo)], check=True)

    # 2. prebuilt fuzzer binary + its sibling artifacts (seed corpus / options / dict)
    pb = ws / "prebuilt"
    pb.mkdir(exist_ok=True)
    src_bin = BUILDS / task / "out" / tp
    shutil.copy2(src_bin, pb / tp)
    os.chmod(pb / tp, 0o755)
    carried = []
    for sib in (f"{tp}_seed_corpus.zip", f"{tp}.options", f"{tp}.dict"):
        sp = BUILDS / task / "out" / sib
        if sp.exists():
            shutil.copy2(sp, pb / sib)
            carried.append(sib)

    # 3. fuzz-tooling: shared infra (symlink, read-only) + per-task writable build/ + projects/
    ft = ws / "fuzz-tooling"
    ft.mkdir(exist_ok=True)
    infra_link = ft / "infra"
    if not infra_link.exists():
        infra_link.symlink_to(SHARED_FT / "infra")
    (ft / "build" / "out").mkdir(parents=True, exist_ok=True)
    projd = ft / "projects" / proj
    projd.mkdir(parents=True, exist_ok=True)
    (projd / "project.yaml").write_text(
        f"language: {lang}\nsanitizers:\n  - {san}\n"
        f"fuzzing_engines:\n  - libfuzzer\nmain_repo: ''\n")

    # 4. harness sources (ALL harness code)
    srcs, entries = harness_sources(repo, tp, wid)

    # 5. graph goes to prebuild/<wid>/mongodb (filled by e2e_build_graph.sh; attach later)
    (ws / "prebuild" / wid).mkdir(parents=True, exist_ok=True)

    cfg = {
        "project_name": proj,
        "task_type": "pov",
        "scan_mode": "full",
        "sanitizers": [san],
        "fuzzers": [tp],
        "workspace": str(ws),
        "in_place": True,
        "build_coverage": False,
        "enable_static_analysis": False,   # flipped to True by attach_graph if graph built
        "docker_image": img,
        "prebuilt_fuzzers": {tp: str(pb / tp)},
        "work_id": wid,
        "fuzzer_sources": {tp: srcs},
        "model_profile": "period-correct",
        "force_model": "gpt-5.5",
        "pov_count": 1,
        "budget_limit": 20.0,
        "timeout_minutes": 90,
        "concurrency": 1,
    }
    (ws / f"fbv2_{proj}.json").write_text(json.dumps(cfg, indent=2))
    return {"task": task, "wid": wid, "tp": tp, "san": san, "img": img,
            "n_entries": len(entries), "n_srcs": len(srcs),
            "srcs": [s.replace(str(repo) + "/", "") for s in srcs],
            "carried": carried, "json": str(ws / f"fbv2_{proj}.json")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", required=True)
    ap.add_argument("--only", default=None, help="build just this one task")
    a = ap.parse_args()
    tasks = [l.strip() for l in open(a.list) if l.strip() and not l.startswith("#")]
    if a.only:
        tasks = [a.only]
    ARM.mkdir(parents=True, exist_ok=True)
    rows = []
    for t in tasks:
        try:
            r = build_ws(t)
            rows.append(r)
            flag = "" if r["n_srcs"] else "  <<< NO HARNESS SRC FOUND"
            multi = f"  ({r['n_entries']} entries)" if r["n_entries"] > 1 else ""
            print(f"[ok] {r['wid']:28s} san={r['san']:9s} tp={r['tp']:28s} "
                  f"srcs={r['n_srcs']}{multi} carried={r['carried']}{flag}")
            for s in r["srcs"]:
                print(f"       - {s}")
        except Exception as e:
            print(f"[ERR] {t}: {type(e).__name__}: {e}")
    json.dump(rows, open(ARM / "build_manifest.json", "w"), indent=2)
    print(f"\nwrote {ARM / 'build_manifest.json'}  ({len(rows)} tasks)")


if __name__ == "__main__":
    main()
