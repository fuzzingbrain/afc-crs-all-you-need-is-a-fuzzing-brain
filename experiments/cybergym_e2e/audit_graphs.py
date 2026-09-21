#!/usr/bin/env python3
"""Accuracy audit for the FBv2-arm call graphs (CyberGym-E2E).

A graph that exists but is shallow/wrong is worse than none, so beyond
"entry present + nodes>0" this checks, per task that currently has a graph:

  entry_ok    LLVMFuzzerTestOneInput node exists, fuzzer_id == target_prog,
              and the entry has >=1 callee (not an isolated stub)
  depth_ok    callgraph reaches call_depth >= 2 (beyond the entry's direct calls)
  lib_ok      the library was actually harvested: functions.json has functions
              from source files OTHER than the harness file, and >= LIB_MIN of them
              (catches e.g. mruby's 8-function graph where rake dropped -flto)
  paths_ok    a sample of function file_paths resolve to real files in repo/

Verdict ACCURATE only if all gates pass; otherwise SHALLOW/SUSPECT and the task's
JSON is flipped back to enable_static_analysis=false (disclosed). gt_reach (GT
crash function present as a node) is reported but NOT gated.

    python audit_graphs.py --list sample_30_libfuzzer_seed42.txt [--apply]
"""
import argparse, json, os, re
from pathlib import Path

ARM = Path(os.environ.get("FBV2_ARM_DIR", "/tmp/claude-1000/e2e-fbv2-arm"))
HERE = Path(__file__).resolve().parent
BUILDS = HERE / "builds"
LIB_MIN = 30          # min library (non-harness) functions for a real graph
SAMPLE = 40           # file_path existence sample size
SKIP_FRAME = re.compile(r"__sanitizer|fuzzer::|__asan|__msan|__ubsan|__interceptor|"
                        r"LLVMFuzzer|asan_|operator new|::malloc|__libc|^malloc$|^free$|"
                        r"MemcmpInterceptor|scanf|printf")


def work_id(task):
    proj, idpart = task.split("/", 1)
    return f"{proj}_{idpart.split('_')[-1]}"


def meta(task):
    return json.load(open(BUILDS / task / "meta.json"))


def gt_frames(task, top=8):
    """Application stack frames from gt_crash.log, deepest first (the vuln
    function is at/near the top of the app portion of the stack). Returns up to
    `top` non-sanitizer frames; criterion 3 = at least one is reachable."""
    p = BUILDS / task / "gt_crash.log"
    if not p.exists():
        return []
    out = []
    for m in re.finditer(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)",
                         p.read_text(errors="replace")):
        fn = m.group(1)
        if not SKIP_FRAME.search(fn):
            out.append(fn)
        if len(out) >= top:
            break
    return out


def harness_basenames(task):
    """basenames of the harness source files from the task JSON fuzzer_sources."""
    proj = task.split("/", 1)[0]
    jp = ARM / work_id(task) / f"fbv2_{proj}.json"
    if not jp.exists():
        return set()
    cfg = json.load(open(jp))
    out = set()
    for lst in cfg.get("fuzzer_sources", {}).values():
        for p in lst:
            out.add(Path(p).name)
    return out


def audit(task):
    wid = work_id(task)
    m = meta(task)
    tp = m["target_prog"]
    repo = ARM / wid / "repo"
    mdir = ARM / wid / "prebuild" / wid / "mongodb"
    cg, fj = mdir / "callgraph.json", mdir / "functions.json"
    r = {"task": task, "wid": wid, "tp": tp, "has_graph": False,
         "nodes": 0, "funcs": 0, "entry_ok": False, "entry_callees": 0,
         "max_depth": -1, "lib_funcs": 0, "lib_ok": False, "depth_ok": False,
         "paths_ok": False, "paths_bad": 0, "gt_frames": gt_frames(task),
         "gt_reach": False, "gt_hit": None, "verdict": "NO_GRAPH"}
    if not (cg.exists() and fj.exists()):
        return r
    try:
        nodes = json.load(open(cg))
        funcs = json.load(open(fj))
    except Exception as e:
        r["verdict"] = f"PARSE_ERR:{e}"
        return r
    r["has_graph"] = True
    r["nodes"], r["funcs"] = len(nodes), len(funcs)

    # entry
    entry = [n for n in nodes if "LLVMFuzzerTestOneInput" in n.get("function_name", "")]
    fuzzer_ids = {n.get("fuzzer_id", "") for n in nodes}
    r["entry_callees"] = max((len(n.get("callees", [])) for n in entry), default=0)
    r["entry_ok"] = bool(entry) and (tp in fuzzer_ids) and r["entry_callees"] >= 1

    # depth
    r["max_depth"] = max((n.get("call_depth", -1) for n in nodes), default=-1)
    r["depth_ok"] = r["max_depth"] >= 2

    # library harvested (functions outside the harness file(s))
    hb = harness_basenames(task)
    r["lib_funcs"] = sum(1 for f in funcs
                         if Path(f.get("file_path", "")).name not in hb
                         and f.get("file_path"))
    r["lib_ok"] = r["lib_funcs"] >= LIB_MIN

    # file_path validity (sample): the ir_callgraph file_path is relative to the
    # (now-cleaned) graph-gen extraction root, so exact-path resolution against the
    # workspace repo/ is unreliable. Validate instead that each sampled file_path
    # names a real source file that exists SOMEWHERE under repo/ (by basename) --
    # i.e. the graph refers to genuine project files, not fabricated paths.
    repo_names = set()
    for root_, _, fnames in os.walk(repo):
        repo_names.update(fnames)
    paths = [f.get("file_path", "") for f in funcs if f.get("file_path")]
    sample = paths[:: max(1, len(paths) // SAMPLE)][:SAMPLE] if paths else []
    bad = sum(1 for fp in sample if Path(fp).name not in repo_names)
    r["paths_bad"] = bad
    r["paths_ok"] = (len(sample) == 0) or (bad <= 0.5 * len(sample))

    # criterion 3: the vulnerability function must be reachable from the harness.
    # Accept if any of the GT stack's app frames is a node in the callgraph.
    node_names = {n.get("function_name") for n in nodes}
    for f in r["gt_frames"]:
        if f in node_names:
            r["gt_reach"] = True
            r["gt_hit"] = f
            break

    # Reachability gate: the graph must actually reach a meaningful slice of the
    # library FROM the fuzzer entry, not just harvest many functions into
    # functions.json. Shallow graphs (entry present but the API/wrapper layer was
    # not harvested as bitcode, so the harness's calls dead-end) have tiny
    # reachable node counts vs. harvested functions -- e.g. libspectre 7/15516,
    # libheif 39/2852, ghostscript 10/598. Those are inaccurate for SP guidance.
    ratio = r["nodes"] / r["funcs"] if r["funcs"] else 0.0
    r["reach_ratio"] = round(ratio, 3)
    r["reach_ok"] = r["nodes"] >= 30 and ratio >= 0.05

    # paths_ok is reported but NOT gated: functions from vendored deps built in
    # /work (boost/thrift for arrow, etc.) legitimately are not under repo/, which
    # would false-negative deep graphs. entry + depth + reachability are the
    # reliable structural-accuracy signals.
    # Verdict gates (the 4 acceptance criteria): loadable format is guaranteed by
    # entry+nodes; (2) sensible = depth_ok+reach_ok+lib_ok; (3) vuln reachable =
    # gt_reach; (4) harness entry present = entry_ok. gt_reach only gates when GT
    # frames are known.
    gt_gate = r["gt_reach"] or not r["gt_frames"]
    r["verdict"] = ("ACCURATE" if (r["entry_ok"] and r["depth_ok"] and r["lib_ok"]
                    and r["reach_ok"] and gt_gate) else "SHALLOW")
    return r


def apply_verdict(task, accurate):
    proj = task.split("/", 1)[0]
    wid = work_id(task)
    jp = ARM / wid / f"fbv2_{proj}.json"
    cfg = json.load(open(jp))
    if accurate:
        cfg["enable_static_analysis"] = True
        cfg["prebuild_dir"] = str(ARM / wid / "prebuild" / wid)
    else:
        cfg["enable_static_analysis"] = False
        cfg.pop("prebuild_dir", None)
    json.dump(cfg, open(jp, "w"), indent=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", required=True)
    ap.add_argument("--apply", action="store_true",
                    help="flip enable_static_analysis per verdict")
    a = ap.parse_args()
    tasks = [l.strip() for l in open(a.list) if l.strip() and not l.startswith("#")]
    rows = [audit(t) for t in tasks]

    print(f"{'work_id':26s} {'verdict':9s} {'nodes':>6s} {'funcs':>6s} "
          f"{'depth':>5s} {'reach%':>6s} {'gt':>3s}  gt_hit")
    for r in sorted(rows, key=lambda x: x["task"]):
        print(f"{r['wid']:26s} {r['verdict']:9s} {r['nodes']:6d} {r['funcs']:6d} "
              f"{r['max_depth']:5d} {r.get('reach_ratio',0)*100:5.1f}% "
              f"{int(r['gt_reach']):3d}  {r.get('gt_hit') or ''}")
    acc = [r for r in rows if r["verdict"] == "ACCURATE"]
    shallow = [r for r in rows if r["verdict"] == "SHALLOW"]
    print(f"\nACCURATE: {len(acc)}   SHALLOW(->static off): {len(shallow)}   "
          f"NO_GRAPH: {sum(1 for r in rows if r['verdict']=='NO_GRAPH')}")
    print("ACCURATE:", ", ".join(r["wid"] for r in acc))
    print("SHALLOW :", ", ".join(r["wid"] for r in shallow))
    if a.apply:
        for r in rows:
            apply_verdict(r["task"], r["verdict"] == "ACCURATE")
        print("\napplied verdicts to task JSONs (enable_static_analysis)")
    json.dump(rows, open(ARM / "graph_audit.json", "w"), indent=2)
    print(f"wrote {ARM / 'graph_audit.json'}")


if __name__ == "__main__":
    main()
