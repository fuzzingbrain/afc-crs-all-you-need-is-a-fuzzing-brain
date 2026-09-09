"""Score the agent's built-in worklist (fbagent/analysis.py) on the same 24
challenges and the same bug-window metric as joern_driver.py, so a change to the
analyzer has a before/after number.

Per challenge:
  defined    bug function found as a definition in the lexical graph
  reachable  bug function reachable from the harness entry (call graph)
  line_all   some reachable sink lies in the bug window (any rank)
  line_top   ... within the top-N the agent is actually shown (N=40)
  func_top   a sink in the bug FUNCTION is in the top-N
  reach/sinks/N   sizes
Usage: python3 eval_default.py [--top 40] [--clang] [chal ...]
"""
import json, os, sys, time, importlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "FuzzingBrain-Agent"))
from fbagent import analysis

BASE = os.path.dirname(os.path.abspath(__file__))
SRC = json.load(open(f"{BASE}/srctrees.json")); GT = json.load(open(f"{BASE}/ground_truth.json"))
SET = list(json.load(open(f"{BASE}/joern_precise.json")))

def window(g):
    w = set()
    if g.get("line_range"): a, b = g["line_range"]; w |= set(range(a, b + 1))
    if g.get("site_line") is not None:
        t = g.get("tol") or 0; w |= set(range(g["site_line"] - t, g["site_line"] + t + 1))
    return w

def main():
    args = sys.argv[1:]
    top = 40; clang = False
    if "--top" in args: i = args.index("--top"); top = int(args[i + 1]); del args[i:i + 2]
    if "--clang" in args: clang = True; args.remove("--clang")
    chals = args or SET
    rows = {}
    for c in chals:
        g = GT[c]; root = SRC[c]; w = window(g); base = os.path.basename(g["file"])
        fbare = g["func"].split("::")[-1].split(".")[-1] if g["func"] else None
        t0 = time.time()
        analysis._CTX_CACHE.clear()
        ctx = analysis.build(root, use_clang=clang)
        dt = time.time() - t0
        r = dict(defined=bool(fbare and fbare in ctx.cg.where),
                 reachable=bool(fbare and fbare in ctx.dist),
                 dist=ctx.dist.get(fbare) if fbare else None,
                 line_all=False, line_top=False, func_top=False,
                 reach=len(ctx.dist), sinks=len(ctx.reach), top=top, secs=round(dt, 1),
                 entry=ctx.entry)
        for i, s in enumerate(ctx.reach):
            inwin = os.path.basename(s.file) == base and s.line in w
            if inwin: r["line_all"] = True
            if i < top:
                if inwin: r["line_top"] = True
                if fbare and s.func == fbare: r["func_top"] = True
        rows[c] = r
        print(f"{c:18} def={int(r['defined'])} reach={int(r['reachable'])}(d={r['dist']}) "
              f"line_all={int(r['line_all'])} line_top={int(r['line_top'])} func_top={int(r['func_top'])} "
              f"| reachable={r['reach']} sinks={r['sinks']} {r['secs']}s", flush=True)
    n = len(rows)
    print(f"\nTOTAL {n}: defined={sum(r['defined'] for r in rows.values())} "
          f"reachable={sum(r['reachable'] for r in rows.values())} "
          f"line_all={sum(r['line_all'] for r in rows.values())} "
          f"line_top{top}={sum(r['line_top'] for r in rows.values())} "
          f"func_top{top}={sum(r['func_top'] for r in rows.values())}")
    out = f"{BASE}/default_results{'_clang' if clang else ''}.json"
    json.dump(rows, open(out, "w"), indent=1); print("->", out)

if __name__ == "__main__":
    main()
