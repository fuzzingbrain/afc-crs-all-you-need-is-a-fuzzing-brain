# SPDX-License-Identifier: Apache-2.0
"""
Group 1 batch: verify the hand-authored gold suspicious points (gold_sps.json)
with the evidence verifier -- the same verifier Group 2 uses on finder SPs.

Each gold SP supplies the function, the claimed vuln_type, a description, and the
control flow; we feed those to evidence_verify.run so the verifier is judging my
SP (not the bare spec pointer). Sequential, resumable, pure model via EVIDENCE_MODEL.

    EVIDENCE_MODEL=gpt-5.2 python experiments/agent_probe/batch_group1.py --gap 15
"""
from __future__ import annotations
import argparse, asyncio, json, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parents[1]))
import dyn_tools as D
import evidence_verify as EV

SPECS = HERE / "sp_specs"
GOLD = json.loads((HERE / "gold_sps.json").read_text())
RESULTS = HERE / "results_g1"


def _merge(tag: str) -> dict:
    spec = json.loads((SPECS / f"{tag}.json").read_text())
    g = GOLD[tag]
    # Point the verifier at my authored SP: my function, my type, my description+flow.
    spec["ground_truth_functions"] = [g["function_name"]]
    spec["crash_type"] = g["vuln_type"]
    cf = "\n  - " + "\n  - ".join(g.get("important_controlflow", []))
    spec["sp_description"] = g["description"] + "\n\nControl flow to the bug:" + cf
    return spec


async def main_async(tags, gap, force):
    RESULTS.mkdir(exist_ok=True)
    D.ensure_gdb_image()
    results = {}
    for i, tag in enumerate(tags):
        out = RESULTS / f"{tag}.json"
        if out.exists() and not force:
            results[tag] = json.loads(out.read_text())
            print(f"[skip] {tag} (cached)", file=sys.stderr, flush=True); continue
        t = time.time()
        try:
            r = await EV.run(_merge(tag))
        except Exception as e:
            import traceback; traceback.print_exc()
            r = {"tag": tag, "error": f"{type(e).__name__}: {e}", "score": None,
                 "verdict": "ERROR", "dynamic": {"probes": []}}
        out.write_text(json.dumps(r, indent=2, ensure_ascii=False))
        results[tag] = r
        print(f"[done {i+1}/{len(tags)}] {tag} score={r.get('score')} "
              f"{r.get('verdict')} in {time.time()-t:.0f}s", file=sys.stderr, flush=True)
        if gap and i < len(tags) - 1:
            await asyncio.sleep(gap)
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--gap", type=float, default=15.0)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    tags = sorted(GOLD)
    if args.only:
        tags = [t for t in tags if args.only in t]
    results = asyncio.run(main_async(tags, args.gap, args.force))
    print("\n============ GROUP 1 (gold SPs) SCORES ============")
    for tag in sorted(results):
        r = results[tag]; s = r.get("score")
        s = "  -" if s is None else f"{s:>4.2f}"
        nreach = sum(1 for p in r.get("dynamic", {}).get("probes", []) if p.get("hit"))
        ncrash = sum(1 for p in r.get("dynamic", {}).get("probes", []) if p.get("crashed"))
        print(f"  {tag:44} {s}  {r.get('verdict',''):18} reach={nreach} crash={ncrash}")
    scored = [r for r in results.values() if isinstance(r.get("score"), (int, float))]
    if scored:
        hi = sum(1 for r in scored if r["score"] >= 0.5)
        print(f"\nscored {len(scored)}/{len(results)} | >=0.5: {hi}")


if __name__ == "__main__":
    main()
