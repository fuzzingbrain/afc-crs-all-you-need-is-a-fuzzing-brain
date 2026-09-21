# SPDX-License-Identifier: Apache-2.0
"""
Batch-run the evidence verifier over the 57 SP specs, sequentially and resumably.

Gentle on the API: one spec at a time, a delay between specs, and each spec's
LLM calls already back off on rate limits (evidence_verify._llm_retry). Results
land in results_evidence/<tag>.json as they finish, so it can be stopped and
resumed (an existing result is skipped unless --force), and run in chunks between
other experiments.

    python experiments/agent_probe/batch_evidence.py            # all, resume
    python experiments/agent_probe/batch_evidence.py --only ws  # subset
    python experiments/agent_probe/batch_evidence.py --gap 30   # 30s between specs
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import dyn_tools as D
import evidence_verify as EV

SPECS = HERE / "sp_specs"
RESULTS = HERE / "results_evidence"


def _row(tag: str, r: dict) -> str:
    s = r.get("score")
    s = "  -" if s is None else f"{s:>4.2f}"
    nreach = sum(1 for p in r.get("dynamic", {}).get("probes", []) if p.get("hit"))
    ncrash = sum(1 for p in r.get("dynamic", {}).get("probes", []) if p.get("crashed"))
    return f"  {tag:34} {s}  {r.get('verdict',''):22} reach={nreach} crash={ncrash}"


async def main_async(specs, gap, force):
    RESULTS.mkdir(exist_ok=True)
    D.ensure_gdb_image()
    results = {}
    for i, sp in enumerate(specs):
        tag = sp.stem
        out = RESULTS / f"{tag}.json"
        if out.exists() and not force:
            results[tag] = json.loads(out.read_text())
            print(f"[skip] {tag} (cached)", file=sys.stderr, flush=True)
            continue
        spec = json.loads(sp.read_text())
        t = time.time()
        try:
            r = await EV.run(spec)
        except Exception as e:
            r = {"tag": tag, "error": f"{type(e).__name__}: {e}", "score": None,
                 "verdict": "ERROR", "dynamic": {"probes": []}}
        out.write_text(json.dumps(r, indent=2, ensure_ascii=False))
        results[tag] = r
        print(f"[done {i+1}/{len(specs)}] {tag} score={r.get('score')} "
              f"{r.get('verdict')} in {time.time()-t:.0f}s", file=sys.stderr, flush=True)
        if gap and i < len(specs) - 1:
            await asyncio.sleep(gap)
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="substring filter on tag")
    ap.add_argument("--gap", type=float, default=15.0, help="seconds between specs")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    specs = sorted(SPECS.glob("*.json"))
    if args.only:
        specs = [s for s in specs if args.only in s.stem]

    results = asyncio.run(main_async(specs, args.gap, args.force))

    print("\n==================== EVIDENCE VERIFIER SCORES ====================")
    for tag in sorted(results):
        print(_row(tag, results[tag]))
    scored = [r for r in results.values() if isinstance(r.get("score"), (int, float))]
    inc = [r for r in results.values() if r.get("verdict", "").startswith(("INCOMPLETE", "ERROR"))]
    if scored:
        hi = sum(1 for r in scored if r["score"] >= 0.5)
        print(f"\nscored: {len(scored)}/{len(results)}  |  >=0.5: {hi}  |  "
              f"incomplete/error: {len(inc)}")


if __name__ == "__main__":
    main()
