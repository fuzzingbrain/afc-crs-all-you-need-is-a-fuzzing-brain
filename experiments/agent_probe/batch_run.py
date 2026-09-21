# SPDX-License-Identifier: Apache-2.0
"""
Batch-run the probe over every spec in challenges/, sequentially (concurrency 1).

Writes per-challenge results to results/<tag>.json as it goes (resumable: an
existing result is skipped unless --force), then prints a summary table:

    challenge                 Q1_found  Q2_verdict  score
    lp-delta-01               yes       REAL        0.95

Each challenge is one SP-finder run + one SP-verifier run — real LLM calls.
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
sys.path.insert(0, str(HERE.parents[1]))

import probe  # noqa: E402

RESULTS = HERE / "results"


def _summary_row(tag: str, r: dict) -> str:
    q1 = r.get("q1_finder", {})
    q2 = r.get("q2_verifier", {})
    found = "ERR" if "error" in q1 else ("yes" if q1.get("found_ground_truth") else "no")
    if "error" in q2:
        verdict, score = "ERR", "-"
    else:
        verdict = "REAL" if q2.get("verdict_real") else "FP"
        score = f"{q2.get('score', 0):.2f}"
    return f"  {tag:30} Q1_found={found:4} Q2={verdict:5} score={score}"


async def run_one(spec_path: Path, model: str, do_q1: bool, do_q2: bool) -> dict:
    spec = json.loads(spec_path.read_text())
    return await probe.main_async(spec, do_q1, do_q2, model)


def main() -> None:
    ap = argparse.ArgumentParser(description="Batch probe over all challenge specs")
    ap.add_argument("--model", default="claude-sonnet-4-5-20250929")
    ap.add_argument("--force", action="store_true", help="re-run challenges with an existing result")
    ap.add_argument("--only", default="", help="substring filter on challenge tag")
    ap.add_argument("--q1-only", action="store_true")
    ap.add_argument("--q2-only", action="store_true")
    args = ap.parse_args()

    RESULTS.mkdir(exist_ok=True)
    specs = sorted((HERE / "challenges").glob("*.json"))
    if args.only:
        specs = [s for s in specs if args.only in s.stem]
    do_q1 = not args.q2_only
    do_q2 = not args.q1_only

    print(f"[batch] {len(specs)} challenges | model={args.model} | Q1={do_q1} Q2={do_q2}\n")
    results = {}
    for sp in specs:
        tag = sp.stem
        out = RESULTS / f"{tag}.json"
        if out.exists() and not args.force:
            results[tag] = json.loads(out.read_text())
            print(f"[skip] {tag} (cached)")
            continue
        t = time.time()
        try:
            r = asyncio.run(run_one(sp, args.model, do_q1, do_q2))
        except Exception as e:
            r = {"challenge": tag, "error": f"{type(e).__name__}: {e}"}
        out.write_text(json.dumps(r, indent=2, ensure_ascii=False))
        results[tag] = r
        print(f"[done] {tag} in {time.time()-t:.0f}s")

    print("\n==================== SUMMARY ====================")
    for tag in sorted(results):
        print(_summary_row(tag, results[tag]))
    # tallies
    q1_yes = sum(1 for r in results.values() if r.get("q1_finder", {}).get("found_ground_truth"))
    q2_real = sum(1 for r in results.values() if r.get("q2_verifier", {}).get("verdict_real"))
    n = len(results)
    print(f"\nQ1 found ground truth: {q1_yes}/{n}   Q2 judged REAL: {q2_real}/{n}")


if __name__ == "__main__":
    main()
