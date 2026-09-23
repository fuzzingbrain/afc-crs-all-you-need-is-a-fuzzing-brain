# SPDX-License-Identifier: Apache-2.0
"""Entry point for the three-stage pipeline: discovery -> verification ->
reproduction, over a HypothesisPool, driven by the code controller.

    python3 -m fbagent.run_stages --timeout 900 --model claude-opus-5 --max-usd 20

Started by the bench (or a person) in the staged challenge directory, where
`./submit`, the trace bridge, and bench.yaml already exist. Unlike run.py (the
single-loop agent), this runs the multi-stage controller. It writes the same
records run.py does so the bench can read them: .fbbench/usage.json for cost,
and .fb/ holds the VulnHypothesis board, candidates, and per-stage sessions.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from fbagent import controller
from fbagent.llm import LLM


def _write_usage(ws: Path, llm: LLM, summary: dict) -> None:
    """.fbbench/usage.json — the bench's external arm reads this to cost a
    black-box agent (same field names as run.py's summary)."""
    try:
        d = ws / ".fbbench"
        d.mkdir(parents=True, exist_ok=True)
        (d / "usage.json").write_text(json.dumps({
            "usage": dict(llm.usage), "cost_usd": round(llm.cost_usd, 4),
            "model": llm.model, "served_model": llm.served_model,
            "solved": summary.get("solved"), "signatures": summary.get("signatures"),
        }))
    except Exception as e:  # never fail the run over bookkeeping
        print(f"[run_stages] usage write skipped: {e}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=int, default=900, help="wall clock, seconds")
    ap.add_argument("--max-usd", type=float,
                    default=float(os.environ.get("FBAGENT_MAX_USD", "0") or 0),
                    help="global spend cap in USD across all stages (env: FBAGENT_MAX_USD)")
    ap.add_argument("--model", default=None)
    ap.add_argument("--discovery-frac", type=float, default=controller.DISCOVERY_BUDGET_FRAC,
                    help="fraction of the spend cap reserved for discovery")
    args = ap.parse_args()

    llm = LLM(model=args.model) if args.model else LLM()
    ws = Path.cwd()
    print(f"[run_stages] model={llm.model} provider={llm.provider} "
          f"max_usd={args.max_usd} timeout_s={args.timeout}", flush=True)

    summary = controller.run_task(llm=llm, workspace=str(ws), max_usd=args.max_usd,
                                  deadline_s=args.timeout, discovery_frac=args.discovery_frac)
    _write_usage(ws, llm, summary)

    if llm.served_model and llm.model.split("-2")[0] not in (llm.served_model or ""):
        print(f"[run_stages] WARNING: requested {llm.model} but API served "
              f"{llm.served_model}", file=sys.stderr)
    print("\n" + "=" * 60)
    # the per-stage log can be long; print the headline + one line per stage
    head = {k: summary[k] for k in ("harness", "sanitizer", "hypotheses", "solved",
                                    "signatures", "cost_usd", "stop")}
    print(json.dumps(head, indent=2))
    for e in summary.get("log", []):
        print(f"  {e.get('stage'):10} " + json.dumps({k: v for k, v in e.items()
              if k not in ('stage', 'log')})[:200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
