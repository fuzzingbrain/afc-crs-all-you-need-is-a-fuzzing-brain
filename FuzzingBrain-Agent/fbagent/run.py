# SPDX-License-Identifier: Apache-2.0
"""Entry point: run the agent once, in whatever directory it is started in.

The bench (or a person) starts this in the staged challenge directory, where
`./submit` already exists. The agent reads the source, tests candidates through
submit, and stops. Scoring is not our job here — the bench grades the blobs
submit produced; this just drives the loop and prints what it did.

    python3 -m fbagent.run --timeout 900
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from fbagent.agent import Agent
from fbagent.llm import LLM
from fbagent.prompts import OPENING, SYSTEM


def main() -> int:
    ap = argparse.ArgumentParser()
    # The budgets: time, steps, tokens, dollars. Any one that trips ends the
    # run; a zero turns one off. Time is what the bench sets and what binds by
    # default; the rest are off unless asked for, so a run is not guillotined
    # before the wall clock it was given. --max-usd defaults from the
    # FBAGENT_MAX_USD env var, which is how the bench passes a per-cell cap.
    ap.add_argument("--timeout", type=int, default=900, help="wall clock, seconds")
    ap.add_argument("--max-steps", type=int, default=0, help="loop steps, 0 = no cap")
    ap.add_argument("--max-tokens", type=int, default=0,
                    help="total tokens (sent + generated + cached), 0 = no cap")
    ap.add_argument("--max-usd", type=float,
                    default=float(os.environ.get("FBAGENT_MAX_USD", "0") or 0),
                    help="spend cap in USD, 0 = no cap (env: FBAGENT_MAX_USD)")
    ap.add_argument("--model", default=None)
    args = ap.parse_args()

    llm = LLM(model=args.model) if args.model else LLM()
    agent = Agent(SYSTEM, llm=llm, max_steps=args.max_steps,
                  max_tokens=args.max_tokens, max_usd=args.max_usd,
                  deadline_s=args.timeout)

    result = agent.run(OPENING)

    # The full step-by-step trace, written beside the challenge in the working
    # directory. The bench copies it out to the cell as trace.jsonl; stdout
    # (below) stays the short human log.
    from pathlib import Path
    trace_path = Path.cwd() / ".fbagent-trace.jsonl"
    with trace_path.open("w") as tf:
        for rec in agent.trace():
            tf.write(json.dumps(rec) + "\n")

    # A compact record to stdout; the bench keeps this as the agent log.
    print(agent.transcript_text())
    print("\n" + "=" * 60)
    print(json.dumps({
        "stop_reason": result["stop_reason"],
        "steps": result["steps"],
        "cost_usd": round(llm.cost_usd, 4),
        "cache_hit_rate": result["cache_hit_rate"],
        "usage": result["usage"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
