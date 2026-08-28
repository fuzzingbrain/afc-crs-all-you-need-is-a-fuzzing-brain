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
import sys
from pathlib import Path

from fbagent.agent import Agent
from fbagent.llm import LLM

PROMPT = Path(__file__).resolve().parent.parent / "prompt.md"

OPENING = (
    "Read harness/ first to learn the input format, then follow it into src/ to "
    "find a fault it can reach. Build a candidate input and test it with "
    "./submit, and keep going until one crashes."
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=int, default=900, help="wall clock, seconds")
    ap.add_argument("--max-steps", type=int, default=60)
    ap.add_argument("--model", default=None)
    args = ap.parse_args()

    system = PROMPT.read_text()
    llm = LLM(model=args.model) if args.model else LLM()
    agent = Agent(system, llm=llm, max_steps=args.max_steps, deadline_s=args.timeout)

    result = agent.run(OPENING)

    # A compact record to stdout; the bench keeps this as the agent log.
    print(agent.transcript_text())
    print("\n" + "=" * 60)
    print(json.dumps({
        "stop_reason": result["stop_reason"],
        "steps": result["steps"],
        "cache_hit_rate": result["cache_hit_rate"],
        "usage": result["usage"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
