#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One command, one number: what the agent costs at no loss of score.

An outer-loop optimiser edits prompts/system.md, runs this, and reads stdout.
Lower is better. Everything human-readable goes to stderr, so stdout is a bare
float and nothing else.

    python3 tools/trial_cost.py                  # run the trial set, print a number
    python3 tools/trial_cost.py --score-only DIR # re-score a finished run, free

The number is the dollars the run spent -- but only if the score held. Drop a
point and it returns PENALTY instead, because the cheapest possible agent is one
that gives up immediately, and without this floor that is exactly what an
optimiser learns to build.

Scoring is tools/score_run.py, unchanged; this only chains it to `fb-bench run`
and adds the cost side.

Environment:
  FBTRIAL_BUGS   comma list of challenges   (default: the trial set below)
  FBTRIAL_FLOOR  score that must be held    (default: 5, the baseline below)
  FBTRIAL_OUT    run directory              (default: a fresh timestamped one)
  FBAGENT_MODEL  pinned to claude-haiku-4-5 -- the dev-40 run's model, not the
                 code default (opus-5); leaving it unpinned makes every number
                 incomparable with the baseline.
"""
from __future__ import annotations

import argparse, json, os, re, subprocess, sys, time
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parents[1]
BENCH = AGENT_DIR.parents[1] / "FuzzingBrain-Bench"
MANIFEST = AGENT_DIR / "fbagent-native.agent.yaml"

# Five dev-split challenges chosen off the dev-40 sweep: three the agent solves
# (so the floor has teeth) and two it works to exhaustion and never solves (where
# the waste is). Baseline on fbagent-v0.1 / haiku-4.5: score 5, $3.47.
TRIAL_BUGS = ["cups-01", "imagemagick-03", "icu-03", "openldap-02", "freetype-01"]
TRIAL_FLOOR = 5
PENALTY = 999999.0


def spend(run_dir: Path) -> float:
    """Every dollar the run booked, from the bench's per-cell cost.json."""
    total = 0.0
    for c in run_dir.rglob("cost.json"):
        try:
            total += float(json.loads(c.read_text()).get("total_usd") or 0.0)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass
    return total


def score(run_dir: Path) -> int | None:
    """The FB-Bench metric, straight out of tools/score_run.py."""
    p = subprocess.run([sys.executable, str(AGENT_DIR / "tools/score_run.py"),
                        str(run_dir), "--split", "dev"],
                       capture_output=True, text=True)
    sys.stderr.write(p.stdout)
    if p.returncode != 0:
        sys.stderr.write(p.stderr)
        return None
    m = re.search(r"^\s*OURS\s+dev\s*=\s*(\d+)", p.stdout, re.M)
    return int(m.group(1)) if m else None


def verdict(run_dir: Path, floor: int) -> float:
    got, usd = score(run_dir), spend(run_dir)
    if got is None:
        print("trial_cost: could not read a score; returning PENALTY", file=sys.stderr)
        return PENALTY
    print(f"\n  score {got} (floor {floor})   spend ${usd:.4f}", file=sys.stderr)
    if got < floor:
        print(f"  REGRESSION: {got} < {floor} -> PENALTY", file=sys.stderr)
        return PENALTY
    print(f"  held the floor -> {usd:.4f}", file=sys.stderr)
    return usd


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--score-only", metavar="DIR", help="score a finished run; spend nothing")
    ap.add_argument("--floor", type=int, default=int(os.environ.get("FBTRIAL_FLOOR", TRIAL_FLOOR)))
    ap.add_argument("--bugs", default=os.environ.get("FBTRIAL_BUGS", ",".join(TRIAL_BUGS)))
    args = ap.parse_args()

    if args.score_only:
        print(f"{verdict(Path(args.score_only), args.floor):.4f}")
        return 0

    out = Path(os.environ.get("FBTRIAL_OUT") or
               BENCH / "output" / f"trial_{time.strftime('%Y%m%d-%H%M%S')}")
    env = dict(os.environ)
    env.setdefault("FBAGENT_MODEL", "claude-haiku-4-5")   # the dev-40 model
    env.setdefault("FBAGENT_MAX_USD", "8.0")              # the dev-40 per-cell cap

    cmd = ["fb-bench", "run", args.bugs, "--agent", str(MANIFEST),
           "--output", str(out), "--samples", "1", "--jobs", "3", "--no-dashboard"]
    print(f"trial_cost: {' '.join(cmd)}", file=sys.stderr)
    if subprocess.run(cmd, cwd=BENCH, env=env).returncode != 0:
        print("trial_cost: bench exited non-zero; scoring what landed", file=sys.stderr)

    print(f"{verdict(out, args.floor):.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
