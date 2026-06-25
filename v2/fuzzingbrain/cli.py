# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point for FuzzingBrain v2.

Usage (planned):
    fuzzingbrain run <project>      # drive the full prep -> run lifecycle
    fuzzingbrain pipeline next      # inspect actionable units
    fuzzingbrain pipeline advance   # manually advance a unit (debug)

Skeleton only: wires argument parsing to the orchestrator once the control
plane and skill dispatch land.
"""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fuzzingbrain", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="drive the full prep -> run lifecycle")
    run.add_argument("project", help="project id or repo URL")

    sub.add_parser("pipeline", help="inspect / advance pipeline units")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(f"fuzzingbrain v2: command '{args.command}' is not implemented yet")
    return 1


if __name__ == "__main__":
    sys.exit(main())
