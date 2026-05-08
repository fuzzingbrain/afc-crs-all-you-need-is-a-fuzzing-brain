# SPDX-License-Identifier: Apache-2.0
"""Unified CLI entry point for CRS strategies.

Run a registered strategy by name:

    python -m strategies run <name> <fuzzer_path> <project_name> <focus> <language> [options]

Or list the registry:

    python -m strategies list

This replaces the legacy "one executable Python file per strategy"
layout; the Go runner invokes this module with a name argument
instead of locating strategy files by filename glob.

The CLI takes care of:

* Installing the :func:`common.fuzzing.docker_lifecycle.install_cleanup_handlers`
  opt-in exit hook (safe here because this is a top-level binary).
* Building a :class:`~common.config.StrategyConfig` from the CLI args.
* Looking up the strategy class via :func:`strategies.get_strategy_spec`
  and stamping the spec's flags onto the config.
* Instantiating the strategy and calling ``run()``.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

# Add the strategy/ root to sys.path so `common.*` and `core.*` imports work
# whether this module is invoked as `python -m strategies` from the root
# or as `python strategies/__main__.py` from anywhere else.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.config import StrategyConfig
from common.fuzzing.docker_lifecycle import install_cleanup_handlers
from strategies import get_strategy_spec, list_strategies


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m strategies",
        description="Run or list CRS vulnerability-analysis strategies.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="Execute a strategy by name")
    run.add_argument("name", help="Strategy name (see `python -m strategies list`)")
    run.add_argument("fuzzer_path", help="Path to the fuzzer binary")
    run.add_argument("project_name", help="OSS-Fuzz project name")
    run.add_argument("focus", help="Project focus directory")
    run.add_argument("language", help="Language (c / cpp / java)")
    run.add_argument("--model", default="", help="Override the primary LLM model")
    run.add_argument(
        "--max-iterations",
        type=int,
        default=5,
        dest="max_iterations",
        help="Maximum POV / patch retry iterations per model",
    )
    run.add_argument(
        "--fuzzing-timeout",
        type=int,
        default=45,
        dest="fuzzing_timeout_minutes",
        help="Wall-clock minutes allowed for POV generation",
    )
    run.add_argument(
        "--patching-timeout",
        type=int,
        default=30,
        dest="patching_timeout_minutes",
        help="Wall-clock minutes allowed for patch generation",
    )
    run.add_argument(
        "--pov-metadata-dir",
        default="successful_povs",
        dest="pov_metadata_dir",
        help="Per-task POV success directory (relative to the fuzz dir)",
    )
    run.add_argument(
        "--log-dir",
        default="./logs",
        dest="log_dir",
        help="Directory to write strategy log files",
    )
    run.add_argument(
        "--no-cleanup-handlers",
        action="store_true",
        help="Skip installing the docker-cleanup atexit hook (for tests)",
    )

    subparsers.add_parser("list", help="List registered strategies")

    return parser


def _build_config(args: argparse.Namespace, full_scan: bool) -> StrategyConfig:
    """Construct a :class:`StrategyConfig` from parsed CLI args."""
    models: List[str] = [args.model] if args.model else []
    return StrategyConfig(
        strategy_name=args.name,
        fuzzer_path=args.fuzzer_path,
        project_name=args.project_name,
        focus=args.focus,
        language=args.language,
        models=models,
        max_iterations=args.max_iterations,
        fuzzing_timeout_minutes=args.fuzzing_timeout_minutes,
        patching_timeout_minutes=args.patching_timeout_minutes,
        pov_metadata_dir=args.pov_metadata_dir,
        log_dir=args.log_dir,
        full_scan=full_scan,
    )


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        spec = get_strategy_spec(args.name)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not args.no_cleanup_handlers:
        install_cleanup_handlers()

    config = _build_config(args, full_scan=spec.full_scan)
    config.do_patch_only = spec.do_patch_only

    strategy = spec.strategy_class(config)
    success = strategy.run()
    return 0 if success else 1


def _cmd_list(_args: argparse.Namespace) -> int:
    for name in list_strategies():
        print(name)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "list":
        return _cmd_list(args)
    parser.error(f"Unknown command {args.command}")
    return 2  # unreachable


if __name__ == "__main__":
    raise SystemExit(main())
