# SPDX-License-Identifier: Apache-2.0
"""
FuzzingBrain v2 - entry point.

    python -m fuzzingbrain.main --config task.json [--field value ...]

One way in: a task, from a JSON file and/or flags, is turned into a Config and
handed to run_task(). Setting up the machine is setup.sh's job.
"""

import argparse
import atexit
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Keys and the PostgreSQL/Redis URLs live in the repo's .env. Loaded before the
# imports below and before any config is read, so POSTGRES_URL there is the one
# this process connects to. A variable already in the environment wins.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from .core import (  # noqa: E402
    Config,
    setup_logging,
)
from .core.banner import show_banner  # noqa: E402
from .core.config import ConfigError  # noqa: E402
from .core.fuzzer_spec import set_detect_leaks  # noqa: E402
from .core.environment import (  # noqa: E402
    check_api_keys,
    check_docker,
    ensure_postgres,
    ensure_redis,
)
from .db.store import Store, get_store  # noqa: E402
from .db.pg import migrate  # noqa: E402


# =============================================================================
# Terminal Cleanup
# =============================================================================


def reset_terminal():
    """Reset terminal to sane state on exit"""
    if not sys.stdout.isatty():
        return
    try:
        # Reset ANSI attributes
        sys.stdout.write("\033[0m")
        sys.stdout.flush()
        # Reset terminal settings (handles raw mode, echo, etc.)
        os.system("stty sane 2>/dev/null")
    except Exception:
        pass


# Register cleanup on exit
atexit.register(reset_terminal)


# =============================================================================
# Signal Handling
# =============================================================================

_shutdown_requested = False
_current_run_id: Optional[str] = None
_current_out: Optional[Path] = None
_started_at: float = 0.0


def signal_handler(signum, frame):
    """Ctrl+C / SIGTERM: record the run as cancelled, stop what it started."""
    global _shutdown_requested
    if _shutdown_requested:
        print("\n\033[0;31m[FORCE]\033[0m Forcing shutdown...")
        reset_terminal()
        sys.exit(1)

    _shutdown_requested = True
    print(
        "\n\033[1;33m[INTERRUPT]\033[0m Shutting down gracefully... (Press Ctrl+C again to force)"
    )

    if _store is None or not _current_run_id:
        reset_terminal()
        sys.exit(0)

    try:
        from .agents.context import get_all_agent_contexts

        for ctx in get_all_agent_contexts().values():
            if ctx.run_id == _current_run_id and ctx.status == "running":
                try:
                    ctx.cancel()
                except Exception:
                    pass
        workers = _store.end_open_workers(_current_run_id, "cancelled")
        agents = _store.end_running_agents(run_id=_current_run_id, status="cancelled")
        _store.end_run(_current_run_id, "cancelled")
        if _current_out is not None:
            from .core.run_processor import write_result

            write_result(_current_out, _store, _current_run_id, "cancelled", None,
                         (time.monotonic() - _started_at) / 60)
        print(
            f"\033[1;33m[INTERRUPT]\033[0m Run cancelled "
            f"({workers} worker(s), {agents} agent(s) stopped)"
        )
        try:
            from .core.logging import print_run_summary

            print_run_summary(_store, _current_run_id, exit_reason="cancelled")
        except Exception as e:
            print(f"\033[0;31m[ERROR]\033[0m Failed to generate summary: {e}")
    except Exception as e:
        print(f"\033[0;31m[ERROR]\033[0m Failed to update status: {e}")

    try:
        from .llms import LLMClient

        LLMClient.close_all()
    except Exception:
        pass

    try:
        from .core.infrastructure import InfrastructureManager

        if InfrastructureManager._instance:
            InfrastructureManager._instance.stop()
    except Exception:
        pass

    reset_terminal()
    sys.exit(0)


# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# =============================================================================
# Global State
# =============================================================================

_store: Optional[Store] = None


def init_database(config: Config) -> Store:
    """This process's connection to the run database (schema already migrated)."""
    global _store
    if _store is None:
        _store = get_store(config.postgres_url)
    return _store


# =============================================================================
# Terminal Output
# =============================================================================


class Colors:
    # Plain text when piped into a log, or when NO_COLOR is set.
    _on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    RED = "\033[0;31m" if _on else ""
    GREEN = "\033[0;32m" if _on else ""
    YELLOW = "\033[1;33m" if _on else ""
    BLUE = "\033[0;34m" if _on else ""
    CYAN = "\033[0;36m" if _on else ""
    ORANGE = "\033[38;5;208m" if _on else ""
    NC = "\033[0m" if _on else ""


def print_info(msg: str):
    print(f"{Colors.GREEN}[INFO]{Colors.NC} {msg}")


def print_warn(msg: str):
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}")


def print_error(msg: str):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")


def print_step(msg: str):
    print(f"{Colors.CYAN}[STEP]{Colors.NC} {msg}")


# =============================================================================
# Argument Parsing
# =============================================================================


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m fuzzingbrain.main",
        description=(
            "Run FuzzingBrain on one task. Describe the task in a JSON file "
            "(--config), on the command line, or both: a flag overrides the "
            "same field in the file. Fields: fuzzingbrain/core/config.py (FIELDS); "
            "examples: examples/aixcc/cu-delta-05.json, examples/aixcc/mg-full-01.json."
        ),
    )
    parser.add_argument("--config", type=str, help="Task file (JSON)")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Load and validate the task, print it, and exit without running",
    )
    Config.add_arguments(parser)
    return parser.parse_args(argv)


# =============================================================================
# The Run record
# =============================================================================

def code_version() -> Optional[str]:
    """The FBv2 version that runs this: git describe on fb-v* tags."""
    import subprocess

    try:
        r = subprocess.run(
            ["git", "describe", "--tags", "--always", "--dirty", "--match", "fb-v*"],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() or None if r.returncode == 0 else None
    except Exception:
        return None


def run_task(config: Config) -> dict:
    """Run one task end to end. Every way of starting FuzzingBrain ends here."""
    global _current_run_id, _current_out, _started_at
    # Everything this run writes goes under its output: logs/ and events.jsonl.
    from .core.events import set_events_path
    from .core.logging import get_logo

    out = Path(config.workspace)
    set_events_path(out / "events.jsonl")
    log_file = setup_logging(
        out / "logs",
        header=get_logo("controller") + "\n" + "\n".join(
            f"  {label:<12} {value}" for label, value in config.summary()),
    )

    store = init_database(config)
    store.create_run(
        run_id=config.run_id,
        project_name=config.project_name,
        scan_mode=config.scan_mode,
        config=config.record(),
        config_given=dict(config.given),
        workspace_path=config.workspace,
        code_version=code_version(),
        label=config.label,
    )
    _current_run_id = config.run_id
    _current_out = out
    _started_at = time.monotonic()

    print_info(f"Logs: {log_file.parent}")
    print_step("Starting run processing pipeline...")

    from .core.run_processor import process_run

    result = process_run(config, store)

    print("")
    if result["status"] == "error":
        print_error(f"Run failed: {result['message']}")
    else:
        print_info(f"Status: {result['status']}")
        print_info(f"Message: {result['message']}")
    print_info(f"Output: {config.workspace}")
    return result


def _fail(title: str, errors) -> None:
    print_error(title)
    for e in errors:
        print(f"  - {e}")
    sys.exit(2)


def _print_summary(config: Config) -> None:
    rows = config.summary()
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        print(f"  {Colors.CYAN}{label:<{width}}{Colors.NC}  {value}")
    print("")


# =============================================================================
# Main Entry Point
# =============================================================================


def main(argv=None) -> int:
    # 0. Logo
    show_banner()

    # 1. Arguments (--help exits here, before any check). 2. .env is loaded at import.
    args = parse_args(argv)

    # 3. Environment
    if not args.check:
        print_step("Checking environment...")
        err = check_docker()
        if err:
            _fail("Environment check failed", [err])
        print_info("Docker is running")

    # 4. Task: file, then flags on top, then rules
    try:
        config = Config.from_json(args.config) if args.config else Config()
        config.apply_args(args)
    except ConfigError as e:
        _fail("Invalid task", e.errors)
    config.resolve_output()
    errors = config.validate()
    if errors:
        _fail("Invalid task", errors)

    # 5. API keys for the models this task names
    errors = check_api_keys(config.models_in_use())
    if errors:
        _fail("Model check failed", errors)

    # 6. Summary
    print_step("Task")
    _print_summary(config)
    if args.check:
        print_info("Task is valid (--check: not running)")
        return 0

    # 7. Database and queue; the schema is brought up to date before anything writes
    for err in (ensure_postgres(config.postgres_url), ensure_redis(config.redis_url)):
        if err:
            _fail("Environment check failed", [err])
    migrate(config.postgres_url)

    # 8. Output directory
    Path(config.workspace).mkdir(parents=True, exist_ok=True)
    (Path(config.workspace) / "run_id").write_text(config.run_id + "\n")

    # 9. Run
    set_detect_leaks(config.detect_leaks)
    result = run_task(config)

    # 10. Exit code
    return 1 if result.get("status") == "error" else 0


if __name__ == "__main__":
    sys.exit(main())
