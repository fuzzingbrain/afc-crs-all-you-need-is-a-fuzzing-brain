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
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Keys and the PostgreSQL/Redis URLs live in the repo's .env. Loaded before the
# imports below and before any config is read, so POSTGRES_URL there is the one
# this process connects to. A variable already in the environment wins.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from .core import (  # noqa: E402
    Config,
    Run,
    JobType,
    ScanMode,
    setup_logging,
    setup_celery_logging,
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
from .db import RepositoryManager, connect_repositories  # noqa: E402
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


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    global _shutdown_requested, _repos, _current_run_id
    if _shutdown_requested:
        # Second Ctrl+C - force exit
        print("\n\033[0;31m[FORCE]\033[0m Forcing shutdown...")
        reset_terminal()
        sys.exit(1)

    _shutdown_requested = True
    print(
        "\n\033[1;33m[INTERRUPT]\033[0m Shutting down gracefully... (Press Ctrl+C again to force)"
    )

    # If no run was started, exit immediately
    if not _repos or not _current_run_id:
        reset_terminal()
        sys.exit(0)

    # Mark workers and run as cancelled (scoped to current run only)
    try:
        from bson import ObjectId as _ObjectId

        run_oid = (
            _ObjectId(_current_run_id)
            if len(_current_run_id) == 24
            else _current_run_id
        )

        # Update workers for THIS run only
        result = _repos.workers.collection.update_many(
            {
                "run_id": run_oid,
                "status": {"$in": ["pending", "building", "running"]},
            },
            {
                "$set": {
                    "status": "failed",
                    "error_msg": "Cancelled by user (Ctrl+C)",
                }
            },
        )
        worker_count = result.modified_count

        # Update THIS run only
        run_result = _repos.runs.collection.update_one(
            {
                "_id": run_oid,
                "status": {"$in": ["pending", "running"]},
            },
            {
                "$set": {
                    "status": "cancelled",
                    "error_msg": "Cancelled by user (Ctrl+C)",
                }
            },
        )
        run_count = run_result.modified_count

        # Cancel in-memory agents for this run
        try:
            from .agents.context import get_all_agent_contexts, force_cleanup_agents
            from .db import get_database

            for ctx in get_all_agent_contexts().values():
                if ctx.run_id == _current_run_id and ctx.status == "running":
                    try:
                        ctx.cancel()
                    except Exception:
                        pass

            # Force-cleanup zombie agents in DB
            try:
                db = get_database()
            except Exception:
                db = None
            if db is not None:
                force_cleanup_agents(_current_run_id, db)
        except Exception:
            pass

        if worker_count > 0 or run_count > 0:
            print(
                f"\033[1;33m[INTERRUPT]\033[0m Marked {worker_count} worker(s) and {run_count} run(s) as cancelled"
            )

        # Display summary for current run
        try:
            from .core.logging import create_final_summary
            from datetime import datetime

            recent_run = _repos.runs.collection.find_one({"_id": run_oid})
            if recent_run:
                run_id = str(
                    recent_run.get("run_id") or recent_run.get("_id") or "unknown"
                )
                project_name = recent_run.get("project_name", "unknown")

                # Get workers for this run
                workers = list(_repos.workers.collection.find({"run_id": run_oid}))
                worker_results = []
                for w in workers:
                    started = w.get("started_at")
                    finished = w.get("finished_at") or datetime.now()
                    duration_sec = (
                        (finished - started).total_seconds() if started else 0
                    )
                    fuzzer = w.get("fuzzer", "N/A")
                    sanitizer = w.get("sanitizer", "N/A")

                    # Query SP count from database
                    sp_count = _repos.suspicious_points.count(
                        {
                            "run_id": run_oid,
                            "sources": {
                                "$elemMatch": {
                                    "harness_name": fuzzer,
                                    "sanitizer": sanitizer,
                                }
                            },
                        }
                    )

                    # Query POV count from database
                    worker_sp_ids = [
                        str(sp.get("suspicious_point_id") or sp.get("_id"))
                        for sp in _repos.suspicious_points.collection.find(
                            {
                                "run_id": run_oid,
                                "sources": {
                                    "$elemMatch": {
                                        "harness_name": fuzzer,
                                        "sanitizer": sanitizer,
                                    }
                                },
                            },
                            {"suspicious_point_id": 1, "_id": 1},
                        )
                    ]
                    pov_count = 0
                    if worker_sp_ids:
                        sp_oids = []
                        for x in worker_sp_ids:
                            try:
                                sp_oids.append(_ObjectId(x))
                            except Exception:
                                sp_oids.append(x)
                        pov_count = _repos.povs.count(
                            {
                                "run_id": run_oid,
                                "suspicious_point_id": {"$in": sp_oids},
                                "is_successful": True,
                            }
                        )
                    # Also count fuzzer-discovered POVs
                    fuzzer_pov_count = _repos.povs.count(
                        {
                            "run_id": run_oid,
                            "harness_name": fuzzer,
                            "sanitizer": sanitizer,
                            "suspicious_point_id": {"$in": ["", None]},
                            "is_successful": True,
                        }
                    )
                    pov_count += fuzzer_pov_count

                    worker_results.append(
                        {
                            "fuzzer": fuzzer,
                            "sanitizer": sanitizer,
                            "status": w.get("status", "cancelled"),
                            "duration_str": f"{duration_sec / 60:.1f}m",
                            "sps_found": sp_count,
                            "pov_generated": pov_count,
                            "patch_generated": w.get("patch_generated", 0),
                        }
                    )

                # Read cost from database
                total_cost = recent_run.get("llm_cost", 0.0)
                budget_limit = recent_run.get("budget_limit", 0.0)

                # Calculate elapsed time
                created_at = recent_run.get("created_at", datetime.now())
                elapsed_minutes = (datetime.now() - created_at).total_seconds() / 60

                summary = create_final_summary(
                    project_name=project_name,
                    run_id=run_id,
                    workers=worker_results,
                    total_elapsed_minutes=elapsed_minutes,
                    use_color=True,
                    total_cost=total_cost,
                    budget_limit=budget_limit,
                    exit_reason="cancelled",
                )
                print(summary)
        except Exception as e:
            print(f"\033[0;31m[ERROR]\033[0m Failed to generate summary: {e}")

    except Exception as e:
        print(f"\033[0;31m[ERROR]\033[0m Failed to update status: {e}")

    # Close LLM clients before stopping infrastructure
    # (prevents SSL transport errors when event loop closes)
    try:
        from .llms import LLMClient

        LLMClient.close_all()
    except Exception:
        pass

    # Stop infrastructure
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

# Global Repository Manager - initialized in init_database()
_repos: Optional[RepositoryManager] = None


def get_repos() -> RepositoryManager:
    """Get global RepositoryManager instance"""
    global _repos
    if _repos is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return _repos


def init_database(config: Config) -> RepositoryManager:
    """
    Initialize database connection (global singleton)

    Called once at application startup, then shared by all components.
    """
    global _repos

    if _repos is not None:
        return _repos

    try:
        _repos = connect_repositories()
        return _repos
    except Exception as e:
        print_error(str(e))
        sys.exit(1)


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
            "same field in the file. Field reference: docs/task_full.jsonc."
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

def create_run(config: Config) -> Run:
    """The Run record the pipeline and the database work with."""
    workspace = config.workspace
    return Run(
        run_id=config.run_id,
        task_type=JobType(config.task_type),
        scan_mode=ScanMode(config.scan_mode),
        workspace_path=workspace,
        src_path=f"{workspace}/repo",
        fuzz_tooling_path=f"{workspace}/fuzz-tooling",
        diff_path=f"{workspace}/diff" if config.scan_mode == "delta" else None,
        repo_url=config.repo_url,
        project_name=config.project_name,
        ossfuzz_project_name=config.ossfuzz_project_name,
        sanitizers=config.sanitizers,
        timeout_minutes=config.timeout_minutes,
        pov_count=config.pov_count,
        budget_limit=config.budget_limit,
        target_commit=config.target_commit,
        base_commit=config.base_commit,
        delta_commit=config.delta_commit,
        fuzz_tooling_url=config.fuzz_tooling_url,
        fuzz_tooling_ref=config.fuzz_tooling_ref,
        is_fuzz_tooling_provided=config.fuzz_tooling_path is not None,
    )


def run_task(config: Config) -> dict:
    """Run one task end to end. Every way of starting FuzzingBrain ends here."""
    global _current_run_id
    run = create_run(config)
    _current_run_id = run.run_id

    log_dir = setup_logging(
        config.project_name,
        run.run_id,
        metadata={label: value for label, value in config.summary()},
    )
    setup_celery_logging()
    print_info(f"Logs: {log_dir}")
    print_step("Starting run processing pipeline...")

    from .core.run_processor import process_run

    result = process_run(run, config, get_repos())

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
    init_database(config)

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
