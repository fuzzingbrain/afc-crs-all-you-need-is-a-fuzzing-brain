"""
FuzzingBrain v2 - Main Entry Point

This module is the Python entry point for FuzzingBrain.
It is called by FuzzingBrain.sh as: python3 -m fuzzingbrain.main <args>

Four entry modes:
1. REST API Mode (default): Start REST API server
2. MCP Server Mode (--mcp): Start MCP server for AI systems
3. JSON Mode (--config): Load task configuration from JSON file
4. Local Mode (--workspace): Run task on local workspace
"""

import argparse
import atexit
import os
import signal
import sys
from pathlib import Path
from typing import Optional

from .core import (
    Config,
    Task,
    JobType,
    ScanMode,
    setup_logging,
    setup_celery_logging,
    setup_console_only,
)
from .db import MongoDB, RepositoryManager, init_repos


# =============================================================================
# Terminal Cleanup
# =============================================================================


def reset_terminal():
    """Reset terminal to sane state on exit"""
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


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    global _shutdown_requested, _repos
    if _shutdown_requested:
        # Second Ctrl+C - force exit
        print("\n\033[0;31m[FORCE]\033[0m Forcing shutdown...")
        reset_terminal()
        sys.exit(1)

    _shutdown_requested = True
    print(
        "\n\033[1;33m[INTERRUPT]\033[0m Shutting down gracefully... (Press Ctrl+C again to force)"
    )

    # Mark all running workers and tasks as cancelled
    try:
        if _repos:
            # Update workers
            all_workers = _repos.workers.collection.find(
                {"status": {"$in": ["pending", "building", "running"]}}
            )
            worker_count = 0
            for w in all_workers:
                _repos.workers.collection.update_one(
                    {"_id": w["_id"]},
                    {
                        "$set": {
                            "status": "failed",
                            "error_msg": "Cancelled by user (Ctrl+C)",
                        }
                    },
                )
                worker_count += 1

            # Update tasks
            all_tasks = _repos.tasks.collection.find(
                {"status": {"$in": ["pending", "running"]}}
            )
            task_count = 0
            for t in all_tasks:
                _repos.tasks.collection.update_one(
                    {"_id": t["_id"]},
                    {
                        "$set": {
                            "status": "cancelled",
                            "error_msg": "Cancelled by user (Ctrl+C)",
                        }
                    },
                )
                task_count += 1

            if worker_count > 0 or task_count > 0:
                print(
                    f"\033[1;33m[INTERRUPT]\033[0m Marked {worker_count} worker(s) and {task_count} task(s) as cancelled"
                )

            # Display summary for cancelled task
            try:
                from .core.logging import create_final_summary
                from datetime import datetime

                # Find the most recent task
                recent_task = _repos.tasks.collection.find_one(
                    {"status": "cancelled"}, sort=[("created_at", -1)]
                )
                if recent_task:
                    task_id = recent_task.get(
                        "task_id", recent_task.get("_id", "unknown")
                    )
                    project_name = recent_task.get("project_name", "unknown")

                    # Get workers for this task
                    workers = list(_repos.workers.collection.find({"task_id": task_id}))
                    worker_results = []
                    for w in workers:
                        started = w.get("started_at")
                        finished = w.get("finished_at") or datetime.now()
                        duration_sec = (
                            (finished - started).total_seconds() if started else 0
                        )
                        fuzzer = w.get("fuzzer", "N/A")
                        sanitizer = w.get("sanitizer", "N/A")

                        # Query SP count from database (like get_all_worker_results)
                        sp_count = _repos.suspicious_points.count(
                            {
                                "task_id": task_id,
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
                            sp.get("suspicious_point_id") or sp.get("_id")
                            for sp in _repos.suspicious_points.collection.find(
                                {
                                    "task_id": task_id,
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
                            pov_count = _repos.povs.count(
                                {
                                    "task_id": task_id,
                                    "suspicious_point_id": {
                                        "$in": [str(x) for x in worker_sp_ids]
                                    },
                                    "is_successful": True,
                                }
                            )
                        # Also count fuzzer-discovered POVs
                        fuzzer_pov_count = _repos.povs.count(
                            {
                                "task_id": task_id,
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
                                "povs_found": pov_count,
                                "patches_found": w.get("patches_found", 0),
                            }
                        )

                    # Cost tracking now handled via database
                    # TODO: Implement cost aggregation from agents collection
                    total_cost = 0.0
                    budget_limit = 0.0

                    # Calculate elapsed time
                    created_at = recent_task.get("created_at", datetime.now())
                    elapsed_minutes = (datetime.now() - created_at).total_seconds() / 60

                    summary = create_final_summary(
                        project_name=project_name,
                        task_id=task_id,
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

    print_info("Connecting to MongoDB...")
    try:
        db = MongoDB.connect(config.mongodb_url, config.mongodb_db)
        _repos = init_repos(db)
        print_info(f"Connected to database: {config.mongodb_db}")
        return _repos
    except Exception as e:
        print_error(f"Failed to connect to MongoDB: {e}")
        print_error("Make sure MongoDB is running (check: docker ps)")
        sys.exit(1)


# =============================================================================
# Terminal Output
# =============================================================================


class Colors:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    ORANGE = "\033[38;5;208m"
    NC = "\033[0m"


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


def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="FuzzingBrain v2 - Autonomous Cyber Reasoning System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Mode selection
    parser.add_argument("--mcp", action="store_true", help="Start MCP server mode")
    parser.add_argument("--api", action="store_true", help="Start REST API server mode")
    parser.add_argument("--config", type=str, help="JSON configuration file path")

    # Task identification
    parser.add_argument(
        "--task-id", type=str, help="Task ID (auto-generated if not provided)"
    )

    # Project info (required for CLI mode)
    parser.add_argument("--repo-url", type=str, help="Git repository URL")
    parser.add_argument("--project", type=str, help="Project name (e.g., libpng)")
    parser.add_argument(
        "--ossfuzz-project",
        type=str,
        help="OSS-Fuzz project name (if different from --project)",
    )

    # Workspace
    parser.add_argument("--workspace", type=str, help="Workspace directory path")
    parser.add_argument(
        "--in-place", action="store_true", help="Run without copying workspace"
    )

    # Task configuration
    parser.add_argument(
        "--task-type",
        type=str,
        choices=["pov", "patch", "pov-patch", "harness"],
        default="pov",
    )
    parser.add_argument(
        "--scan-mode",
        type=str,
        choices=["full", "delta"],
        default="full",
        help="Scan mode: full or delta",
    )
    parser.add_argument(
        "--sanitizers", type=str, default="address", help="Comma-separated sanitizers"
    )
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in minutes")
    parser.add_argument(
        "--pov-count",
        type=int,
        default=1,
        help="Stop after N verified POVs (0 = unlimited)",
    )
    parser.add_argument(
        "--fuzzers",
        type=str,
        help="Comma-separated list of fuzzers to use (empty = all)",
    )
    parser.add_argument(
        "--budget",
        type=float,
        default=50.0,
        help="Budget limit in dollars (0 = unlimited)",
    )

    # Commit configuration
    parser.add_argument("--target-commit", type=str, help="Target commit for full scan")
    parser.add_argument("--base-commit", type=str, help="Base commit for delta scan")
    parser.add_argument("--delta-commit", type=str, help="Delta commit for delta scan")

    # Fuzz tooling
    parser.add_argument(
        "--fuzz-tooling-url", type=str, help="Custom fuzz-tooling repository URL"
    )
    parser.add_argument("--fuzz-tooling-ref", type=str, help="Fuzz-tooling branch/tag")

    # Prebuild (advanced)
    parser.add_argument("--work-id", type=str, help="Work ID for prebuild data")
    parser.add_argument(
        "--prebuild-dir", type=str, help="Path to prebuild data directory"
    )

    # Evaluation
    parser.add_argument("--eval-server", type=str, help="Evaluation server URL")

    # Patch mode specific
    parser.add_argument("--gen-blob", type=str, help="Generator blob for patch mode")
    parser.add_argument(
        "--input-blob", type=str, help="Input blob (base64) for patch mode"
    )

    # Harness mode specific
    parser.add_argument(
        "--targets", type=str, help="Target functions as JSON array for harness mode"
    )
    parser.add_argument(
        "--targets-file", type=str, help="Path to JSON file containing targets"
    )

    # Fuzzer sources (complex type, JSON format)
    parser.add_argument(
        "--fuzzer-sources",
        type=str,
        help="Fuzzer sources as JSON object: {name: [paths]}",
    )
    parser.add_argument(
        "--fuzzer-sources-file",
        type=str,
        help="Path to JSON file containing fuzzer sources",
    )

    return parser.parse_args()


def create_config_from_args(args: argparse.Namespace) -> Config:
    """Create Config from parsed arguments"""
    # Start with environment config
    config = Config.from_env()

    # MCP server mode
    if args.mcp:
        config.mcp_mode = True
        return config

    # JSON mode - load from file
    if args.config:
        config = Config.from_json(args.config)
        # Infrastructure config from environment (not from JSON)
        config.mongodb_url = os.environ.get("MONGODB_URL", "mongodb://localhost:27017")
        config.mongodb_db = os.environ.get("MONGODB_DB", "fuzzingbrain")
        config.redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        return config

    # CLI mode - apply all arguments
    # Project info
    if args.repo_url:
        config.repo_url = args.repo_url
    if args.project:
        config.project_name = args.project
    if args.ossfuzz_project:
        config.ossfuzz_project_name = args.ossfuzz_project

    # Task identification
    if args.task_id:
        config.task_id = args.task_id

    # Workspace
    if args.workspace:
        config.workspace = args.workspace
    if args.in_place:
        config.in_place = args.in_place

    # Task configuration
    if args.task_type:
        config.task_type = args.task_type
    if args.scan_mode:
        config.scan_mode = args.scan_mode
    if args.sanitizers:
        config.sanitizers = args.sanitizers.split(",")
    if args.timeout:
        config.timeout_minutes = args.timeout
    if args.pov_count is not None:
        config.pov_count = args.pov_count
    if args.fuzzers:
        config.fuzzer_filter = [f.strip() for f in args.fuzzers.split(",") if f.strip()]
    if args.budget:
        config.budget_limit = args.budget

    # Commit configuration
    if args.target_commit:
        config.target_commit = args.target_commit
    if args.base_commit:
        config.base_commit = args.base_commit
    if args.delta_commit:
        config.delta_commit = args.delta_commit

    # Fuzz tooling
    if args.fuzz_tooling_url:
        config.fuzz_tooling_url = args.fuzz_tooling_url
    if args.fuzz_tooling_ref:
        config.fuzz_tooling_ref = args.fuzz_tooling_ref

    # Prebuild
    if args.work_id:
        config.work_id = args.work_id
    if args.prebuild_dir:
        config.prebuild_dir = args.prebuild_dir

    # Evaluation
    if args.eval_server:
        config.eval_server = args.eval_server

    # Patch mode specific
    if args.gen_blob:
        config.gen_blob = args.gen_blob
    if args.input_blob:
        config.input_blob = args.input_blob

    # Harness mode specific (JSON format or file)
    if args.targets:
        import json

        config.targets = json.loads(args.targets)
    elif args.targets_file:
        import json

        with open(args.targets_file, "r") as f:
            config.targets = json.load(f)

    # Fuzzer sources (JSON format or file)
    if args.fuzzer_sources:
        import json

        config.fuzzer_sources = json.loads(args.fuzzer_sources)
    elif args.fuzzer_sources_file:
        import json

        with open(args.fuzzer_sources_file, "r") as f:
            config.fuzzer_sources = json.load(f)

    return config


# =============================================================================
# Shared Business Logic
# =============================================================================


def process_task(task: Task, config: Config) -> dict:
    """
    Process a task - shared logic for all entry modes.

    This is the core business logic that:
    1. Parses and validates the workspace
    2. Sets up repository and fuzz-tooling
    3. Discovers fuzzers
    4. Builds fuzzers
    5. Dispatches workers via Celery
    6. Monitors and collects results
    """
    # Setup logging for this task
    project_name = config.project_name or "unknown"
    log_dir = setup_logging(
        project_name,
        task.task_id,
        metadata={
            "Task Type": task.task_type.value,
            "Scan Mode": task.scan_mode.value,
            "Workspace": config.workspace,
            "Sanitizers": ", ".join(config.sanitizers),
            "Timeout": f"{config.timeout_minutes} minutes",
            "Base Commit": config.base_commit,
            "Delta Commit": config.delta_commit,
        },
    )
    # Setup celery.log for Celery process logs
    setup_celery_logging()
    print_info(f"Logs: {log_dir}")

    print_info(f"Task ID: {task.task_id}")
    print_info(f"Task Type: {task.task_type.value}")
    print_info(f"Scan Mode: {task.scan_mode.value}")
    print("")

    print_step("Starting task processing pipeline...")

    from .core.task_processor import process_task as run_processor

    result = run_processor(task, config, get_repos())

    # Display result
    print("")
    if result["status"] == "error":
        print_error(f"Task failed: {result['message']}")
    else:
        print_info(f"Status: {result['status']}")
        print_info(f"Message: {result['message']}")
        if "workspace" in result:
            print_info(f"Workspace: {result['workspace']}")
        if "fuzzers" in result and result["fuzzers"]:
            print_info(f"Fuzzers: {', '.join(result['fuzzers'])}")

    return result


def create_task_from_config(config: Config) -> Task:
    """Create a Task object from Config"""
    from bson import ObjectId

    task_id = config.task_id or str(ObjectId())

    return Task(
        task_id=task_id,
        task_type=JobType(config.task_type),
        scan_mode=ScanMode(config.scan_mode),
        task_path=config.workspace,
        src_path=f"{config.workspace}/repo" if config.workspace else None,
        fuzz_tooling_path=f"{config.workspace}/fuzz-tooling"
        if config.workspace
        else None,
        diff_path=f"{config.workspace}/diff"
        if config.workspace and config.scan_mode == "delta"
        else None,
        repo_url=config.repo_url,
        project_name=config.project_name,
        sanitizers=config.sanitizers,
        timeout_minutes=config.timeout_minutes,
        base_commit=config.base_commit,
        delta_commit=config.delta_commit,
        is_fuzz_tooling_provided=config.fuzz_tooling_path is not None,
    )


# =============================================================================
# Entry Mode: MCP Server
# =============================================================================


def run_mcp_server(config: Config):
    """
    Start MCP server mode.

    Exposes FuzzingBrain as MCP tools for external AI systems.
    """
    setup_console_only("INFO")
    print_step("Starting FuzzingBrain MCP Server...")
    print_info(f"Host: {config.mcp_host}")
    print_info(f"Port: {config.mcp_port}")
    print("")
    print_info("Available MCP Tools:")
    print_info("  - fuzzingbrain_find_pov")
    print_info("  - fuzzingbrain_generate_patch")
    print_info("  - fuzzingbrain_pov_patch")
    print_info("  - fuzzingbrain_get_status")
    print_info("  - fuzzingbrain_generate_harness")
    print("")

    from .mcp_server import run_server as start_mcp_server

    start_mcp_server(config)


# =============================================================================
# Entry Mode: REST API
# =============================================================================


def run_api(config: Config):
    """
    Start REST API server mode.

    Exposes FuzzingBrain as REST API endpoints.
    """
    setup_console_only("INFO")
    print_step("Starting FuzzingBrain REST API Server...")
    print_info(f"Host: {config.api_host}")
    print_info(f"Port: {config.api_port}")
    print("")
    print_info("Available API Endpoints:")
    print_info("  POST /api/v1/pov         - Find vulnerabilities")
    print_info("  POST /api/v1/patch       - Generate patches")
    print_info("  POST /api/v1/pov-patch   - POV + Patch combo")
    print_info("  POST /api/v1/harness     - Generate harnesses")
    print_info("  GET  /api/v1/status/{id} - Get task status")
    print_info("  GET  /docs               - API documentation")
    print("")

    from .api_server import run_api_server

    run_api_server(host=config.api_host, port=config.api_port)


# =============================================================================
# Workspace Setup
# =============================================================================


def setup_workspace(config: Config) -> Config:
    """
    Setup workspace directory with repo and fuzz-tooling.

    This ensures the workspace has:
    1. A workspace directory
    2. A cloned repository (if repo_url provided)
    3. fuzz-tooling from OSS-Fuzz or custom URL

    Returns updated config with workspace path set.
    """
    from bson import ObjectId
    import subprocess
    import shutil
    import tempfile

    script_dir = Path(__file__).parent.parent
    workspace_base = script_dir / "workspace"

    # Generate task ID if not provided
    task_id = config.task_id or str(ObjectId())
    config.task_id = task_id

    # Determine project name
    project_name = config.project_name
    if not project_name and config.repo_url:
        # Extract from repo URL
        project_name = config.repo_url.rstrip("/").rstrip(".git").split("/")[-1]
        config.project_name = project_name

    # Create workspace if not provided
    if not config.workspace:
        workspace_name = f"{project_name}_{task_id}" if project_name else task_id
        config.workspace = str(workspace_base / workspace_name)

    workspace = Path(config.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    # Clone repository if needed
    repo_path = workspace / "repo"
    if not repo_path.exists() and config.repo_url:
        print_step("Cloning repository...")
        print_info(f"URL: {config.repo_url}")
        try:
            result = subprocess.run(
                ["git", "clone", config.repo_url, str(repo_path)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                print_error(f"Failed to clone repository: {result.stderr}")
                sys.exit(1)
            print_info("Repository cloned successfully")

            # Checkout target commit if specified (Full Scan mode)
            if config.target_commit:
                print_info(f"Checking out commit: {config.target_commit}")
                subprocess.run(
                    ["git", "checkout", config.target_commit],
                    cwd=str(repo_path),
                    capture_output=True,
                )
            # Checkout delta commit for Delta Scan mode
            elif config.scan_mode == "delta" and config.delta_commit:
                print_info(f"Checking out delta commit: {config.delta_commit}")
                subprocess.run(
                    ["git", "checkout", config.delta_commit],
                    cwd=str(repo_path),
                    capture_output=True,
                )
            elif (
                config.scan_mode == "delta"
                and config.base_commit
                and not config.delta_commit
            ):
                # If no delta_commit specified, use HEAD (default behavior is fine)
                print_info("Delta scan: using HEAD as delta commit")
        except Exception as e:
            print_error(f"Failed to clone repository: {e}")
            sys.exit(1)
    elif repo_path.exists():
        # Repo already exists, ensure correct commit is checked out
        if config.scan_mode == "delta" and config.delta_commit:
            print_info(f"Ensuring delta commit is checked out: {config.delta_commit}")
            subprocess.run(
                ["git", "checkout", config.delta_commit],
                cwd=str(repo_path),
                capture_output=True,
            )
        elif config.target_commit:
            print_info(f"Ensuring target commit is checked out: {config.target_commit}")
            subprocess.run(
                ["git", "checkout", config.target_commit],
                cwd=str(repo_path),
                capture_output=True,
            )

    # Setup fuzz-tooling if needed
    fuzz_tooling_path = workspace / "fuzz-tooling"
    if not fuzz_tooling_path.exists() or not any(fuzz_tooling_path.iterdir()):
        print_step("Setting up fuzz-tooling...")

        # Determine OSS-Fuzz project name
        ossfuzz_project = config.ossfuzz_project_name or project_name

        if config.fuzz_tooling_url:
            # Use custom fuzz-tooling URL
            print_info(f"Using custom fuzz-tooling: {config.fuzz_tooling_url}")
            try:
                with tempfile.TemporaryDirectory() as tmp_dir:
                    clone_args = ["git", "clone", "--depth", "1"]
                    if config.fuzz_tooling_ref:
                        clone_args.extend(["--branch", config.fuzz_tooling_ref])
                    clone_args.extend([config.fuzz_tooling_url, tmp_dir])

                    result = subprocess.run(clone_args, capture_output=True, text=True)
                    if result.returncode != 0:
                        print_error(f"Failed to clone fuzz-tooling: {result.stderr}")
                    else:
                        # Copy relevant directories
                        fuzz_tooling_path.mkdir(parents=True, exist_ok=True)

                        # Look for project directory
                        projects_dir = Path(tmp_dir) / "projects"
                        if projects_dir.exists() and ossfuzz_project:
                            project_dir = _find_ossfuzz_project(
                                projects_dir, ossfuzz_project
                            )
                            if project_dir:
                                dest = fuzz_tooling_path / "projects" / project_dir.name
                                dest.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copytree(project_dir, dest)
                                print_info(f"Found project: {project_dir.name}")

                        # Copy infra directory if exists
                        infra_dir = Path(tmp_dir) / "infra"
                        if infra_dir.exists():
                            shutil.copytree(infra_dir, fuzz_tooling_path / "infra")

                        print_info("Custom fuzz-tooling setup complete")
            except Exception as e:
                print_warn(f"Failed to setup custom fuzz-tooling: {e}")
        else:
            # Use google/oss-fuzz
            print_info("Fetching from google/oss-fuzz...")
            try:
                with tempfile.TemporaryDirectory() as tmp_dir:
                    result = subprocess.run(
                        [
                            "git",
                            "clone",
                            "--depth",
                            "1",
                            "https://github.com/google/oss-fuzz.git",
                            tmp_dir,
                        ],
                        capture_output=True,
                        text=True,
                    )
                    if result.returncode != 0:
                        print_warn(f"Failed to clone oss-fuzz: {result.stderr}")
                    else:
                        projects_dir = Path(tmp_dir) / "projects"
                        if projects_dir.exists() and ossfuzz_project:
                            project_dir = _find_ossfuzz_project(
                                projects_dir, ossfuzz_project
                            )
                            if project_dir:
                                fuzz_tooling_path.mkdir(parents=True, exist_ok=True)
                                dest = fuzz_tooling_path / "projects" / project_dir.name
                                dest.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copytree(project_dir, dest)
                                print_info(
                                    f"Found OSS-Fuzz project: {project_dir.name}"
                                )

                                # Copy infra directory
                                infra_dir = Path(tmp_dir) / "infra"
                                if infra_dir.exists():
                                    shutil.copytree(
                                        infra_dir, fuzz_tooling_path / "infra"
                                    )
                            else:
                                print_warn(
                                    f"No matching OSS-Fuzz project found for: {ossfuzz_project}"
                                )
                                print_warn(
                                    "Use 'ossfuzz_project_name' in config to specify manually"
                                )
            except Exception as e:
                print_warn(f"Failed to fetch from oss-fuzz: {e}")
    else:
        print_info("Using existing fuzz-tooling")

    # Setup diff directory for delta scan
    if config.scan_mode == "delta" and config.base_commit:
        diff_path = workspace / "diff"
        diff_path.mkdir(parents=True, exist_ok=True)

        diff_file = diff_path / "ref.diff"
        if not diff_file.exists() and repo_path.exists():
            print_step("Generating diff for delta scan...")
            delta_commit = config.delta_commit or "HEAD"
            try:
                result = subprocess.run(
                    [
                        "git",
                        "diff",
                        f"{config.base_commit}..{delta_commit}",
                        "--",
                        ".",
                        ":!.aixcc",
                        ":!*/.aixcc",
                    ],
                    cwd=str(repo_path),
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    diff_file.write_text(result.stdout)
                    print_info(
                        f"Generated diff: {config.base_commit[:8]}..{delta_commit[:8] if delta_commit != 'HEAD' else 'HEAD'}"
                    )
            except Exception as e:
                print_warn(f"Failed to generate diff: {e}")

    return config


def _find_ossfuzz_project(projects_dir: Path, project_name: str) -> Optional[Path]:
    """
    Find OSS-Fuzz project directory by name.

    Tries various name variations to match the project.
    """
    # Direct match
    direct = projects_dir / project_name
    if direct.exists():
        return direct

    # Lowercase
    lower = projects_dir / project_name.lower()
    if lower.exists():
        return lower

    # Remove common prefixes/suffixes
    import re

    stripped = re.sub(r"^(lib|py|go|rust)-?", "", project_name, flags=re.IGNORECASE)
    stripped = re.sub(r"-?(lib|py|go|rust)$", "", stripped, flags=re.IGNORECASE)
    if stripped != project_name:
        stripped_path = projects_dir / stripped
        if stripped_path.exists():
            return stripped_path
        stripped_lower = projects_dir / stripped.lower()
        if stripped_lower.exists():
            return stripped_lower

    # Remove afc- prefix (AIxCC repos)
    if project_name.lower().startswith("afc-"):
        afc_stripped = project_name[4:]
        afc_path = projects_dir / afc_stripped
        if afc_path.exists():
            return afc_path
        afc_lower = projects_dir / afc_stripped.lower()
        if afc_lower.exists():
            return afc_lower

    return None


# =============================================================================
# Entry Mode: JSON Config
# =============================================================================


def run_json_mode(config: Config):
    """
    Run from JSON configuration file.

    All task parameters are loaded from the JSON file.
    """
    print_step("Starting FuzzingBrain from JSON config...")

    # Setup workspace (clone repo, download fuzz-tooling)
    config = setup_workspace(config)

    # Validate configuration
    errors = config.validate()
    if errors:
        for error in errors:
            print_error(error)
        sys.exit(1)

    # Print configuration summary
    print_info(f"Scan Mode: {config.scan_mode}")
    print_info(f"Task Type: {config.task_type}")
    print_info(f"Sanitizers: {', '.join(config.sanitizers)}")
    print_info(f"Timeout: {config.timeout_minutes} minutes")

    if config.repo_url:
        print_info(f"Repository: {config.repo_url}")
    if config.workspace:
        print_info(f"Workspace: {config.workspace}")
    if config.scan_mode == "delta":
        print_info(
            f"Delta: {config.base_commit[:8]}..{(config.delta_commit or 'HEAD')[:8] if config.delta_commit else 'HEAD'}"
        )

    print("")

    # Create and process task
    task = create_task_from_config(config)
    result = process_task(task, config)

    return result


# =============================================================================
# Entry Mode: Local Workspace
# =============================================================================


def run_local_mode(config: Config):
    """
    Run on local workspace.

    Uses an existing workspace directory with repo and fuzz-tooling.
    """
    print_step("Starting FuzzingBrain Local Mode...")

    # Validate configuration
    errors = config.validate()
    if errors:
        for error in errors:
            print_error(error)
        sys.exit(1)

    # Print configuration summary
    print_info(f"Workspace: {config.workspace}")
    print_info(f"Scan Mode: {config.scan_mode}")
    print_info(f"Task Type: {config.task_type}")
    print_info(f"Sanitizers: {', '.join(config.sanitizers)}")
    print_info(f"Timeout: {config.timeout_minutes} minutes")

    if config.scan_mode == "delta":
        print_info(
            f"Delta: {config.base_commit[:8]}..{(config.delta_commit or 'HEAD')[:8] if config.delta_commit else 'HEAD'}"
        )

    print("")

    # Verify workspace structure
    workspace = Path(config.workspace)
    if not workspace.exists():
        print_error(f"Workspace does not exist: {config.workspace}")
        sys.exit(1)

    repo_path = workspace / "repo"
    if not repo_path.exists():
        print_warn("No repo directory found in workspace")

    fuzz_tooling = workspace / "fuzz-tooling"
    if fuzz_tooling.exists():
        print_info("Fuzz-tooling found")
    else:
        print_warn("No fuzz-tooling directory found")

    print("")

    # Create and process task
    task = create_task_from_config(config)
    result = process_task(task, config)

    # Show expected output structure
    print("")
    print_step("Expected output structure:")
    print_info(f"  {config.workspace}/results/")
    if "pov" in config.task_type:
        print_info("  ├── povs/")
    if "patch" in config.task_type:
        print_info("  ├── patches/")
    if config.task_type == "harness":
        print_info("  ├── harnesses/")
    print_info("  └── report.json")

    return result


# =============================================================================
# Main Entry Point
# =============================================================================


def main():
    """Main entry point - routes to appropriate mode"""
    args = parse_args()
    config = create_config_from_args(args)

    # =========================================================================
    # Evaluation Reporter removed - using MongoDB persistence instead
    # Worker/Agent context is now handled via WorkerContext/AgentContext
    # =========================================================================
    if config.budget_limit > 0:
        print(f"\033[0;36m[CONFIG]\033[0m Budget limit: ${config.budget_limit:.2f}")
    if config.pov_count > 0:
        print(f"\033[0;36m[CONFIG]\033[0m POV count limit: {config.pov_count}")

    # Show fuzzer filter if specified
    if config.fuzzer_filter:
        print(
            f"\033[0;36m[CONFIG]\033[0m Fuzzer filter: {', '.join(config.fuzzer_filter)}"
        )

    # Check for API mode from args
    if hasattr(args, "api") and args.api:
        config.api_mode = True

    # =========================================================================
    # Initialize database connection (shared by all modes)
    # =========================================================================
    repos = init_database(config)

    # =========================================================================
    # Route to corresponding mode
    # =========================================================================
    if config.mcp_mode:
        # Mode 1: MCP Server
        run_mcp_server(config)
    elif config.api_mode:
        # Mode 2: REST API Server
        run_api(config)
    elif args.config:
        # Mode 3: JSON Config
        run_json_mode(config)
    else:
        # Mode 4: Local Workspace
        run_local_mode(config)


if __name__ == "__main__":
    main()
