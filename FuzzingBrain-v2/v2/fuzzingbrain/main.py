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

from .core import Config, Task, JobType, ScanMode, setup_logging, setup_console_only
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
        os.system('stty sane 2>/dev/null')
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
    print("\n\033[1;33m[INTERRUPT]\033[0m Shutting down gracefully... (Press Ctrl+C again to force)")

    # Mark all running workers as cancelled
    try:
        if _repos:
            from .core.models import WorkerStatus
            # Find all non-finished workers and mark them cancelled
            all_workers = _repos.workers.collection.find({
                "status": {"$in": ["pending", "building", "running"]}
            })
            cancelled_count = 0
            for w in all_workers:
                _repos.workers.collection.update_one(
                    {"_id": w["_id"]},
                    {"$set": {
                        "status": "failed",
                        "error_msg": "Cancelled by user (Ctrl+C)"
                    }}
                )
                cancelled_count += 1
            if cancelled_count > 0:
                print(f"\033[1;33m[INTERRUPT]\033[0m Marked {cancelled_count} worker(s) as cancelled")
    except Exception as e:
        print(f"\033[0;31m[ERROR]\033[0m Failed to update worker status: {e}")

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
    parser.add_argument("--task-id", type=str, help="Task ID (auto-generated if not provided)")

    # Workspace
    parser.add_argument("--workspace", type=str, help="Workspace directory path")
    parser.add_argument("--in-place", action="store_true", help="Run without copying workspace")

    # Task configuration
    parser.add_argument("--job-type", type=str, choices=["pov", "patch", "pov-patch", "harness"], default="pov-patch")
    parser.add_argument("--scan-mode", type=str, choices=["full", "delta"], default="full", help="Scan mode: full or delta")
    parser.add_argument("--sanitizers", type=str, default="address", help="Comma-separated sanitizers")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in minutes")

    # Delta scan
    parser.add_argument("--base-commit", type=str, help="Base commit for delta scan")
    parser.add_argument("--delta-commit", type=str, help="Delta commit for delta scan")

    # Project info
    parser.add_argument("--project", type=str, help="Project name (e.g., libpng)")
    parser.add_argument("--ossfuzz-project", type=str, help="OSS-Fuzz project name (if different from --project)")

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
        return config

    # Local mode - apply CLI arguments
    if args.task_id:
        config.task_id = args.task_id
    if args.workspace:
        config.workspace = args.workspace
    if args.in_place:
        config.in_place = args.in_place
    if args.job_type:
        config.job_type = args.job_type
    if args.scan_mode:
        config.scan_mode = args.scan_mode
    if args.sanitizers:
        config.sanitizers = args.sanitizers.split(",")
    if args.timeout:
        config.timeout_minutes = args.timeout
    if args.base_commit:
        config.base_commit = args.base_commit
    if args.delta_commit:
        config.delta_commit = args.delta_commit
    if args.project:
        config.project_name = args.project
    if args.ossfuzz_project:
        config.ossfuzz_project = args.ossfuzz_project

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
        }
    )
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
    import uuid
    task_id = config.task_id or str(uuid.uuid4())[:8]

    return Task(
        task_id=task_id,
        task_type=JobType(config.job_type),
        scan_mode=ScanMode(config.scan_mode),
        task_path=config.workspace,
        src_path=f"{config.workspace}/repo" if config.workspace else None,
        fuzz_tooling_path=f"{config.workspace}/fuzz-tooling" if config.workspace else None,
        diff_path=f"{config.workspace}/diff" if config.workspace and config.scan_mode == "delta" else None,
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
# Entry Mode: JSON Config
# =============================================================================

def run_json_mode(config: Config):
    """
    Run from JSON configuration file.

    All task parameters are loaded from the JSON file.
    """
    print_step("Starting FuzzingBrain from JSON config...")

    # Validate configuration
    errors = config.validate()
    if errors:
        for error in errors:
            print_error(error)
        sys.exit(1)

    # Print configuration summary
    print_info(f"Scan Mode: {config.scan_mode}")
    print_info(f"Job Type: {config.job_type}")
    print_info(f"Sanitizers: {', '.join(config.sanitizers)}")
    print_info(f"Timeout: {config.timeout_minutes} minutes")

    if config.repo_url:
        print_info(f"Repository: {config.repo_url}")
    if config.workspace:
        print_info(f"Workspace: {config.workspace}")
    if config.scan_mode == "delta":
        print_info(f"Delta: {config.base_commit[:8]}..{(config.delta_commit or 'HEAD')[:8] if config.delta_commit else 'HEAD'}")

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
    print_info(f"Job Type: {config.job_type}")
    print_info(f"Sanitizers: {', '.join(config.sanitizers)}")
    print_info(f"Timeout: {config.timeout_minutes} minutes")

    if config.scan_mode == "delta":
        print_info(f"Delta: {config.base_commit[:8]}..{(config.delta_commit or 'HEAD')[:8] if config.delta_commit else 'HEAD'}")

    print("")

    # Verify workspace structure
    workspace = Path(config.workspace)
    if not workspace.exists():
        print_error(f"Workspace does not exist: {config.workspace}")
        sys.exit(1)

    repo_path = workspace / "repo"
    if not repo_path.exists():
        print_warn(f"No repo directory found in workspace")

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
    if "pov" in config.job_type:
        print_info(f"  ├── povs/")
    if "patch" in config.job_type:
        print_info(f"  ├── patches/")
    if config.job_type == "harness":
        print_info(f"  ├── harnesses/")
    print_info(f"  └── report.json")

    return result


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Main entry point - routes to appropriate mode"""
    args = parse_args()
    config = create_config_from_args(args)

    # Check for API mode from args
    if hasattr(args, 'api') and args.api:
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
