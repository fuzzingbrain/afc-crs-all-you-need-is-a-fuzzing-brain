"""
FuzzingBrain v2 - Main Entry Point

This module is the Python entry point for FuzzingBrain.
It is called by FuzzingBrain.sh as: python3 -m fuzzingbrain.main <args>

Three entry modes:
1. Server Mode (--server): Start MCP server for external AI systems
2. JSON Mode (--config): Load task configuration from JSON file
3. Local Mode (--workspace): Run task on local workspace
"""

import argparse
import sys
from pathlib import Path

from .config import Config
from .models import Task, JobType


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
    parser.add_argument("--server", action="store_true", help="Start MCP server mode")
    parser.add_argument("--config", type=str, help="JSON configuration file path")

    # Task identification
    parser.add_argument("--task-id", type=str, help="Task ID (auto-generated if not provided)")

    # Workspace
    parser.add_argument("--workspace", type=str, help="Workspace directory path")
    parser.add_argument("--in-place", action="store_true", help="Run without copying workspace")

    # Task configuration
    parser.add_argument("--job-type", type=str, choices=["pov", "patch", "pov-patch", "harness"], default="pov-patch")
    parser.add_argument("--sanitizers", type=str, default="address", help="Comma-separated sanitizers")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in minutes")

    # Delta scan
    parser.add_argument("--base-commit", type=str, help="Base commit for delta scan")
    parser.add_argument("--delta-commit", type=str, help="Delta commit for delta scan")

    return parser.parse_args()


def create_config_from_args(args: argparse.Namespace) -> Config:
    """Create Config from parsed arguments"""
    # Start with environment config
    config = Config.from_env()

    # Server mode
    if args.server:
        config.server_mode = True
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
    if args.sanitizers:
        config.sanitizers = args.sanitizers.split(",")
    if args.timeout:
        config.timeout_minutes = args.timeout
    if args.base_commit:
        config.base_commit = args.base_commit
    if args.delta_commit:
        config.delta_commit = args.delta_commit

    return config


# =============================================================================
# Shared Business Logic (placeholder)
# =============================================================================

def process_task(task: Task, config: Config):  # noqa: ARG001
    """
    Process a task - shared logic for all entry modes.

    This is the core business logic that:
    1. Parses and validates the workspace
    2. Starts static analysis
    3. Builds fuzzers
    4. Dispatches workers via Celery
    5. Monitors and collects results
    """
    print_info(f"Task ID: {task.task_id}")
    print_info(f"Task Type: {task.task_type.value}")
    print("")

    # TODO: Implement actual task processing
    # from .controller import Controller
    # controller = Controller(config)
    # result = controller.run(task)
    # return result

    print_step("Task execution pipeline:")
    print_info("1. Parse and validate workspace")
    print_info("2. Start static analysis server")
    print_info("3. Build fuzzers")
    print_info("4. Dispatch workers via Celery")
    print_info("5. Monitor and collect results")
    print("")

    print_warn("Task execution not yet implemented")

    return {
        "task_id": task.task_id,
        "status": "pending",
        "message": "Task created but execution not implemented",
    }


def create_task_from_config(config: Config) -> Task:
    """Create a Task object from Config"""
    import uuid
    task_id = config.task_id or str(uuid.uuid4())[:8]

    return Task(
        task_id=task_id,
        task_type=JobType(config.job_type),
        task_path=config.workspace,
        src_path=f"{config.workspace}/repo" if config.workspace else None,
        fuzz_tooling_path=f"{config.workspace}/fuzz-tooling" if config.workspace else None,
        diff_path=f"{config.workspace}/diff" if config.workspace and config.is_delta_scan else None,
        repo_url=config.repo_url,
        project_name=config.project_name,
        sanitizers=config.sanitizers,
        timeout_minutes=config.timeout_minutes,
        base_commit=config.base_commit,
        delta_commit=config.delta_commit,
        is_fuzz_tooling_provided=config.fuzz_tooling_path is not None,
    )


# =============================================================================
# Entry Mode: Server
# =============================================================================

def run_server(config: Config):
    """
    Start MCP server mode.

    Exposes FuzzingBrain as MCP tools for external AI systems.
    """
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

    from .server import run_server as start_mcp_server
    start_mcp_server(config)


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
    print_info(f"Job Type: {config.job_type}")
    print_info(f"Sanitizers: {', '.join(config.sanitizers)}")
    print_info(f"Timeout: {config.timeout_minutes} minutes")

    if config.repo_url:
        print_info(f"Repository: {config.repo_url}")
    if config.workspace:
        print_info(f"Workspace: {config.workspace}")
    if config.is_delta_scan:
        print_info(f"Delta Scan: {config.base_commit} -> {config.delta_commit or 'HEAD'}")

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
    print_info(f"Job Type: {config.job_type}")
    print_info(f"Sanitizers: {', '.join(config.sanitizers)}")
    print_info(f"Timeout: {config.timeout_minutes} minutes")

    if config.is_delta_scan:
        print_info(f"Delta Scan: {config.base_commit} -> {config.delta_commit or 'HEAD'}")

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

    if config.server_mode:
        # Mode 1: MCP Server
        run_server(config)
    elif args.config:
        # Mode 2: JSON Config
        run_json_mode(config)
    else:
        # Mode 3: Local Workspace
        run_local_mode(config)


if __name__ == "__main__":
    main()
