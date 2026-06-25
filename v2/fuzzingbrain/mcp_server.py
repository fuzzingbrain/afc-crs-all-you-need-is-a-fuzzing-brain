"""
FuzzingBrain MCP Server

Exposes FuzzingBrain as an MCP tool that can be called by other AI systems.
"""

from fastmcp import FastMCP
from typing import Optional, List, Dict

from .core import Config, Task, JobType, ScanMode


# Create MCP server instance
mcp = FastMCP("FuzzingBrain")


@mcp.tool()
async def fuzzingbrain_task(
    # Project info (required)
    repo_url: str,
    project_name: str,
    # Task configuration
    task_type: str = "pov",  # pov | patch | pov-patch | harness
    scan_mode: str = "full",  # full | delta
    # OSS-Fuzz project name (if different from project_name)
    ossfuzz_project_name: Optional[str] = None,
    # Commit configuration
    target_commit: Optional[str] = None,
    base_commit: Optional[str] = None,
    delta_commit: Optional[str] = None,
    # Fuzzing configuration
    fuzzer_filter: Optional[List[str]] = None,
    sanitizers: Optional[List[str]] = None,
    timeout_minutes: int = 30,
    pov_count: int = 1,
    # Fuzz tooling
    fuzz_tooling_url: Optional[str] = None,
    fuzz_tooling_ref: Optional[str] = None,
    # Fuzzer sources (name -> [paths])
    fuzzer_sources: Optional[Dict[str, List[str]]] = None,
    # Prebuild
    work_id: Optional[str] = None,
    prebuild_dir: Optional[str] = None,
    # Patch mode specific
    gen_blob: Optional[str] = None,
    input_blob: Optional[str] = None,
    # Harness mode specific
    targets: Optional[List[dict]] = None,
    # Runtime control
    budget_limit: float = 50.0,
) -> dict:
    """
    Run a FuzzingBrain task (unified endpoint).

    Supports all task types: pov, patch, pov-patch, harness.
    All parameters match the JSON configuration template.

    Args:
        repo_url: Git repository URL (required)
        project_name: Project name (required)
        task_type: Task type - pov, patch, pov-patch, or harness
        scan_mode: Scan mode - full or delta
        ossfuzz_project_name: OSS-Fuzz project name if different from project_name
        target_commit: Target commit for full scan
        base_commit: Base commit for delta scan
        delta_commit: Delta commit for delta scan
        fuzzer_filter: List of fuzzers to use (empty = all)
        sanitizers: List of sanitizers (default: ["address"])
        timeout_minutes: Timeout in minutes (default: 30)
        pov_count: Stop after N POVs (0 = unlimited, default: 1)
        fuzz_tooling_url: Custom fuzz-tooling repository URL
        fuzz_tooling_ref: Fuzz-tooling branch/tag
        fuzzer_sources: Dict mapping fuzzer_name -> list of source paths
        work_id: Work ID for prebuild data
        prebuild_dir: Path to prebuild data directory
        gen_blob: Generator blob for patch mode
        input_blob: Input blob (base64) for patch mode
        targets: Target functions for harness mode
        budget_limit: Budget limit in dollars (default: 50.0)

    Returns:
        dict with task_id for tracking and initial status
    """
    task = Task(
        task_type=JobType(task_type),
        scan_mode=ScanMode(scan_mode),
        repo_url=repo_url,
        project_name=project_name,
        ossfuzz_project_name=ossfuzz_project_name,
        sanitizers=sanitizers or ["address"],
        timeout_minutes=timeout_minutes,
        pov_count=pov_count,
        budget_limit=budget_limit,
        target_commit=target_commit,
        base_commit=base_commit,
        delta_commit=delta_commit,
        fuzz_tooling_url=fuzz_tooling_url,
        fuzz_tooling_ref=fuzz_tooling_ref,
    )

    # TODO: Start actual task processing
    # from .core.task_processor import TaskProcessor
    # processor = TaskProcessor(task, config)
    # asyncio.create_task(processor.run())

    return {
        "task_id": task.task_id,
        "task_type": task_type,
        "status": "pending",
        "message": f"{task_type} task started for {repo_url}",
    }


# Legacy tools for backward compatibility


@mcp.tool()
async def fuzzingbrain_find_pov(
    repo_url: str,
    project_name: Optional[str] = None,
    commit_id: Optional[str] = None,
    fuzz_tooling_url: Optional[str] = None,
    sanitizers: Optional[List[str]] = None,
    timeout_minutes: int = 30,
) -> dict:
    """
    Find proof-of-vulnerability (POV) in a repository.

    Scans the repository for vulnerabilities using fuzzing and returns
    any discovered POVs with their details.

    Args:
        repo_url: GitHub repository URL to scan
        commit_id: Optional specific commit to scan (default: HEAD)
        project_name: OSS-Fuzz project name (auto-detected if not provided)
        fuzz_tooling_url: Optional custom fuzz-tooling repository URL
        sanitizers: List of sanitizers to use (default: ["address"])
        timeout_minutes: Timeout for the scan in minutes (default: 60)

    Returns:
        dict with task_id for tracking and initial status
    """
    config = Config(
        repo_url=repo_url,
        commit_id=commit_id,
        project_name=project_name,
        fuzz_tooling_url=fuzz_tooling_url,
        sanitizers=sanitizers or ["address"],
        timeout_minutes=timeout_minutes,
        task_type="pov",
    )

    task = Task(
        task_type=JobType.POV,
        repo_url=repo_url,
        project_name=project_name,
        sanitizers=config.sanitizers,
        timeout_minutes=timeout_minutes,
    )

    # TODO: Start actual task processing
    # from .controller import Controller
    # controller = Controller(config)
    # asyncio.create_task(controller.run(task))

    return {
        "task_id": task.task_id,
        "status": "pending",
        "message": f"POV scan started for {repo_url}",
    }


@mcp.tool()
async def fuzzingbrain_generate_patch(
    pov_id: str,
    timeout_minutes: int = 60,
) -> dict:
    """
    Generate a patch for a discovered vulnerability.

    Takes a POV ID and attempts to generate a fix for the vulnerability.

    Args:
        pov_id: The ID of the POV to patch
        timeout_minutes: Timeout for patch generation in minutes

    Returns:
        dict with task_id for tracking and initial status
    """
    config = Config(
        task_type="patch",
        timeout_minutes=timeout_minutes,
    )

    task = Task(
        task_type=JobType.PATCH,
        timeout_minutes=timeout_minutes,
    )

    # TODO: Implement patch generation
    # from .controller import Controller
    # controller = Controller(config)
    # asyncio.create_task(controller.generate_patch(task, pov_id))

    return {
        "task_id": task.task_id,
        "pov_id": pov_id,
        "status": "pending",
        "message": f"Patch generation started for POV {pov_id}",
    }


@mcp.tool()
async def fuzzingbrain_pov_patch(
    repo_url: str,
    commit_id: Optional[str] = None,
    project_name: Optional[str] = None,
    fuzz_tooling_url: Optional[str] = None,
    sanitizers: Optional[List[str]] = None,
    timeout_minutes: int = 120,
) -> dict:
    """
    Find vulnerabilities and generate patches in one step.

    Combines POV finding and patch generation into a single workflow.

    Args:
        repo_url: GitHub repository URL to scan
        commit_id: Optional specific commit to scan
        project_name: OSS-Fuzz project name
        fuzz_tooling_url: Optional custom fuzz-tooling repository URL
        sanitizers: List of sanitizers to use
        timeout_minutes: Total timeout in minutes

    Returns:
        dict with task_id for tracking
    """
    config = Config(
        repo_url=repo_url,
        commit_id=commit_id,
        project_name=project_name,
        fuzz_tooling_url=fuzz_tooling_url,
        sanitizers=sanitizers or ["address"],
        timeout_minutes=timeout_minutes,
        task_type="pov-patch",
    )

    task = Task(
        task_type=JobType.POV_PATCH,
        repo_url=repo_url,
        project_name=project_name,
        sanitizers=config.sanitizers,
        timeout_minutes=timeout_minutes,
    )

    # TODO: Implement POV+Patch workflow

    return {
        "task_id": task.task_id,
        "status": "pending",
        "message": f"POV+Patch workflow started for {repo_url}",
    }


@mcp.tool()
async def fuzzingbrain_get_status(task_id: str) -> dict:
    """
    Get the status of a running or completed task.

    Args:
        task_id: The task ID returned from a previous call

    Returns:
        dict with current status, progress, and any results
    """
    # TODO: Query MongoDB for task status
    # from .db import get_task
    # task = await get_task(task_id)

    return {
        "task_id": task_id,
        "status": "unknown",
        "message": "Status tracking not yet implemented",
    }


@mcp.tool()
async def fuzzingbrain_generate_harness(
    repo_url: str,
    targets: List[dict],
    commit_id: Optional[str] = None,
    project_name: Optional[str] = None,
    timeout_minutes: int = 60,
) -> dict:
    """
    Generate fuzzing harnesses for specified functions.

    Creates new fuzz targets to improve code coverage.

    Args:
        repo_url: GitHub repository URL
        targets: List of target functions, each with:
            - function_name: Name of the function to fuzz
            - file_name: Source file containing the function
        commit_id: Optional specific commit
        project_name: OSS-Fuzz project name
        timeout_minutes: Timeout in minutes

    Returns:
        dict with task_id for tracking
    """
    config = Config(
        repo_url=repo_url,
        commit_id=commit_id,
        project_name=project_name,
        targets=targets,
        timeout_minutes=timeout_minutes,
        task_type="harness",
    )

    task = Task(
        task_type=JobType.HARNESS,
        repo_url=repo_url,
        project_name=project_name,
        timeout_minutes=timeout_minutes,
    )

    # TODO: Implement harness generation

    return {
        "task_id": task.task_id,
        "status": "pending",
        "message": f"Harness generation started for {len(targets)} targets",
    }


class MCPServer:
    """MCP Server wrapper"""

    def __init__(self, config: Config):
        self.config = config
        self.mcp = mcp

    def run(self):
        """Run the MCP server"""
        # FastMCP handles the server lifecycle
        mcp.run()


def run_server(config: Config):
    """Start the MCP server"""
    server = MCPServer(config)
    server.run()
