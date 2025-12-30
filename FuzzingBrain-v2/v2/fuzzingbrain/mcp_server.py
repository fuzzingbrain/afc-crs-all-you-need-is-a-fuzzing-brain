"""
FuzzingBrain MCP Server

Exposes FuzzingBrain as an MCP tool that can be called by other AI systems.
"""

from fastmcp import FastMCP
from typing import Optional, List
import asyncio

from .core import Config, Task, JobType, TaskStatus


# Create MCP server instance
mcp = FastMCP("FuzzingBrain")


@mcp.tool()
async def fuzzingbrain_find_pov(
    repo_url: str,
    commit_id: Optional[str] = None,
    project_name: Optional[str] = None,
    fuzz_tooling_url: Optional[str] = None,
    sanitizers: Optional[List[str]] = None,
    timeout_minutes: int = 60,
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
