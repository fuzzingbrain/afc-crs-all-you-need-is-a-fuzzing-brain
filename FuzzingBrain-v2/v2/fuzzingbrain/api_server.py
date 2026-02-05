"""
FuzzingBrain REST API

Provides REST API endpoints alongside the MCP server.
Both share the same business logic.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
import uuid

from .core import Task, JobType, ScanMode
from .db import RepositoryManager


def get_repos() -> RepositoryManager:
    """Get global RepositoryManager instance"""
    from .main import get_repos as main_get_repos, init_database
    from .core import Config

    try:
        return main_get_repos()
    except RuntimeError:
        # Database not initialized yet, initialize it now
        config = Config.from_env()
        return init_database(config)


# =============================================================================
# Pydantic Models (Request/Response)
# =============================================================================


class HarnessTarget(BaseModel):
    """Target function for harness generation"""

    function: str
    description: Optional[str] = None
    file_name: Optional[str] = None


class TaskRequest(BaseModel):
    """
    Unified request model for all task types.

    All fields match the JSON configuration template.
    """

    # Project info (required)
    repo_url: str
    project_name: str
    ossfuzz_project_name: Optional[str] = None

    # Task configuration
    task_type: str = "pov"  # pov | patch | pov-patch | harness
    scan_mode: str = "full"  # full | delta

    # Commit configuration
    target_commit: Optional[str] = None
    base_commit: Optional[str] = None
    delta_commit: Optional[str] = None

    # Fuzzing configuration
    fuzzer_filter: List[str] = []
    sanitizers: List[str] = ["address"]
    timeout_minutes: int = 30
    pov_count: int = 1

    # Fuzz tooling
    fuzz_tooling_url: Optional[str] = None
    fuzz_tooling_ref: Optional[str] = None

    # Fuzzer sources (name -> [paths])
    fuzzer_sources: Optional[dict] = None

    # Prebuild
    work_id: Optional[str] = None
    prebuild_dir: Optional[str] = None

    # Patch mode specific
    gen_blob: Optional[str] = None
    input_blob: Optional[str] = None

    # Harness mode specific
    targets: Optional[List[HarnessTarget]] = None

    # Runtime control
    budget_limit: float = 50.0
    eval_server: Optional[str] = None


# Legacy request models (for backward compatibility)
class POVRequest(TaskRequest):
    """Request model for POV finding (legacy, use TaskRequest)"""

    task_type: str = "pov"


class PatchRequest(BaseModel):
    """Request model for patch generation from existing POV"""

    pov_id: str
    timeout_minutes: int = 30
    budget_limit: float = 50.0


class POVPatchRequest(TaskRequest):
    """Request model for POV + Patch combo (legacy, use TaskRequest)"""

    task_type: str = "pov-patch"


class HarnessRequest(TaskRequest):
    """Request model for harness generation (legacy, use TaskRequest)"""

    task_type: str = "harness"
    targets: List[HarnessTarget] = []


class TaskResponse(BaseModel):
    """Standard response with task ID"""

    task_id: str
    status: str
    message: str


class StatusResponse(BaseModel):
    """Task status response"""

    task_id: str
    status: str
    task_type: Optional[str] = None
    progress: Optional[dict] = None
    povs: Optional[List[dict]] = None
    patches: Optional[List[dict]] = None
    error: Optional[str] = None


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title="FuzzingBrain API",
    description="Autonomous Cyber Reasoning System - REST API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


# =============================================================================
# Shared Business Logic (placeholder)
# =============================================================================


async def start_pov_task(task: Task):
    """Start POV finding task - placeholder"""
    # TODO: Implement actual task processing
    # from .controller import Controller
    # controller = Controller()
    # await controller.run_pov(task)
    pass


async def start_patch_task(task: Task, pov_id: str):
    """Start patch generation task - placeholder"""
    pass


async def start_pov_patch_task(task: Task):
    """Start POV+Patch task - placeholder"""
    pass


async def start_harness_task(task: Task, targets: List[dict]):
    """Start harness generation task - placeholder"""
    pass


# =============================================================================
# API Endpoints
# =============================================================================


@app.get("/")
async def root():
    """API root - health check"""
    return {
        "service": "FuzzingBrain",
        "version": "2.0.0",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


# -----------------------------------------------------------------------------
# Unified Task Endpoint
# -----------------------------------------------------------------------------


def create_task_from_request(request: TaskRequest) -> Task:
    """Create Task from unified TaskRequest"""
    return Task(
        task_id=str(uuid.uuid4())[:8],
        task_type=JobType(request.task_type),
        scan_mode=ScanMode(request.scan_mode),
        repo_url=request.repo_url,
        project_name=request.project_name,
        sanitizers=request.sanitizers,
        timeout_minutes=request.timeout_minutes,
        base_commit=request.base_commit,
        delta_commit=request.delta_commit,
    )


@app.post("/api/v1/task", response_model=TaskResponse)
async def create_task(request: TaskRequest, background_tasks: BackgroundTasks):
    """
    Create a new FuzzingBrain task (unified endpoint).

    Accepts all task types: pov, patch, pov-patch, harness.
    All fields match the JSON configuration template.
    """
    task = create_task_from_request(request)

    # Route to appropriate handler based on task_type
    if request.task_type == "pov":
        background_tasks.add_task(start_pov_task, task)
    elif request.task_type == "patch":
        background_tasks.add_task(start_pov_patch_task, task)  # patch from scratch
    elif request.task_type == "pov-patch":
        background_tasks.add_task(start_pov_patch_task, task)
    elif request.task_type == "harness":
        targets = [t.model_dump() for t in request.targets] if request.targets else []
        background_tasks.add_task(start_harness_task, task, targets)

    return TaskResponse(
        task_id=task.task_id,
        status="pending",
        message=f"{request.task_type} task started for {request.repo_url}",
    )


# -----------------------------------------------------------------------------
# Legacy POV Endpoints (for backward compatibility)
# -----------------------------------------------------------------------------


@app.post("/api/v1/pov", response_model=TaskResponse)
async def find_pov(request: POVRequest, background_tasks: BackgroundTasks):
    """
    Start a POV (proof-of-vulnerability) finding task.

    Scans the repository for vulnerabilities using fuzzing.
    Returns a task_id for tracking progress.
    """
    task = create_task_from_request(request)

    # Start task in background
    background_tasks.add_task(start_pov_task, task)

    return TaskResponse(
        task_id=task.task_id,
        status="pending",
        message=f"POV scan started for {request.repo_url}",
    )


# -----------------------------------------------------------------------------
# Patch Endpoints
# -----------------------------------------------------------------------------


@app.post("/api/v1/patch", response_model=TaskResponse)
async def generate_patch(request: PatchRequest, background_tasks: BackgroundTasks):
    """
    Generate a patch for a discovered vulnerability.

    Takes a POV ID and attempts to generate a fix.
    """
    task = Task(
        task_id=str(uuid.uuid4())[:8],
        task_type=JobType.PATCH,
        timeout_minutes=request.timeout_minutes,
    )

    # Start task in background
    background_tasks.add_task(start_patch_task, task, request.pov_id)

    return TaskResponse(
        task_id=task.task_id,
        status="pending",
        message=f"Patch generation started for POV {request.pov_id}",
    )


# -----------------------------------------------------------------------------
# POV + Patch Combo
# -----------------------------------------------------------------------------


@app.post("/api/v1/pov-patch", response_model=TaskResponse)
async def pov_patch(request: POVPatchRequest, background_tasks: BackgroundTasks):
    """
    Find vulnerabilities and generate patches in one workflow.

    Combines POV finding and patch generation.
    """
    task = Task(
        task_id=str(uuid.uuid4())[:8],
        task_type=JobType.POV_PATCH,
        scan_mode=ScanMode.FULL,
        repo_url=request.repo_url,
        project_name=request.project_name,
        sanitizers=request.sanitizers,
        timeout_minutes=request.timeout_minutes,
    )

    # Start task in background
    background_tasks.add_task(start_pov_patch_task, task)

    return TaskResponse(
        task_id=task.task_id,
        status="pending",
        message=f"POV+Patch workflow started for {request.repo_url}",
    )


# -----------------------------------------------------------------------------
# Harness Generation
# -----------------------------------------------------------------------------


@app.post("/api/v1/harness", response_model=TaskResponse)
async def generate_harness(request: HarnessRequest, background_tasks: BackgroundTasks):
    """
    Generate fuzzing harnesses for specified functions.

    Creates new fuzz targets to improve code coverage.
    """
    task = Task(
        task_id=str(uuid.uuid4())[:8],
        task_type=JobType.HARNESS,
        repo_url=request.repo_url,
        project_name=request.project_name,
        timeout_minutes=request.timeout_minutes,
    )

    targets = [t.model_dump() for t in request.targets]

    # Start task in background
    background_tasks.add_task(start_harness_task, task, targets)

    return TaskResponse(
        task_id=task.task_id,
        status="pending",
        message=f"Harness generation started for {len(targets)} targets",
    )


# -----------------------------------------------------------------------------
# Status Query
# -----------------------------------------------------------------------------


@app.get("/api/v1/status/{task_id}", response_model=StatusResponse)
async def get_status(task_id: str):
    """
    Get the status of a task.

    Returns current status, progress, and any results.
    """
    repos = get_repos()
    task = repos.tasks.find_by_id(task_id)

    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")

    # Get related POVs and Patches
    povs = repos.povs.find_by_task(task_id)
    patches = repos.patches.find_by_task(task_id)
    workers = repos.workers.find_by_task(task_id)

    return StatusResponse(
        task_id=task_id,
        status=task.status.value,
        task_type=task.task_type.value,
        progress={
            "workers_total": len(workers),
            "workers_running": len([w for w in workers if w.status.value == "running"]),
            "workers_completed": len(
                [w for w in workers if w.status.value == "completed"]
            ),
            "povs_found": len(povs),
            "patches_found": len(patches),
        },
        povs=[p.to_dict() for p in povs[:10]],  # Return max 10
        patches=[p.to_dict() for p in patches[:10]],
        error=task.error_msg,
    )


@app.get("/api/v1/tasks")
async def list_tasks(
    status: Optional[str] = None,
    task_type: Optional[str] = None,
    limit: int = 20,
):
    """
    List all tasks, optionally filtered by status or type.
    """
    repos = get_repos()

    # Build query conditions
    query = {}
    if status:
        query["status"] = status
    if task_type:
        query["task_type"] = task_type

    tasks = repos.tasks.find_all(query, limit=limit)

    return {
        "tasks": [t.to_dict() for t in tasks],
        "total": len(tasks),
    }


# -----------------------------------------------------------------------------
# Results
# -----------------------------------------------------------------------------


@app.get("/api/v1/pov/{task_id}")
async def get_povs(task_id: str, active_only: bool = True):
    """Get all POVs found for a task"""
    repos = get_repos()

    # Check if task exists
    task = repos.tasks.find_by_id(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")

    if active_only:
        povs = repos.povs.find_active_by_task(task_id)
    else:
        povs = repos.povs.find_by_task(task_id)

    return {
        "task_id": task_id,
        "povs": [p.to_dict() for p in povs],
        "total": len(povs),
    }


@app.get("/api/v1/patch/{task_id}")
async def get_patches(task_id: str, valid_only: bool = False):
    """Get all patches generated for a task"""
    repos = get_repos()

    # Check if task exists
    task = repos.tasks.find_by_id(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")

    if valid_only:
        patches = repos.patches.find_valid_by_task(task_id)
    else:
        patches = repos.patches.find_by_task(task_id)

    return {
        "task_id": task_id,
        "patches": [p.to_dict() for p in patches],
        "total": len(patches),
    }


# =============================================================================
# Server Runner
# =============================================================================


def check_port_in_use(port: int) -> tuple[bool, int]:
    """
    Check if a port is in use.

    Returns:
        (is_in_use, pid) - pid is 0 if not in use or can't determine
    """
    import subprocess

    try:
        result = subprocess.run(
            ["lsof", "-i", f":{port}", "-t"], capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            pid = int(result.stdout.strip().split("\n")[0])
            return True, pid
    except Exception:
        pass
    return False, 0


def run_api_server(host: str = "0.0.0.0", port: int = 18080):
    """Run the FastAPI server"""
    import uvicorn
    import os
    import signal

    # Check if port is in use
    in_use, pid = check_port_in_use(port)
    if in_use:
        print(f"\n[WARN] Port {port} is already in use by process {pid}")
        response = input("Kill the process and continue? [y/N]: ").strip().lower()

        if response == "y":
            try:
                os.kill(pid, signal.SIGTERM)
                print(f"[INFO] Killed process {pid}")
                import time

                time.sleep(1)  # Wait for port to be released
            except ProcessLookupError:
                print(f"[INFO] Process {pid} already terminated")
            except PermissionError:
                print(f"[ERROR] No permission to kill process {pid}")
                return
        else:
            print("[INFO] Exiting...")
            return

    uvicorn.run(app, host=host, port=port)
