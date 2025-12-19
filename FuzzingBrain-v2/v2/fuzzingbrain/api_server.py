"""
FuzzingBrain REST API

Provides REST API endpoints alongside the MCP server.
Both share the same business logic.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
import uuid

from .core import Task, JobType, ScanMode, TaskStatus
from .db import RepositoryManager


def get_repos() -> RepositoryManager:
    """Get global RepositoryManager instance"""
    from .main import get_repos as main_get_repos
    return main_get_repos()


# =============================================================================
# Pydantic Models (Request/Response)
# =============================================================================

class POVRequest(BaseModel):
    """Request model for POV finding"""
    repo_url: str
    commit_id: Optional[str] = None
    project_name: Optional[str] = None
    fuzz_tooling_url: Optional[str] = None
    sanitizers: List[str] = ["address"]
    timeout_minutes: int = 60


class PatchRequest(BaseModel):
    """Request model for patch generation"""
    pov_id: str
    timeout_minutes: int = 60


class POVPatchRequest(BaseModel):
    """Request model for POV + Patch combo"""
    repo_url: str
    commit_id: Optional[str] = None
    project_name: Optional[str] = None
    fuzz_tooling_url: Optional[str] = None
    sanitizers: List[str] = ["address"]
    timeout_minutes: int = 120


class HarnessTarget(BaseModel):
    """Target function for harness generation"""
    function: str
    description: Optional[str] = None
    file_name: Optional[str] = None


class HarnessRequest(BaseModel):
    """Request model for harness generation"""
    repo_url: str
    targets: List[HarnessTarget]
    commit_id: Optional[str] = None
    project_name: Optional[str] = None
    timeout_minutes: int = 60


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
# POV Endpoints
# -----------------------------------------------------------------------------

@app.post("/api/v1/pov", response_model=TaskResponse)
async def find_pov(request: POVRequest, background_tasks: BackgroundTasks):
    """
    Start a POV (proof-of-vulnerability) finding task.

    Scans the repository for vulnerabilities using fuzzing.
    Returns a task_id for tracking progress.
    """
    task = Task(
        task_id=str(uuid.uuid4())[:8],
        task_type=JobType.POV,
        scan_mode=ScanMode.FULL,
        repo_url=request.repo_url,
        project_name=request.project_name,
        sanitizers=request.sanitizers,
        timeout_minutes=request.timeout_minutes,
    )

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
            "workers_completed": len([w for w in workers if w.status.value == "completed"]),
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

def run_api_server(host: str = "0.0.0.0", port: int = 8080):
    """Run the FastAPI server"""
    import uvicorn
    uvicorn.run(app, host=host, port=port)
