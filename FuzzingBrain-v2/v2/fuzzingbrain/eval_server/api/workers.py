"""Worker tracking API routes."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class WorkerData(BaseModel):
    """Worker registration data."""
    worker_id: str
    task_id: str
    instance_id: str = ""
    fuzzer: str = ""
    sanitizer: str = ""
    status: str = "starting"
    started_at: Optional[str] = None
    cpu_percent: Optional[float] = None
    memory_mb: Optional[float] = None


class WorkerStatusUpdate(BaseModel):
    """Worker status update."""
    status: str
    cpu_percent: Optional[float] = None
    memory_mb: Optional[float] = None


class WorkerResponse(BaseModel):
    """Worker response."""
    worker_id: str
    task_id: str
    fuzzer: str
    sanitizer: str
    status: str
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    cpu_percent: Optional[float] = None
    memory_mb: Optional[float] = None
    agent_count: int = 0


@router.post("")
async def register_worker(data: WorkerData) -> Dict[str, Any]:
    """Register a new worker."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage

    worker_data = {
        "worker_id": data.worker_id,
        "task_id": data.task_id,
        "instance_id": data.instance_id,
        "fuzzer": data.fuzzer,
        "sanitizer": data.sanitizer,
        "status": data.status,
        "started_at": datetime.fromisoformat(data.started_at) if data.started_at else datetime.utcnow(),
        "cpu_percent": data.cpu_percent,
        "memory_mb": data.memory_mb,
        "created_at": datetime.utcnow(),
        "last_heartbeat": datetime.utcnow(),
    }
    await mongo.upsert_worker(worker_data)

    return {"success": True, "worker_id": data.worker_id}


@router.post("/{worker_id}/status")
async def update_worker_status(worker_id: str, data: WorkerStatusUpdate) -> Dict[str, Any]:
    """Update worker status."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage
    await mongo.update_worker_status(
        worker_id,
        data.status,
        cpu_percent=data.cpu_percent,
        memory_mb=data.memory_mb,
    )

    return {"success": True}


@router.post("/{worker_id}/end")
async def end_worker(worker_id: str, status: str = "completed") -> Dict[str, Any]:
    """Mark worker as ended."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage
    await mongo.end_worker(worker_id, status)

    return {"success": True}


@router.get("")
async def list_workers(
    task_id: Optional[str] = None,
    status: Optional[str] = None,
) -> List[WorkerResponse]:
    """List workers with optional filters."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage

    if task_id:
        workers = await mongo.get_workers_by_task(task_id)
    else:
        # Get all workers (limited query)
        workers = await mongo._db.workers.find({}).sort("started_at", -1).limit(100).to_list(length=100)

    result = []
    for worker in workers:
        # Get agent count for this worker
        agents = await mongo.get_agents_by_worker(worker["worker_id"])

        result.append(WorkerResponse(
            worker_id=worker["worker_id"],
            task_id=worker.get("task_id", ""),
            fuzzer=worker.get("fuzzer", ""),
            sanitizer=worker.get("sanitizer", ""),
            status=worker.get("status", "unknown"),
            started_at=worker.get("started_at").isoformat() if worker.get("started_at") else None,
            ended_at=worker.get("ended_at").isoformat() if worker.get("ended_at") else None,
            cpu_percent=worker.get("cpu_percent"),
            memory_mb=worker.get("memory_mb"),
            agent_count=len(agents),
        ))

    return result


@router.get("/{worker_id}")
async def get_worker(worker_id: str) -> Dict[str, Any]:
    """Get worker details with agents."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage

    worker = await mongo.get_worker(worker_id)
    if not worker:
        raise HTTPException(status_code=404, detail="Worker not found")

    # Get agents for this worker
    agents = await mongo.get_agents_by_worker(worker_id)

    return {
        "worker": {
            "worker_id": worker["worker_id"],
            "task_id": worker.get("task_id", ""),
            "fuzzer": worker.get("fuzzer", ""),
            "sanitizer": worker.get("sanitizer", ""),
            "status": worker.get("status", "unknown"),
            "started_at": worker.get("started_at").isoformat() if worker.get("started_at") else None,
            "ended_at": worker.get("ended_at").isoformat() if worker.get("ended_at") else None,
            "cpu_percent": worker.get("cpu_percent"),
            "memory_mb": worker.get("memory_mb"),
        },
        "agents": [
            {
                "agent_id": a.get("agent_id", ""),
                "agent_type": a.get("agent_type", ""),
                "status": a.get("status", "unknown"),
                "started_at": a.get("started_at").isoformat() if a.get("started_at") else None,
                "ended_at": a.get("ended_at").isoformat() if a.get("ended_at") else None,
            }
            for a in agents
        ],
    }
