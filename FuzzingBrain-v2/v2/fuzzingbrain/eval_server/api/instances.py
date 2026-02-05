"""Instance management API routes."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class InstanceRegister(BaseModel):
    """Instance registration request."""

    instance_id: str
    host: str
    pid: int
    version: str
    config: Dict[str, Any] = {}


class HeartbeatData(BaseModel):
    """Heartbeat request."""

    status: str = "running"
    tasks_running: int = 0
    agents_running: int = 0
    cpu_percent: float = 0.0
    memory_gb: float = 0.0
    cost_total: float = 0.0


class InstanceResponse(BaseModel):
    """Instance response."""

    instance_id: str
    host: str
    status: str
    started_at: Optional[str] = None
    last_heartbeat: Optional[str] = None
    tasks_running: int = 0
    cost_total: float = 0.0


@router.post("/register")
async def register_instance(data: InstanceRegister) -> Dict[str, Any]:
    """Register a new FuzzingBrain instance."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, redis_store = storage

    # Store in MongoDB
    instance_data = {
        "instance_id": data.instance_id,
        "host": data.host,
        "pid": data.pid,
        "version": data.version,
        "config": data.config,
        "status": "running",
        "started_at": datetime.utcnow(),
        "last_heartbeat": datetime.utcnow(),
    }
    await mongo.upsert_instance(instance_data)

    # Update Redis
    if redis_store:
        await redis_store.set_instance_status(data.instance_id, "running")
        await redis_store.set_instance_heartbeat(data.instance_id)

    return {"success": True, "instance_id": data.instance_id}


@router.post("/{instance_id}/heartbeat")
async def heartbeat(instance_id: str, data: HeartbeatData) -> Dict[str, Any]:
    """Update instance heartbeat."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, redis_store = storage

    # Update MongoDB
    await mongo.update_heartbeat(
        instance_id,
        {
            "status": data.status,
            "tasks_running": data.tasks_running,
            "agents_running": data.agents_running,
            "cpu_percent": data.cpu_percent,
            "memory_gb": data.memory_gb,
            "cost_total": data.cost_total,
        },
    )

    # Update Redis
    if redis_store:
        await redis_store.set_instance_heartbeat(instance_id)
        await redis_store.set_instance_status(
            instance_id,
            data.status,
            {
                "tasks_running": data.tasks_running,
                "cost_total": data.cost_total,
            },
        )

    return {"success": True}


@router.get("/")
async def list_instances(include_dead: bool = False) -> List[InstanceResponse]:
    """List all instances."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage
    instances = await mongo.get_all_instances(include_dead=include_dead)

    return [
        InstanceResponse(
            instance_id=inst["instance_id"],
            host=inst.get("host", ""),
            status=inst.get("status", "unknown"),
            started_at=inst.get("started_at", "").isoformat()
            if inst.get("started_at")
            else None,
            last_heartbeat=inst.get("last_heartbeat", "").isoformat()
            if inst.get("last_heartbeat")
            else None,
            tasks_running=inst.get("tasks_running", 0),
            cost_total=inst.get("cost_total", 0.0),
        )
        for inst in instances
    ]


@router.get("/{instance_id}")
async def get_instance(instance_id: str) -> InstanceResponse:
    """Get instance details."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage
    inst = await mongo.get_instance(instance_id)

    if not inst:
        raise HTTPException(status_code=404, detail="Instance not found")

    return InstanceResponse(
        instance_id=inst["instance_id"],
        host=inst.get("host", ""),
        status=inst.get("status", "unknown"),
        started_at=inst.get("started_at", "").isoformat()
        if inst.get("started_at")
        else None,
        last_heartbeat=inst.get("last_heartbeat", "").isoformat()
        if inst.get("last_heartbeat")
        else None,
        tasks_running=inst.get("tasks_running", 0),
        cost_total=inst.get("cost_total", 0.0),
    )
