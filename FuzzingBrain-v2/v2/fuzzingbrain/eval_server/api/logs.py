"""Agent logs API routes."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class LogData(BaseModel):
    """Single log entry."""

    log_id: str
    agent_id: str
    timestamp: str
    role: str
    content: str = ""
    content_truncated: bool = False
    thinking: Optional[str] = None
    tool_calls: List[Dict[str, Any]] = []
    tool_call_id: Optional[str] = None
    tool_name: Optional[str] = None
    tool_success: Optional[bool] = None
    instance_id: str = ""
    task_id: str = ""
    worker_id: str = ""
    agent_type: str = ""
    iteration: int = 0
    tokens: int = 0
    cost: float = 0.0


class LogsBatch(BaseModel):
    """Batch of logs."""

    logs: List[LogData]


@router.post("")
async def receive_logs(batch: LogsBatch) -> Dict[str, Any]:
    """Receive batch of logs from FuzzingBrain instance."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, redis_store = storage

    # Convert to MongoDB format
    logs = []
    for log in batch.logs:
        logs.append(
            {
                "log_id": log.log_id,
                "agent_id": log.agent_id,
                "timestamp": datetime.fromisoformat(
                    log.timestamp.replace("Z", "+00:00")
                ),
                "role": log.role,
                "content": log.content,
                "content_truncated": log.content_truncated,
                "thinking": log.thinking,
                "tool_calls": log.tool_calls,
                "tool_call_id": log.tool_call_id,
                "tool_name": log.tool_name,
                "tool_success": log.tool_success,
                "instance_id": log.instance_id,
                "task_id": log.task_id,
                "worker_id": log.worker_id,
                "agent_type": log.agent_type,
                "iteration": log.iteration,
                "tokens": log.tokens,
                "cost": log.cost,
            }
        )

    # Store in MongoDB
    await mongo.insert_logs(logs)

    # Publish to Redis for real-time subscribers
    if redis_store:
        for log in batch.logs:
            await redis_store.publish_log(log.agent_id, log.model_dump())

    return {"success": True, "count": len(batch.logs)}


@router.get("/agent/{agent_id}")
async def get_agent_logs(
    agent_id: str,
    limit: int = 1000,
) -> List[Dict[str, Any]]:
    """Get logs for an agent."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage
    logs = await mongo.get_agent_logs(agent_id=agent_id, limit=limit)

    # Convert datetime to string
    for log in logs:
        if isinstance(log.get("timestamp"), datetime):
            log["timestamp"] = log["timestamp"].isoformat()
        log.pop("_id", None)

    return logs


@router.get("/task/{task_id}")
async def get_task_logs(
    task_id: str,
    limit: int = 5000,
) -> List[Dict[str, Any]]:
    """Get all logs for a task."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage
    logs = await mongo.get_task_logs(task_id=task_id, limit=limit)

    # Convert datetime to string
    for log in logs:
        if isinstance(log.get("timestamp"), datetime):
            log["timestamp"] = log["timestamp"].isoformat()
        log.pop("_id", None)

    return logs


@router.get("/search")
async def search_logs(
    q: str,
    task_id: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Search logs by content."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage
    logs = await mongo.search_logs(query_text=q, task_id=task_id, limit=limit)

    # Convert datetime to string
    for log in logs:
        if isinstance(log.get("timestamp"), datetime):
            log["timestamp"] = log["timestamp"].isoformat()
        log.pop("_id", None)

    return logs
