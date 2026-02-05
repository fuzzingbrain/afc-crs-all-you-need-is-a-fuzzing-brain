"""Task tracking API routes."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class TaskData(BaseModel):
    """Task data from FuzzingBrain."""

    task_id: str
    instance_id: str = ""
    project_name: str = ""
    status: str = "running"
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    config: Dict[str, Any] = {}


class TaskResponse(BaseModel):
    """Task response."""

    task_id: str
    instance_id: str
    project_name: str
    status: str
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    cost_total: float = 0.0
    llm_calls: int = 0
    tool_calls: int = 0
    worker_count: int = 0
    agent_count: int = 0


@router.post("")
async def register_task(data: TaskData) -> Dict[str, Any]:
    """Register a new task."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, redis_store = storage

    task_data = {
        "task_id": data.task_id,
        "instance_id": data.instance_id,
        "project_name": data.project_name,
        "status": data.status,
        "started_at": datetime.fromisoformat(data.started_at)
        if data.started_at
        else datetime.utcnow(),
        "ended_at": datetime.fromisoformat(data.ended_at) if data.ended_at else None,
        "config": data.config,
        "created_at": datetime.utcnow(),
    }
    await mongo.upsert_task(task_data)

    return {"success": True, "task_id": data.task_id}


@router.post("/{task_id}/end")
async def end_task(task_id: str, status: str = "completed") -> Dict[str, Any]:
    """Mark task as ended."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage

    task = await mongo.get_task(task_id)
    if task:
        task["status"] = status
        task["ended_at"] = datetime.utcnow()
        await mongo.upsert_task(task)

    return {"success": True}


@router.get("")
async def list_tasks(
    status: Optional[str] = None,
    limit: int = 100,
) -> List[TaskResponse]:
    """List all tasks."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, redis_store = storage
    tasks = await mongo.get_tasks(status=status, limit=limit)

    result = []
    for task in tasks:
        # Get cost data for this task
        cost_data = await mongo.get_cost_summary(task_id=task["task_id"])

        # Get worker and agent counts
        workers = await mongo.get_workers_by_task(task["task_id"])
        agents = await mongo.get_agents_by_task(task["task_id"])

        result.append(
            TaskResponse(
                task_id=task["task_id"],
                instance_id=task.get("instance_id", ""),
                project_name=task.get("project_name", ""),
                status=task.get("status", "unknown"),
                started_at=task.get("started_at").isoformat()
                if task.get("started_at")
                else None,
                ended_at=task.get("ended_at").isoformat()
                if task.get("ended_at")
                else None,
                cost_total=cost_data.get("total_cost", 0.0),
                llm_calls=cost_data.get("total_calls", 0),
                tool_calls=0,  # TODO: add tool call count
                worker_count=len(workers),
                agent_count=len(agents),
            )
        )

    return result


@router.get("/{task_id}")
async def get_task(task_id: str) -> Dict[str, Any]:
    """Get task details with all associated data."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage

    task = await mongo.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # Get cost summary
    cost_summary = await mongo.get_cost_summary(task_id=task_id)

    # Get cost by model
    cost_by_model = await mongo.get_cost_by_model(task_id=task_id)

    # Get tool summary
    tool_summary = await mongo.get_tool_summary(task_id=task_id)

    # Get workers for this task
    workers = await mongo.get_workers_by_task(task_id)

    # Get agents for this task
    agents = await mongo.get_agents_by_task(task_id)

    # Get max iteration per agent from LLM calls
    agent_iterations = await mongo.get_agent_max_iterations(task_id)

    # Get recent LLM calls
    llm_calls = await mongo.get_llm_calls(task_id=task_id, limit=50)

    # Get recent logs
    logs = await mongo.get_task_logs(task_id=task_id, limit=100)

    # Get workflow statistics
    sp_stats = await mongo.get_sp_workflow_stats(task_id)
    direction_stats = await mongo.get_direction_workflow_stats(task_id)
    pov_stats = await mongo.get_pov_workflow_stats(task_id)

    return {
        "task": {
            "task_id": task["task_id"],
            "instance_id": task.get("instance_id", ""),
            "project_name": task.get("project_name", ""),
            "status": task.get("status", "unknown"),
            "started_at": task.get("started_at").isoformat()
            if task.get("started_at")
            else None,
            "ended_at": task.get("ended_at").isoformat()
            if task.get("ended_at")
            else None,
            "config": task.get("config", {}),
        },
        "costs": {
            "total_cost": cost_summary.get("total_cost", 0.0),
            "total_llm_calls": cost_summary.get("total_calls", 0),
            "total_input_tokens": cost_summary.get("total_input_tokens", 0),
            "total_output_tokens": cost_summary.get("total_output_tokens", 0),
            "by_model": [
                {
                    "model": m.get("_id", "unknown"),
                    "cost": m.get("total_cost", 0.0),
                    "calls": m.get("total_calls", 0),
                }
                for m in cost_by_model
            ],
        },
        "workers": [
            {
                "worker_id": w.get("worker_id", ""),
                "fuzzer": w.get("fuzzer", ""),
                "sanitizer": w.get("sanitizer", ""),
                "status": w.get("status", "unknown"),
                "started_at": w.get("started_at").isoformat()
                if w.get("started_at")
                else None,
                "ended_at": w.get("ended_at").isoformat()
                if w.get("ended_at")
                else None,
                "cpu_percent": w.get("cpu_percent"),
                "memory_mb": w.get("memory_mb"),
            }
            for w in workers
        ],
        "agents": [
            {
                "agent_id": a.get("agent_id", ""),
                "worker_id": a.get("worker_id", ""),
                "agent_type": a.get("agent_type", ""),
                "status": a.get("status", "unknown"),
                "started_at": a.get("started_at").isoformat()
                if a.get("started_at")
                else None,
                "ended_at": a.get("ended_at").isoformat()
                if a.get("ended_at")
                else None,
                "iteration": a.get("iteration", 0),
                "max_iteration": agent_iterations.get(a.get("agent_id", ""), 0),
            }
            for a in agents
        ],
        "tools": [
            {
                "name": t.get("_id", "unknown"),
                "calls": t.get("total_calls", 0),
                "success": t.get("success_count", 0),
                "failure": t.get("failure_count", 0),
            }
            for t in tool_summary
        ],
        "llm_calls": [
            {
                "call_id": c.get("call_id", ""),
                "model": c.get("model", ""),
                "operation": c.get("operation", ""),
                "cost": c.get("cost_total", 0.0),
                "tokens": c.get("total_tokens", 0),
                "latency_ms": c.get("latency_ms", 0),
                "timestamp": c.get("timestamp").isoformat()
                if c.get("timestamp")
                else None,
            }
            for c in llm_calls
        ],
        "logs": [
            {
                "log_id": log.get("log_id", ""),
                "role": log.get("role", ""),
                "content": log.get("content", "")[:500],  # Truncate
                "timestamp": log.get("timestamp").isoformat()
                if log.get("timestamp")
                else None,
            }
            for log in logs
        ],
        "workflow": {
            "sp": sp_stats,
            "direction": direction_stats,
            "pov": pov_stats,
        },
    }
