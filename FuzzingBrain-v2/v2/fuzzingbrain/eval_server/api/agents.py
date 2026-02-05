"""Agent tracking API routes."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class AgentData(BaseModel):
    """Agent registration data."""

    agent_id: str
    task_id: str = ""
    worker_id: str = ""
    instance_id: str = ""
    agent_type: str = ""
    status: str = "starting"
    started_at: Optional[str] = None
    iteration: int = 0


class AgentStatusUpdate(BaseModel):
    """Agent status update."""

    status: str
    iteration: Optional[int] = None


class AgentResponse(BaseModel):
    """Agent response."""

    agent_id: str
    task_id: str
    worker_id: str
    agent_type: str
    status: str
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    iteration: int = 0
    llm_calls: int = 0
    log_count: int = 0


@router.post("")
async def register_agent(data: AgentData) -> Dict[str, Any]:
    """Register a new agent."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage

    agent_data = {
        "agent_id": data.agent_id,
        "task_id": data.task_id,
        "worker_id": data.worker_id,
        "instance_id": data.instance_id,
        "agent_type": data.agent_type,
        "status": data.status,
        "started_at": datetime.fromisoformat(data.started_at)
        if data.started_at
        else datetime.utcnow(),
        "iteration": data.iteration,
        "created_at": datetime.utcnow(),
        "last_heartbeat": datetime.utcnow(),
    }
    await mongo.upsert_agent(agent_data)

    return {"success": True, "agent_id": data.agent_id}


@router.post("/{agent_id}/status")
async def update_agent_status(agent_id: str, data: AgentStatusUpdate) -> Dict[str, Any]:
    """Update agent status."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage
    await mongo.update_agent_status(agent_id, data.status, iteration=data.iteration)

    return {"success": True}


@router.post("/{agent_id}/end")
async def end_agent(agent_id: str, status: str = "completed") -> Dict[str, Any]:
    """Mark agent as ended."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage
    await mongo.end_agent(agent_id, status)

    return {"success": True}


@router.get("")
async def list_agents(
    task_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    status: Optional[str] = None,
) -> List[AgentResponse]:
    """List agents with optional filters."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage

    if task_id:
        agents = await mongo.get_agents_by_task(task_id)
    elif worker_id:
        agents = await mongo.get_agents_by_worker(worker_id)
    else:
        # Get all agents (limited query)
        agents = (
            await mongo._db.agents.find({})
            .sort("started_at", -1)
            .limit(100)
            .to_list(length=100)
        )

    result = []
    for agent in agents:
        # Get LLM call count for this agent
        llm_calls = await mongo.get_llm_calls(agent_id=agent["agent_id"], limit=1000)
        # Get log count for this agent
        logs = await mongo.get_agent_logs(agent["agent_id"], limit=1000)

        result.append(
            AgentResponse(
                agent_id=agent["agent_id"],
                task_id=agent.get("task_id", ""),
                worker_id=agent.get("worker_id", ""),
                agent_type=agent.get("agent_type", ""),
                status=agent.get("status", "unknown"),
                started_at=agent.get("started_at").isoformat()
                if agent.get("started_at")
                else None,
                ended_at=agent.get("ended_at").isoformat()
                if agent.get("ended_at")
                else None,
                iteration=agent.get("iteration", 0),
                llm_calls=len(llm_calls),
                log_count=len(logs),
            )
        )

    return result


@router.get("/{agent_id}")
async def get_agent(agent_id: str) -> Dict[str, Any]:
    """Get agent details with logs."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage

    agent = await mongo.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Get logs for this agent
    logs = await mongo.get_agent_logs(agent_id, limit=100)

    # Get LLM calls for this agent
    llm_calls = await mongo.get_llm_calls(agent_id=agent_id, limit=50)

    # Get cost summary for this agent
    cost_data = await mongo._db.llm_calls.aggregate(
        [
            {"$match": {"agent_id": agent_id}},
            {
                "$group": {
                    "_id": None,
                    "total_cost": {"$sum": "$cost_total"},
                    "total_calls": {"$sum": 1},
                    "total_tokens": {"$sum": "$total_tokens"},
                }
            },
        ]
    ).to_list(length=1)

    cost_summary = (
        cost_data[0]
        if cost_data
        else {"total_cost": 0, "total_calls": 0, "total_tokens": 0}
    )

    return {
        "agent": {
            "agent_id": agent["agent_id"],
            "task_id": agent.get("task_id", ""),
            "worker_id": agent.get("worker_id", ""),
            "agent_type": agent.get("agent_type", ""),
            "status": agent.get("status", "unknown"),
            "started_at": agent.get("started_at").isoformat()
            if agent.get("started_at")
            else None,
            "ended_at": agent.get("ended_at").isoformat()
            if agent.get("ended_at")
            else None,
            "iteration": agent.get("iteration", 0),
        },
        "costs": {
            "total_cost": cost_summary.get("total_cost", 0),
            "total_calls": cost_summary.get("total_calls", 0),
            "total_tokens": cost_summary.get("total_tokens", 0),
        },
        "logs": [
            {
                "log_id": log.get("log_id", ""),
                "role": log.get("role", ""),
                "content": log.get("content", "")[:500],
                "timestamp": log.get("timestamp").isoformat()
                if log.get("timestamp")
                else None,
            }
            for log in logs
        ],
        "llm_calls": [
            {
                "call_id": c.get("call_id", ""),
                "model": c.get("model", ""),
                "cost": c.get("cost_total", 0.0),
                "tokens": c.get("total_tokens", 0),
                "latency_ms": c.get("latency_ms", 0),
                "timestamp": c.get("timestamp").isoformat()
                if c.get("timestamp")
                else None,
            }
            for c in llm_calls
        ],
    }
