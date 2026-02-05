"""Cost tracking API routes."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class LLMCallData(BaseModel):
    """Single LLM call data."""

    call_id: str
    timestamp: str
    model: str
    provider: str
    fallback_used: bool = False
    original_model: Optional[str] = None
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_input: float = 0.0
    cost_output: float = 0.0
    cost_total: float = 0.0
    latency_ms: int = 0
    instance_id: str = ""
    task_id: str = ""
    worker_id: str = ""
    agent_id: str = ""
    agent_type: str = ""
    operation: str = ""
    iteration: int = 0


class LLMCallsBatch(BaseModel):
    """Batch of LLM calls."""

    calls: List[LLMCallData]


class ToolCallData(BaseModel):
    """Single tool call data."""

    call_id: str
    timestamp: str
    tool_name: str
    tool_category: str = ""
    arguments_summary: str = ""
    success: bool = True
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    result_size_bytes: int = 0
    latency_ms: int = 0
    instance_id: str = ""
    task_id: str = ""
    worker_id: str = ""
    agent_id: str = ""
    agent_type: str = ""
    iteration: int = 0


class ToolCallsBatch(BaseModel):
    """Batch of tool calls."""

    calls: List[ToolCallData]


@router.post("/llm_calls")
async def receive_llm_calls(batch: LLMCallsBatch) -> Dict[str, Any]:
    """Receive batch of LLM calls from FuzzingBrain instance."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, redis_store = storage

    # Convert to MongoDB format
    calls = []
    total_cost = 0.0
    for call in batch.calls:
        calls.append(
            {
                "call_id": call.call_id,
                "timestamp": datetime.fromisoformat(
                    call.timestamp.replace("Z", "+00:00")
                ),
                "model": call.model,
                "provider": call.provider,
                "fallback_used": call.fallback_used,
                "original_model": call.original_model,
                "input_tokens": call.input_tokens,
                "output_tokens": call.output_tokens,
                "total_tokens": call.total_tokens,
                "cost_input": call.cost_input,
                "cost_output": call.cost_output,
                "cost_total": call.cost_total,
                "latency_ms": call.latency_ms,
                "instance_id": call.instance_id,
                "task_id": call.task_id,
                "worker_id": call.worker_id,
                "agent_id": call.agent_id,
                "agent_type": call.agent_type,
                "operation": call.operation,
                "iteration": call.iteration,
            }
        )
        total_cost += call.cost_total

    # Store in MongoDB
    await mongo.insert_llm_calls(calls)

    # Update Redis counters
    if redis_store:
        await redis_store.incr_cluster_cost(total_cost)
        await redis_store.incr_cluster_counter("total_llm_calls", len(batch.calls))

        # Update per-task counters
        task_costs = {}
        for call in batch.calls:
            if call.task_id:
                task_costs[call.task_id] = (
                    task_costs.get(call.task_id, 0) + call.cost_total
                )
        for task_id, cost in task_costs.items():
            await redis_store.incr_task_cost(task_id, cost)
            await redis_store.incr_task_llm_calls(task_id)

    return {"success": True, "count": len(batch.calls), "total_cost": total_cost}


@router.post("/tool_calls")
async def receive_tool_calls(batch: ToolCallsBatch) -> Dict[str, Any]:
    """Receive batch of tool calls from FuzzingBrain instance."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, redis_store = storage

    # Convert to MongoDB format
    calls = []
    for call in batch.calls:
        calls.append(
            {
                "call_id": call.call_id,
                "timestamp": datetime.fromisoformat(
                    call.timestamp.replace("Z", "+00:00")
                ),
                "tool_name": call.tool_name,
                "tool_category": call.tool_category,
                "arguments_summary": call.arguments_summary,
                "success": call.success,
                "error_type": call.error_type,
                "error_message": call.error_message,
                "result_size_bytes": call.result_size_bytes,
                "latency_ms": call.latency_ms,
                "instance_id": call.instance_id,
                "task_id": call.task_id,
                "worker_id": call.worker_id,
                "agent_id": call.agent_id,
                "agent_type": call.agent_type,
                "iteration": call.iteration,
            }
        )

    # Store in MongoDB
    await mongo.insert_tool_calls(calls)

    # Update Redis counters
    if redis_store:
        await redis_store.incr_cluster_counter("total_tool_calls", len(batch.calls))

        # Update per-task counters
        for call in batch.calls:
            if call.task_id:
                await redis_store.incr_task_tool_calls(call.task_id)

    return {"success": True, "count": len(batch.calls)}


@router.get("/summary")
async def get_cost_summary(task_id: Optional[str] = None) -> Dict[str, Any]:
    """Get cost summary."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, redis_store = storage

    # Try Redis first for real-time data
    if redis_store and not task_id:
        try:
            stats = await redis_store.get_cluster_stats()
            return {
                "total_cost": stats["total_cost"],
                "total_llm_calls": stats["total_llm_calls"],
                "total_tool_calls": stats["total_tool_calls"],
                "source": "redis",
            }
        except Exception:
            pass

    # Fall back to MongoDB
    summary = await mongo.get_cost_summary(task_id=task_id)
    return {
        "total_cost": summary["total_cost"],
        "total_llm_calls": summary["total_calls"],
        "total_input_tokens": summary["total_input_tokens"],
        "total_output_tokens": summary["total_output_tokens"],
        "source": "mongodb",
    }


@router.get("/by-model")
async def get_cost_by_model(task_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get cost breakdown by model."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage
    return await mongo.get_cost_by_model(task_id=task_id)


@router.get("/tools/summary")
async def get_tool_summary(task_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get tool usage summary."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage
    return await mongo.get_tool_summary(task_id=task_id)


@router.get("/task/{task_id}")
async def get_task_cost(task_id: str) -> Dict[str, Any]:
    """Get cost for a specific task."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, redis_store = storage

    # Try Redis first
    if redis_store:
        try:
            stats = await redis_store.get_task_stats(task_id)
            return {
                "task_id": task_id,
                "total_cost": stats["cost"],
                "llm_calls": stats["llm_calls"],
                "tool_calls": stats["tool_calls"],
                "source": "redis",
            }
        except Exception:
            pass

    # Fall back to MongoDB
    summary = await mongo.get_cost_summary(task_id=task_id)
    return {
        "task_id": task_id,
        "total_cost": summary["total_cost"],
        "total_llm_calls": summary["total_calls"],
        "source": "mongodb",
    }
