"""Directions API routes."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException

from .suspicious_points import get_main_db, _format_datetime

router = APIRouter()


@router.get("")
async def list_directions(
    task_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List directions."""
    db = get_main_db()

    query = {}
    if task_id:
        query["task_id"] = task_id
    if status:
        query["status"] = status

    cursor = db.directions.find(query).sort("created_at", -1).limit(limit)
    results = await cursor.to_list(length=limit)

    return [
        {
            "id": str(d.get("_id", "")),
            "name": d.get("name", ""),
            "fuzzer": d.get("fuzzer", ""),
            "risk_level": d.get("risk_level", ""),
            "risk_reason": d.get("risk_reason", ""),
            "core_functions": d.get("core_functions", []),
            "entry_functions": d.get("entry_functions", []),
            "code_summary": d.get("code_summary", ""),
            "status": d.get("status", "pending"),
            "sp_count": d.get("sp_count", 0),
            "functions_analyzed": d.get("functions_analyzed", 0),
            "created_at": _format_datetime(d.get("created_at")),
            "started_at": _format_datetime(d.get("started_at")),
            "completed_at": _format_datetime(d.get("completed_at")),
        }
        for d in results
    ]


@router.get("/stats")
async def get_direction_stats(task_id: Optional[str] = None) -> Dict[str, Any]:
    """Get direction statistics."""
    db = get_main_db()

    query = {}
    if task_id:
        query["task_id"] = task_id

    total = await db.directions.count_documents(query)
    completed = await db.directions.count_documents({**query, "status": "completed"})
    pending = await db.directions.count_documents({**query, "status": "pending"})
    processing = await db.directions.count_documents({**query, "status": "processing"})

    return {
        "total": total,
        "completed": completed,
        "pending": pending,
        "processing": processing,
    }


@router.get("/{direction_id}")
async def get_direction(direction_id: str) -> Dict[str, Any]:
    """Get direction details."""
    db = get_main_db()

    d = await db.directions.find_one({"_id": direction_id})
    if not d:
        raise HTTPException(status_code=404, detail="Direction not found")

    return {
        "id": str(d.get("_id", "")),
        "name": d.get("name", ""),
        "fuzzer": d.get("fuzzer", ""),
        "risk_level": d.get("risk_level", ""),
        "risk_reason": d.get("risk_reason", ""),
        "core_functions": d.get("core_functions", []),
        "entry_functions": d.get("entry_functions", []),
        "call_chain_summary": d.get("call_chain_summary", ""),
        "code_summary": d.get("code_summary", ""),
        "status": d.get("status", "pending"),
        "sp_count": d.get("sp_count", 0),
        "functions_analyzed": d.get("functions_analyzed", 0),
        "created_at": _format_datetime(d.get("created_at")),
        "started_at": _format_datetime(d.get("started_at")),
        "completed_at": _format_datetime(d.get("completed_at")),
        "updated_at": _format_datetime(d.get("updated_at")),
    }
