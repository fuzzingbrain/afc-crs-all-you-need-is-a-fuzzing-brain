"""POV API routes."""

from typing import Any, Dict, List, Optional

from bson import ObjectId
from fastapi import APIRouter, HTTPException

from .suspicious_points import get_main_db, _format_datetime

router = APIRouter()


@router.get("")
async def list_povs(
    task_id: Optional[str] = None,
    sp_id: Optional[str] = None,
    crashed: Optional[bool] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List POVs."""
    db = get_main_db()

    query = {}
    if task_id:
        query["task_id"] = task_id
    if sp_id:
        query["suspicious_point_id"] = sp_id
    if crashed is not None:
        query["is_successful"] = crashed

    cursor = db.povs.find(query).sort("created_at", -1).limit(limit)
    results = await cursor.to_list(length=limit)

    pov_list = []
    for pov in results:
        # Get function_name from related SP if not in POV
        function_name = pov.get("function_name", "")
        if not function_name:
            sp_id = pov.get("suspicious_point_id")
            if sp_id:
                sp = await db.suspicious_points.find_one({"_id": ObjectId(sp_id)})
                if sp:
                    function_name = sp.get("function_name", "")

        # Extract crash type from sanitizer_output
        crash_type = pov.get("vuln_type", "")

        pov_list.append(
            {
                "id": str(pov.get("_id", "")),
                "sp_id": pov.get("suspicious_point_id", ""),
                "function_name": function_name,
                "vuln_type": pov.get("vuln_type", ""),
                "crashed": pov.get("is_successful"),
                "crash_type": crash_type,
                "harness_name": pov.get("harness_name", ""),
                "sanitizer": pov.get("sanitizer", ""),
                "attempt": pov.get("attempt", 0),
                "created_at": _format_datetime(pov.get("created_at")),
            }
        )

    return pov_list


@router.get("/stats")
async def get_pov_stats(task_id: Optional[str] = None) -> Dict[str, Any]:
    """Get POV statistics."""
    db = get_main_db()

    query = {}
    if task_id:
        query["task_id"] = task_id

    total = await db.povs.count_documents(query)
    crashed = await db.povs.count_documents({**query, "is_successful": True})
    not_crashed = await db.povs.count_documents({**query, "is_successful": False})
    pending = await db.povs.count_documents({**query, "is_successful": None})

    return {
        "total": total,
        "crashed": crashed,
        "not_crashed": not_crashed,
        "pending": pending,
    }


@router.get("/{pov_id}")
async def get_pov(pov_id: str) -> Dict[str, Any]:
    """Get POV details."""
    db = get_main_db()

    pov = await db.povs.find_one({"_id": ObjectId(pov_id)})
    if not pov:
        raise HTTPException(status_code=404, detail="POV not found")

    # Get function_name from related SP if not in POV
    function_name = pov.get("function_name", "")
    sp_description = ""
    if not function_name or True:  # Always try to get SP info
        sp_id = pov.get("suspicious_point_id")
        if sp_id:
            sp = await db.suspicious_points.find_one({"_id": ObjectId(sp_id)})
            if sp:
                function_name = function_name or sp.get("function_name", "")
                sp_description = sp.get("description", "")

    return {
        "id": str(pov.get("_id", "")),
        "sp_id": pov.get("suspicious_point_id", ""),
        "function_name": function_name,
        "vuln_type": pov.get("vuln_type", ""),
        "description": pov.get("description", "") or sp_description,
        "crashed": pov.get("is_successful"),
        "crash_type": pov.get("vuln_type", ""),
        "crash_output": pov.get("sanitizer_output", ""),
        "harness_name": pov.get("harness_name", ""),
        "sanitizer": pov.get("sanitizer", ""),
        "attempt": pov.get("attempt", 0),
        "pov_input": pov.get("blob", ""),
        "pov_path": pov.get("blob_path", ""),
        "gen_code": pov.get("gen_blob", ""),
        "created_at": _format_datetime(pov.get("created_at")),
    }
