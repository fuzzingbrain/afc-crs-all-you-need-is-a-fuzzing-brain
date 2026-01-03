"""Suspicious Points API routes."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
import motor.motor_asyncio

router = APIRouter()

# Connection to main fuzzingbrain database
_main_db = None


def get_main_db():
    """Get connection to main fuzzingbrain database."""
    global _main_db
    if _main_db is None:
        client = motor.motor_asyncio.AsyncIOMotorClient("mongodb://localhost:27017/")
        _main_db = client["fuzzingbrain"]
    return _main_db


def _format_datetime(dt):
    """Format datetime to ISO string, handling both datetime objects and strings."""
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    return dt.isoformat() if hasattr(dt, 'isoformat') else str(dt)


@router.get("")
async def list_suspicious_points(
    task_id: Optional[str] = None,
    is_checked: Optional[bool] = None,
    is_real: Optional[bool] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List suspicious points."""
    db = get_main_db()

    query = {}
    if task_id:
        query["task_id"] = task_id
    if is_checked is not None:
        query["is_checked"] = is_checked
    if is_real is not None:
        query["is_real"] = is_real

    cursor = db.suspicious_points.find(query).sort("created_at", -1).limit(limit)
    results = await cursor.to_list(length=limit)

    return [
        {
            "id": str(sp.get("_id", "")),
            "function_name": sp.get("function_name", ""),
            "vuln_type": sp.get("vuln_type", ""),
            "description": sp.get("description", "")[:200],
            "score": sp.get("score", 0),
            "is_checked": sp.get("is_checked", False),
            "is_real": sp.get("is_real", False),
            "is_important": sp.get("is_important", False),
            "harness_name": sp.get("harness_name", ""),
            "sanitizer": sp.get("sanitizer", ""),
            "verification_notes": sp.get("verification_notes", ""),
            "pov_guidance": sp.get("pov_guidance", ""),
            "created_at": _format_datetime(sp.get("created_at")),
        }
        for sp in results
    ]


@router.get("/stats")
async def get_sp_stats(task_id: Optional[str] = None) -> Dict[str, Any]:
    """Get suspicious points statistics.

    - is_checked: whether verification was done
    - is_important: whether it's a real bug (determined during verification)
    - is_real: whether POV was generated (not about real/fake bug)
    """
    db = get_main_db()

    query = {}
    if task_id:
        query["task_id"] = task_id

    total = await db.suspicious_points.count_documents(query)
    checked = await db.suspicious_points.count_documents({**query, "is_checked": True})
    # is_important=True means it's a real bug
    real_bugs = await db.suspicious_points.count_documents({**query, "is_important": True})
    # verified but not important = false positive
    false_positives = await db.suspicious_points.count_documents({**query, "is_checked": True, "is_important": False})
    # is_real means POV was generated
    pov_generated = await db.suspicious_points.count_documents({**query, "is_real": True})

    return {
        "total": total,
        "checked": checked,
        "unchecked": total - checked,
        "real_bugs": real_bugs,
        "false_positives": false_positives,
        "pov_generated": pov_generated,
    }


@router.get("/{sp_id}")
async def get_suspicious_point(sp_id: str) -> Dict[str, Any]:
    """Get suspicious point details."""
    db = get_main_db()

    sp = await db.suspicious_points.find_one({"_id": sp_id})
    if not sp:
        raise HTTPException(status_code=404, detail="Suspicious point not found")

    return {
        "id": str(sp.get("_id", "")),
        "function_name": sp.get("function_name", ""),
        "vuln_type": sp.get("vuln_type", ""),
        "description": sp.get("description", ""),
        "score": sp.get("score", 0),
        "is_checked": sp.get("is_checked", False),
        "is_real": sp.get("is_real", False),
        "is_important": sp.get("is_important", False),
        "harness_name": sp.get("harness_name", ""),
        "sanitizer": sp.get("sanitizer", ""),
        "verification_notes": sp.get("verification_notes", ""),
        "pov_guidance": sp.get("pov_guidance", ""),
        "important_controlflow": sp.get("important_controlflow", []),
        "created_at": _format_datetime(sp.get("created_at")),
        "updated_at": _format_datetime(sp.get("updated_at")),
    }
