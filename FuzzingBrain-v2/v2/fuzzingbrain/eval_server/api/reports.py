"""Reports API routes."""

from typing import Any, Dict, List, Optional

from bson import ObjectId
from fastapi import APIRouter

from .suspicious_points import get_main_db, _format_datetime

router = APIRouter()


@router.get("")
async def list_reports(
    task_id: Optional[str] = None,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """List vulnerability reports (POVs that crashed/succeeded)."""
    db = get_main_db()

    query = {"is_successful": True}
    if task_id:
        query["task_id"] = task_id

    cursor = db.povs.find(query).sort("created_at", -1).limit(limit)
    results = await cursor.to_list(length=limit)

    reports = []
    for pov in results:
        # Get related SP info
        sp_id = pov.get("suspicious_point_id")
        sp = None
        function_name = ""
        if sp_id:
            sp = await db.suspicious_points.find_one({"_id": ObjectId(sp_id)})
            if sp:
                function_name = sp.get("function_name", "")

        reports.append(
            {
                "id": str(pov.get("_id", "")),
                "sp_id": sp_id or "",
                "function_name": function_name,
                "vuln_type": pov.get("vuln_type", ""),
                "description": sp.get("description", "")
                if sp
                else pov.get("description", ""),
                "crashed": pov.get("is_successful"),
                "crash_type": pov.get("vuln_type", ""),
                "crash_output": pov.get("sanitizer_output", ""),
                "harness_name": pov.get("harness_name", ""),
                "sanitizer": pov.get("sanitizer", ""),
                "pov_input": pov.get("blob", ""),
                "pov_path": pov.get("blob_path", ""),
                "gen_code": pov.get("gen_blob", ""),
                "verification_notes": sp.get("verification_notes", "") if sp else "",
                "created_at": _format_datetime(pov.get("created_at")),
            }
        )

    return reports
