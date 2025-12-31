"""
Suspicious Points Tools

MCP tools for AI Agent to create, update, and query suspicious points.
These tools use the same AnalysisClient context as analyzer tools.
"""

import json
from typing import Any, Dict, List, Optional

from loguru import logger

from . import tools_mcp
from .analyzer import _get_client, _ensure_client


# =============================================================================
# SP Context - Track harness_name and sanitizer for SP isolation
# =============================================================================

# Global context for SP tools (each worker sets its own)
_sp_harness_name: Optional[str] = None
_sp_sanitizer: Optional[str] = None


def set_sp_context(harness_name: str, sanitizer: str) -> None:
    """
    Set the context for SP tools.

    This should be called by each worker before running agents that create SPs.
    SPs created will be tagged with this harness_name and sanitizer, ensuring
    each worker only processes its own SPs.

    Args:
        harness_name: Fuzzer harness name (e.g., "fuzz_png")
        sanitizer: Sanitizer type (e.g., "address")
    """
    global _sp_harness_name, _sp_sanitizer
    _sp_harness_name = harness_name
    _sp_sanitizer = sanitizer
    logger.debug(f"SP context set: harness_name={harness_name}, sanitizer={sanitizer}")


def get_sp_context() -> tuple:
    """Get the current SP context (harness_name, sanitizer)."""
    return _sp_harness_name, _sp_sanitizer


# =============================================================================
# Suspicious Point Tools
# =============================================================================

@tools_mcp.tool
def create_suspicious_point(
    function_name: str,
    description: str,
    vuln_type: str,
    score: float = 0.5,
    important_controlflow: List[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Create a new suspicious point when you identify a potential vulnerability.

    Use control flow descriptions instead of line numbers.

    Args:
        function_name: The function containing the suspicious code
        description: Detailed description of the potential vulnerability.
                    Describe using control flow, not line numbers.
                    Example: "The length parameter from user input flows into
                    memcpy without bounds checking after the if-else branch"
        vuln_type: Type of vulnerability. One of:
            - buffer-overflow
            - use-after-free
            - integer-overflow
            - null-pointer-dereference
            - format-string
            - double-free
            - uninitialized-memory
            - out-of-bounds-read
            - out-of-bounds-write
        score: Confidence score (0.0-1.0). Higher means more likely to be real.
            - 0.8-1.0: Very confident, clear vulnerability pattern
            - 0.5-0.8: Moderate confidence, needs verification
            - 0.0-0.5: Low confidence, suspicious but uncertain
        important_controlflow: List of related functions/variables that affect this bug.
            Format: [{"type": "function"|"variable", "name": "xxx", "location": "description"}]

    Returns:
        {"success": True, "id": "xxx"} on success
        {"success": False, "error": "..."} on failure
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        # Include harness_name and sanitizer from context
        harness_name, sanitizer = get_sp_context()
        result = client.create_suspicious_point(
            function_name=function_name,
            description=description,
            vuln_type=vuln_type,
            score=score,
            important_controlflow=important_controlflow or [],
            harness_name=harness_name or "",
            sanitizer=sanitizer or "",
        )

        # Log the new suspicious point
        sp_json = json.dumps({
            "id": result.get("id"),
            "function_name": function_name,
            "vuln_type": vuln_type,
            "score": score,
            "description": description,
            "important_controlflow": important_controlflow or [],
            "harness_name": harness_name,
            "sanitizer": sanitizer,
        }, ensure_ascii=False)
        logger.info(f"[NEW SUSPICIOUS POINT] {sp_json}")

        return {
            "success": True,
            "id": result.get("id"),
            "created": True,
        }
    except Exception as e:
        logger.error(f"Failed to create suspicious point: {e}")
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def update_suspicious_point(
    suspicious_point_id: str,
    is_checked: bool = None,
    is_real: bool = None,
    is_important: bool = None,
    score: float = None,
    verification_notes: str = None,
) -> Dict[str, Any]:
    """
    Update a suspicious point after verification.

    Call this after analyzing a suspicious point to mark it as verified.

    Args:
        suspicious_point_id: The ID of the suspicious point to update
        is_checked: Set to True when verification is complete
        is_real: Set to True if confirmed as real vulnerability, False if false positive
        is_important: Set to True if this is a high-priority vulnerability
        score: Updated confidence score based on analysis
        verification_notes: Notes explaining the verification result.
            Example: "Confirmed: no bounds check before memcpy, attacker-controlled length"
            Example: "False positive: length is validated in caller function png_read_chunk"

    Returns:
        {"success": True, "updated": True} on success
        {"success": False, "error": "..."} on failure
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        result = client.update_suspicious_point(
            sp_id=suspicious_point_id,
            is_checked=is_checked,
            is_real=is_real,
            is_important=is_important,
            score=score,
            verification_notes=verification_notes,
        )

        # Log the update with server result
        update_json = json.dumps({
            "id": suspicious_point_id,
            "is_checked": is_checked,
            "is_real": is_real,
            "is_important": is_important,
            "score": score,
            "verification_notes": verification_notes,
        }, ensure_ascii=False)

        # Check if server actually updated the DB
        updated = result.get("updated", False) if result else False
        if updated:
            logger.info(f"[UPDATE SUSPICIOUS POINT] {update_json}")
        else:
            logger.warning(f"[UPDATE SUSPICIOUS POINT FAILED] Server returned: {result}, params: {update_json}")

        return {
            "success": updated,
            "updated": updated,
            "server_result": result,
        }
    except Exception as e:
        logger.error(f"Failed to update suspicious point: {e}")
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def list_suspicious_points(
    filter_unchecked: bool = False,
    filter_real: bool = False,
    filter_important: bool = False,
) -> Dict[str, Any]:
    """
    List suspicious points for the current task with optional filters.

    Args:
        filter_unchecked: If True, only return points that haven't been verified yet
        filter_real: If True, only return confirmed real vulnerabilities
        filter_important: If True, only return high-priority points

    Returns:
        {
            "success": True,
            "suspicious_points": [...],  # List of suspicious point dicts
            "count": N,                  # Number of points returned
        }
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        result = client.list_suspicious_points(
            filter_unchecked=filter_unchecked,
            filter_real=filter_real,
            filter_important=filter_important,
        )
        return {
            "success": True,
            "suspicious_points": result.get("suspicious_points", []),
            "count": result.get("count", 0),
        }
    except Exception as e:
        logger.error(f"Failed to list suspicious points: {e}")
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def get_suspicious_point(suspicious_point_id: str) -> Dict[str, Any]:
    """
    Get details of a specific suspicious point.

    Args:
        suspicious_point_id: The ID of the suspicious point

    Returns:
        {"success": True, "suspicious_point": {...}} on success
        {"success": False, "error": "..."} if not found
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        result = client.get_suspicious_point(suspicious_point_id)
        if result is None:
            return {
                "success": False,
                "error": f"Suspicious point '{suspicious_point_id}' not found",
            }
        return {
            "success": True,
            "suspicious_point": result,
        }
    except Exception as e:
        logger.error(f"Failed to get suspicious point: {e}")
        return {
            "success": False,
            "error": str(e),
        }


# Export public API
__all__ = [
    # Context
    "set_sp_context",
    "get_sp_context",
    # SP tools
    "create_suspicious_point",
    "update_suspicious_point",
    "list_suspicious_points",
    "get_suspicious_point",
]
