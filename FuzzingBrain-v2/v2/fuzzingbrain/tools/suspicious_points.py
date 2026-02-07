"""
Suspicious Points Tools

MCP tools for AI Agent to create, update, and query suspicious points.
These tools use the same AnalysisClient context as analyzer tools.
"""

import json
from contextvars import ContextVar
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from . import tools_mcp
from .analyzer import _get_client, _ensure_client


# =============================================================================
# SP Context - Track harness_name and sanitizer for SP isolation
# Using ContextVar for async task isolation (each asyncio.Task has its own context)
# =============================================================================

_sp_harness_name: ContextVar[Optional[str]] = ContextVar(
    "sp_harness_name", default=None
)
_sp_sanitizer: ContextVar[Optional[str]] = ContextVar("sp_sanitizer", default=None)
_sp_direction_id: ContextVar[Optional[str]] = ContextVar(
    "sp_direction_id", default=None
)
_sp_agent_id: ContextVar[Optional[str]] = ContextVar("sp_agent_id", default=None)


def set_sp_context(
    harness_name: str,
    sanitizer: str,
    direction_id: str = "",
    agent_id: str = "",
) -> None:
    """
    Set the context for SP tools.

    This should be called by each worker before running agents that create SPs.
    SPs created will be tagged with this harness_name and sanitizer, ensuring
    each worker only processes its own SPs.

    Uses ContextVar for proper isolation in async/parallel execution.

    Args:
        harness_name: Fuzzer harness name (e.g., "fuzz_png")
        sanitizer: Sanitizer type (e.g., "address")
        direction_id: Direction ID for linking SP to direction
        agent_id: Agent ObjectId for tracking SP creator/verifier
    """
    _sp_harness_name.set(harness_name)
    _sp_sanitizer.set(sanitizer)
    _sp_direction_id.set(direction_id)
    _sp_agent_id.set(agent_id)
    logger.debug(
        f"SP context set: harness_name={harness_name}, sanitizer={sanitizer}, direction_id={direction_id}, agent_id={agent_id[:8] if agent_id else 'none'}"
    )


def get_sp_context() -> Tuple[
    Optional[str], Optional[str], Optional[str], Optional[str]
]:
    """Get the current SP context (harness_name, sanitizer, direction_id, agent_id)."""
    return (
        _sp_harness_name.get(),
        _sp_sanitizer.get(),
        _sp_direction_id.get(),
        _sp_agent_id.get(),
    )


def set_sp_agent_id(agent_id: str) -> None:
    """
    Set only the agent_id in SP context.

    This should be called by agents when they start running, so they can
    be tracked as the creator/verifier of SPs without changing other context.

    Args:
        agent_id: Agent ObjectId for tracking SP creator/verifier
    """
    _sp_agent_id.set(agent_id)
    logger.debug(f"SP agent_id set: {agent_id[:8] if agent_id else 'none'}")


# Aliases for mcp_factory compatibility
_get_sp_context = get_sp_context


def _ensure_sp_context() -> Optional[Dict[str, Any]]:
    """Ensure SP context is set, return error dict if not."""
    harness_name, sanitizer, _, _ = get_sp_context()
    if harness_name is None or sanitizer is None:
        return {
            "success": False,
            "error": "SP context not set. Call set_sp_context() first.",
        }
    return None


# =============================================================================
# Suspicious Point Tools - Implementation Functions
# =============================================================================


def create_suspicious_point_impl(
    function_name: str,
    vuln_type: str,
    description: str,
    score: float = 0.5,
    important_controlflow: List[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Implementation of create_suspicious_point (without MCP decorator)."""
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        harness_name, sanitizer, direction_id, agent_id = get_sp_context()
        result = client.create_suspicious_point(
            function_name=function_name,
            description=description,
            vuln_type=vuln_type,
            score=score,
            important_controlflow=important_controlflow or [],
            harness_name=harness_name or "",
            sanitizer=sanitizer or "",
            direction_id=direction_id or "",
            agent_id=agent_id or "",
        )

        merged = result.get("merged", False)
        sp_id = result.get("id")

        if merged:
            logger.info(f"[MERGED SP] {sp_id[:8]} <- {function_name} ({vuln_type})")
            return {"success": True, "merged": True, "id": sp_id[:8]}
        else:
            logger.info(
                f"[NEW SP] {sp_id[:8]} -> {function_name} ({vuln_type}, score={score})"
            )
            return {"success": True, "created": True, "id": sp_id[:8]}
    except Exception as e:
        logger.error(f"Failed to create suspicious point: {e}")
        return {"success": False, "error": str(e)[:100]}


def update_suspicious_point_impl(
    suspicious_point_id: str,
    score: float = None,
    is_checked: bool = None,
    is_real: bool = None,
    is_important: bool = None,
    verification_notes: str = None,
    pov_guidance: str = None,
    reachability_status: str = None,
    reachability_multiplier: float = None,
    reachability_reason: str = None,
) -> Dict[str, Any]:
    """Implementation of update_suspicious_point (without MCP decorator)."""
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        # Get agent_id from context for tracking verified_by_agent_id
        _, _, _, agent_id = get_sp_context()
        result = client.update_suspicious_point(
            sp_id=suspicious_point_id,
            is_checked=is_checked,
            is_real=is_real,
            is_important=is_important,
            score=score,
            verification_notes=verification_notes,
            pov_guidance=pov_guidance,
            reachability_status=reachability_status,
            reachability_multiplier=reachability_multiplier,
            reachability_reason=reachability_reason,
            agent_id=agent_id or "",  # Track which agent verified this SP
        )

        update_json = json.dumps(
            {
                "id": suspicious_point_id,
                "is_checked": is_checked,
                "is_real": is_real,
                "is_important": is_important,
                "score": score,
                "verification_notes": verification_notes,
                "pov_guidance": pov_guidance,
            },
            ensure_ascii=False,
        )

        updated = result.get("updated", False) if result else False
        if updated:
            logger.info(f"[UPDATE SUSPICIOUS POINT] {update_json}")
            # SP verification is now tracked via AgentContext and MongoDB
            # No need for reporter - data persisted directly
        else:
            logger.warning(
                f"[UPDATE SUSPICIOUS POINT FAILED] Server returned: {result}"
            )

        return {"success": updated, "updated": updated, "server_result": result}
    except Exception as e:
        logger.error(f"Failed to update suspicious point: {e}")
        return {"success": False, "error": str(e)}


def list_suspicious_points_impl(
    filter_unchecked: bool = False,
    filter_real: bool = False,
    filter_important: bool = False,
) -> Dict[str, Any]:
    """Implementation of list_suspicious_points (without MCP decorator)."""
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
        return {"success": False, "error": str(e)}


def get_suspicious_point_impl(suspicious_point_id: str) -> Dict[str, Any]:
    """Implementation of get_suspicious_point (without MCP decorator)."""
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
        return {"success": True, "suspicious_point": result}
    except Exception as e:
        logger.error(f"Failed to get suspicious point: {e}")
        return {"success": False, "error": str(e)}


# =============================================================================
# Suspicious Point Tools - MCP Decorated
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
        # Include harness_name, sanitizer, and agent_id from context
        harness_name, sanitizer, direction_id, agent_id = get_sp_context()
        result = client.create_suspicious_point(
            function_name=function_name,
            description=description,
            vuln_type=vuln_type,
            score=score,
            important_controlflow=important_controlflow or [],
            harness_name=harness_name or "",
            sanitizer=sanitizer or "",
            direction_id=direction_id or "",
            agent_id=agent_id or "",
        )

        merged = result.get("merged", False)
        sp_id = result.get("id")

        if merged:
            logger.info(f"[MERGED SP] {sp_id[:8]} <- {function_name} ({vuln_type})")
            return {"success": True, "merged": True, "id": sp_id[:8]}
        else:
            logger.info(
                f"[NEW SP] {sp_id[:8]} -> {function_name} ({vuln_type}, score={score})"
            )
            return {"success": True, "created": True, "id": sp_id[:8]}
    except Exception as e:
        logger.error(f"Failed to create suspicious point: {e}")
        return {"success": False, "error": str(e)[:100]}


@tools_mcp.tool
def update_suspicious_point(
    suspicious_point_id: str,
    is_checked: bool = None,
    is_real: bool = None,
    is_important: bool = None,
    score: float = None,
    verification_notes: str = None,
    pov_guidance: str = None,
) -> Dict[str, Any]:
    """
    Update a suspicious point after verification.

    Call this after analyzing a suspicious point to mark it as verified.

    Args:
        suspicious_point_id: The ID of the suspicious point to update
        is_checked: Set to True when verification is complete
        is_real: Set to True if confirmed as real vulnerability, False if false positive
        is_important: Set to True if this is a high-priority vulnerability (will proceed to POV)
        score: Updated confidence score based on analysis
        verification_notes: Notes explaining the verification result.
            Example: "Confirmed: no bounds check before memcpy, attacker-controlled length"
            Example: "False positive: length is validated in caller function"
        pov_guidance: REQUIRED when is_important=True. Brief guidance for POV agent:
            1. Input direction: What kind of input to generate
            2. How to reach the vuln: What input structure/values help the payload
               pass through earlier checks and reach the vulnerable code
            Keep it simple, 1-3 sentences. POV agent uses this as reference only.

    Returns:
        {"success": True, "updated": True} on success
        {"success": False, "error": "..."} on failure
    """
    err = _ensure_client()
    if err:
        return err

    # Validate: pov_guidance is REQUIRED when is_important=True
    if is_important is True and not pov_guidance:
        return {
            "success": False,
            "error": "pov_guidance is REQUIRED when is_important=True. Please provide brief guidance for POV agent: what input to generate and how to reach the vulnerability.",
        }

    try:
        client = _get_client()
        # Get agent_id from context for tracking verified_by_agent_id
        _, _, _, agent_id = get_sp_context()
        result = client.update_suspicious_point(
            sp_id=suspicious_point_id,
            is_checked=is_checked,
            is_real=is_real,
            is_important=is_important,
            score=score,
            verification_notes=verification_notes,
            pov_guidance=pov_guidance,
            agent_id=agent_id or "",  # Track which agent verified this SP
        )

        # Log the update with server result
        update_json = json.dumps(
            {
                "id": suspicious_point_id,
                "is_checked": is_checked,
                "is_real": is_real,
                "is_important": is_important,
                "score": score,
                "verification_notes": verification_notes,
                "pov_guidance": pov_guidance,
            },
            ensure_ascii=False,
        )

        # Check if server actually updated the DB
        updated = result.get("updated", False) if result else False
        if updated:
            logger.info(f"[UPDATE SUSPICIOUS POINT] {update_json}")
        else:
            logger.warning(
                f"[UPDATE SUSPICIOUS POINT FAILED] Server returned: {result}, params: {update_json}"
            )

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
    "set_sp_agent_id",
    "get_sp_context",
    "_get_sp_context",
    "_ensure_sp_context",
    # SP tools (MCP decorated)
    "create_suspicious_point",
    "update_suspicious_point",
    "list_suspicious_points",
    "get_suspicious_point",
    # SP tools (implementation, for mcp_factory)
    "create_suspicious_point_impl",
    "update_suspicious_point_impl",
    "list_suspicious_points_impl",
    "get_suspicious_point_impl",
]
