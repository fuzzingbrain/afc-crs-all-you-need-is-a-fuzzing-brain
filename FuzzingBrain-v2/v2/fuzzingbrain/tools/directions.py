"""
Direction Tools

MCP tools for AI Agent to create and manage analysis directions for Full-scan mode.
These tools use the same AnalysisClient context as analyzer tools.
"""

from contextvars import ContextVar
from typing import Any, Dict, List, Optional

from loguru import logger

from . import tools_mcp
from .analyzer import _get_client, _ensure_client


# =============================================================================
# Direction Context - Track fuzzer for direction isolation
# Using ContextVar for async task isolation (each asyncio.Task has its own context)
# =============================================================================

_direction_fuzzer: ContextVar[Optional[str]] = ContextVar('direction_fuzzer', default=None)


def set_direction_context(fuzzer: str) -> None:
    """
    Set the context for direction tools.

    Uses ContextVar for proper isolation in async/parallel execution.

    Args:
        fuzzer: Fuzzer name
    """
    _direction_fuzzer.set(fuzzer)
    logger.debug(f"Direction context set: fuzzer={fuzzer}")


def get_direction_context() -> Optional[str]:
    """Get the current direction context (fuzzer)."""
    return _direction_fuzzer.get()


# =============================================================================
# Direction Tools - Implementation Functions
# =============================================================================

def create_direction_impl(
    name: str,
    risk_level: str,
    risk_reason: str,
    core_functions: List[str],
    entry_functions: List[str] = None,
    code_summary: str = "",
) -> Dict[str, Any]:
    """Implementation of create_direction (without MCP decorator)."""
    err = _ensure_client()
    if err:
        return err

    valid_levels = ["high", "medium", "low"]
    if risk_level.lower() not in valid_levels:
        return {
            "success": False,
            "error": f"Invalid risk_level: {risk_level}. Must be one of: {valid_levels}",
        }

    try:
        client = _get_client()
        fuzzer = get_direction_context() or ""

        result = client.create_direction(
            name=name,
            risk_level=risk_level.lower(),
            risk_reason=risk_reason,
            core_functions=core_functions,
            entry_functions=entry_functions or [],
            call_chain_summary="",
            code_summary=code_summary,
            fuzzer=fuzzer,
        )

        if result.get("created"):
            logger.info(f"[DIRECTION] Created: {name} ({risk_level}) with {len(core_functions)} functions")
            return {
                "success": True,
                "id": result.get("id"),
                "message": f"Direction '{name}' created with {len(core_functions)} core functions",
            }
        else:
            return {"success": False, "error": result.get("error", "Unknown error")}

    except Exception as e:
        return {"success": False, "error": str(e)}


def list_directions_impl(status: str = None) -> Dict[str, Any]:
    """Implementation of list_directions (without MCP decorator)."""
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        fuzzer = get_direction_context()

        result = client.list_directions(fuzzer=fuzzer, status=status)
        return {
            "success": True,
            "directions": result.get("directions", []),
            "count": result.get("count", 0),
            "stats": result.get("stats", {}),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_direction_impl(direction_id: str) -> Dict[str, Any]:
    """Implementation of get_direction (without MCP decorator)."""
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        result = client.get_direction(direction_id)

        if result:
            return {"success": True, "direction": result}
        else:
            return {"success": False, "error": f"Direction not found: {direction_id}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# =============================================================================
# Direction Tools - MCP Decorated
# =============================================================================

@tools_mcp.tool
def create_direction(
    name: str,
    risk_level: str,
    risk_reason: str,
    core_functions: List[str],
    entry_functions: List[str] = None,
    call_chain_summary: str = "",
    code_summary: str = "",
) -> Dict[str, Any]:
    """
    Create a new direction for Full-scan analysis.

    A direction is a logical grouping of related functions that should be
    analyzed together for security vulnerabilities.

    Args:
        name: Descriptive name for this direction based on business logic
        risk_level: Security risk level. One of:
            - "high": Direct input parsing, memory ops, type conversions
            - "medium": Indirect input handling, secondary paths
            - "low": Constants, static data, pure computation
        risk_reason: Explanation of why this risk level was assigned
        core_functions: List of main function names in this direction
        entry_functions: List of functions where fuzzer input enters this direction
        call_chain_summary: Summary of call paths through this direction
        code_summary: Brief description of what this code does

    Returns:
        {"success": True, "id": "..."} on success
        {"success": False, "error": "..."} on failure
    """
    err = _ensure_client()
    if err:
        return err

    # Validate risk level
    valid_levels = ["high", "medium", "low"]
    if risk_level.lower() not in valid_levels:
        return {
            "success": False,
            "error": f"Invalid risk_level: {risk_level}. Must be one of: {valid_levels}",
        }

    try:
        client = _get_client()
        fuzzer = get_direction_context() or ""

        result = client.create_direction(
            name=name,
            risk_level=risk_level.lower(),
            risk_reason=risk_reason,
            core_functions=core_functions,
            entry_functions=entry_functions or [],
            call_chain_summary=call_chain_summary,
            code_summary=code_summary,
            fuzzer=fuzzer,
        )

        if result.get("created"):
            logger.info(f"[DIRECTION] Created: {name} ({risk_level}) with {len(core_functions)} functions")
            return {
                "success": True,
                "id": result.get("id"),
                "message": f"Direction '{name}' created with {len(core_functions)} core functions",
            }
        else:
            return {
                "success": False,
                "error": result.get("error", "Unknown error"),
            }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def list_directions(
    status: str = None,
) -> Dict[str, Any]:
    """
    List all directions for the current fuzzer.

    Args:
        status: Optional filter by status ("pending", "in_progress", "completed")

    Returns:
        List of directions with their details and stats.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        fuzzer = get_direction_context()

        result = client.list_directions(
            fuzzer=fuzzer,
            status=status,
        )

        return {
            "success": True,
            "directions": result.get("directions", []),
            "count": result.get("count", 0),
            "stats": result.get("stats", {}),
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def get_direction(
    direction_id: str,
) -> Dict[str, Any]:
    """
    Get details of a specific direction.

    Args:
        direction_id: The ID of the direction to retrieve

    Returns:
        Direction details including core functions, risk level, and status.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        result = client.get_direction(direction_id)

        if result:
            return {
                "success": True,
                "direction": result,
            }
        else:
            return {
                "success": False,
                "error": f"Direction not found: {direction_id}",
            }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


# Export public API
__all__ = [
    # Context
    "set_direction_context",
    "get_direction_context",
    # Direction tools (MCP decorated)
    "create_direction",
    "list_directions",
    "get_direction",
    # Direction tools (implementation, for mcp_factory)
    "create_direction_impl",
    "list_directions_impl",
    "get_direction_impl",
]
