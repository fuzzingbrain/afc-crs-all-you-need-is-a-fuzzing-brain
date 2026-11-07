# SPDX-License-Identifier: Apache-2.0
"""
Logic group Tools

MCP tools for AI Agent to create and manage analysis logic groups for Full-scan mode.
These tools use the same AnalysisClient context as analyzer tools.
"""

from contextvars import ContextVar
from typing import Any, Dict, List, Optional

from loguru import logger

from . import tools_mcp
from .analyzer import _get_client, _ensure_client


# =============================================================================
# Logic group Context - Track fuzzer for logic group isolation
# Using ContextVar for async task isolation (each asyncio.Task has its own context)
# =============================================================================

_logic_group_fuzzer: ContextVar[Optional[str]] = ContextVar(
    "logic_group_fuzzer", default=None
)
_logic_group_agent_id: ContextVar[Optional[str]] = ContextVar(
    "logic_group_agent_id", default=None
)


def set_logic_group_context(fuzzer: str) -> None:
    """
    Set the context for logic group tools.

    Uses ContextVar for proper isolation in async/parallel execution.

    Args:
        fuzzer: Fuzzer name
    """
    _logic_group_fuzzer.set(fuzzer)
    logger.debug(f"Logic group context set: fuzzer={fuzzer}")


def set_logic_group_agent_id(agent_id: str) -> None:
    """
    Set the agent_id for logic group tools.

    Called by agents on startup to track which agent created a logic group.

    Args:
        agent_id: Agent ObjectId string
    """
    _logic_group_agent_id.set(agent_id)


def get_logic_group_context() -> Optional[str]:
    """Get the current logic group context (fuzzer)."""
    return _logic_group_fuzzer.get()


# =============================================================================
# Logic group Tools - Implementation Functions
# =============================================================================


def create_logic_group_impl(
    name: str,
    risk_level: str,
    risk_reason: str,
    core_functions: List[str],
    entry_functions: List[str] = None,
    code_summary: str = "",
) -> Dict[str, Any]:
    """Implementation of create_logic_group (without MCP decorator)."""
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
        fuzzer = get_logic_group_context() or ""
        agent_id = _logic_group_agent_id.get() or ""

        result = client.create_logic_group(
            name=name,
            risk_level=risk_level.lower(),
            risk_reason=risk_reason,
            core_functions=core_functions,
            entry_functions=entry_functions or [],
            call_chain_summary="",
            code_summary=code_summary,
            fuzzer=fuzzer,
            agent_id=agent_id,
        )

        if result.get("created"):
            logger.info(
                f"[LOGIC GROUP] Created: {name} ({risk_level}) with {len(core_functions)} functions"
            )
            return {
                "success": True,
                "id": result.get("id"),
                "message": f"Logic group '{name}' created with {len(core_functions)} core functions",
            }
        else:
            return {"success": False, "error": result.get("error", "Unknown error")}

    except Exception as e:
        return {"success": False, "error": str(e)}


def list_logic_groups_impl(status: str = None) -> Dict[str, Any]:
    """Implementation of list_logic_groups (without MCP decorator)."""
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        fuzzer = get_logic_group_context()

        result = client.list_logic_groups(fuzzer=fuzzer, status=status)
        return {
            "success": True,
            "logic_groups": result.get("logic_groups", []),
            "count": result.get("count", 0),
            "stats": result.get("stats", {}),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_logic_group_impl(lg_id: str) -> Dict[str, Any]:
    """Implementation of get_logic_group (without MCP decorator)."""
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        result = client.get_logic_group(lg_id)

        if result:
            return {"success": True, "logic_group": result}
        else:
            return {"success": False, "error": f"Logic group not found: {lg_id}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# =============================================================================
# Logic group Tools - MCP Decorated
# =============================================================================


@tools_mcp.tool
def create_logic_group(
    name: str,
    risk_level: str,
    risk_reason: str,
    core_functions: List[str],
    entry_functions: List[str] = None,
    call_chain_summary: str = "",
    code_summary: str = "",
) -> Dict[str, Any]:
    """
    Create a new logic group for Full-scan analysis.

    A logic group is a logical grouping of related functions that should be
    analyzed together for security vulnerabilities.

    Args:
        name: Descriptive name for this logic group based on business logic
        risk_level: Security risk level. One of:
            - "high": Direct input parsing, memory ops, type conversions
            - "medium": Indirect input handling, secondary paths
            - "low": Constants, static data, pure computation
        risk_reason: Explanation of why this risk level was assigned
        core_functions: List of main function names in this logic group
        entry_functions: List of functions where fuzzer input enters this logic group
        call_chain_summary: Summary of call paths through this logic group
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
        fuzzer = get_logic_group_context() or ""
        agent_id = _logic_group_agent_id.get() or ""

        result = client.create_logic_group(
            name=name,
            risk_level=risk_level.lower(),
            risk_reason=risk_reason,
            core_functions=core_functions,
            entry_functions=entry_functions or [],
            call_chain_summary=call_chain_summary,
            code_summary=code_summary,
            fuzzer=fuzzer,
            agent_id=agent_id,
        )

        if result.get("created"):
            logger.info(
                f"[LOGIC GROUP] Created: {name} ({risk_level}) with {len(core_functions)} functions"
            )
            return {
                "success": True,
                "id": result.get("id"),
                "message": f"Logic group '{name}' created with {len(core_functions)} core functions",
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
def list_logic_groups(
    status: str = None,
) -> Dict[str, Any]:
    """
    List all logic groups for the current fuzzer.

    Args:
        status: Optional filter by status ("pending", "in_progress", "completed")

    Returns:
        List of logic groups with their details and stats.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        fuzzer = get_logic_group_context()

        result = client.list_logic_groups(
            fuzzer=fuzzer,
            status=status,
        )

        return {
            "success": True,
            "logic_groups": result.get("logic_groups", []),
            "count": result.get("count", 0),
            "stats": result.get("stats", {}),
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def get_logic_group(
    lg_id: str,
) -> Dict[str, Any]:
    """
    Get details of a specific logic group.

    Args:
        lg_id: The ID of the logic group to retrieve

    Returns:
        Logic group details including core functions, risk level, and status.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        result = client.get_logic_group(lg_id)

        if result:
            return {
                "success": True,
                "logic_group": result,
            }
        else:
            return {
                "success": False,
                "error": f"Logic group not found: {lg_id}",
            }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


# Export public API
__all__ = [
    # Context
    "set_logic_group_context",
    "set_logic_group_agent_id",
    "get_logic_group_context",
    # Logic group tools (MCP decorated)
    "create_logic_group",
    "list_logic_groups",
    "get_logic_group",
    # Logic group tools (implementation, for mcp_factory)
    "create_logic_group_impl",
    "list_logic_groups_impl",
    "get_logic_group_impl",
]
