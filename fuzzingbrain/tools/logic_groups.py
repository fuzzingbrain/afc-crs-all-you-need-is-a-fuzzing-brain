# SPDX-License-Identifier: Apache-2.0
"""
Logic group tools (full scan).

The LG planner of a worker groups the harness's reachable functions into
logic groups; each is a row of logic_groups owned by the worker. The tools
run in the worker process (worker/scope.py) and write PostgreSQL directly.
"""

from contextvars import ContextVar
from typing import Any, Dict, List, Optional

import logging

from ..db.store import get_store, lg_dict
from ..worker.scope import get_scope

logger = logging.getLogger(__name__)

_logic_group_agent_id: ContextVar[Optional[str]] = ContextVar(
    "logic_group_agent_id", default=None
)

RISK_LEVELS = ("high", "medium", "low")


def set_logic_group_agent_id(agent_id: str) -> None:
    """The agent the next logic groups are created by."""
    _logic_group_agent_id.set(agent_id or None)


def _public(lg) -> Dict[str, Any]:
    d = lg_dict(lg)
    d["id"] = d["short_id"]
    for k in ("run_id", "worker_id", "lg_id", "short_id", "created_by_agent_id"):
        d.pop(k, None)
    return d


def create_logic_group_impl(
    name: str,
    risk_level: str,
    risk_reason: str,
    core_functions: List[str],
    entry_functions: List[str] = None,
    code_summary: str = "",
) -> Dict[str, Any]:
    scope = get_scope()
    if scope is None:
        return {"success": False, "error": "logic group tools run only inside a worker"}
    level = (risk_level or "").lower()
    if level not in RISK_LEVELS:
        return {
            "success": False,
            "error": f"Invalid risk_level: {risk_level}. Must be one of: {list(RISK_LEVELS)}",
        }
    if not name or not core_functions:
        return {"success": False, "error": "name and core_functions are required"}
    agent_id = _logic_group_agent_id.get()
    if not agent_id:
        return {"success": False, "error": "no agent is creating this logic group"}
    summary = "\n\n".join(p for p in (risk_reason, code_summary) if p) or None
    try:
        lid = get_store().create_logic_group(
            scope.run_id,
            scope.worker_id,
            agent_id,
            name,
            level,
            [str(f) for f in core_functions],
            [str(f) for f in (entry_functions or [])],
            summary,
        )
    except Exception as e:
        logger.error(f"Failed to create logic group: {e}")
        return {"success": False, "error": str(e)[:200]}
    logger.info(
        f"[LOGIC GROUP] Created: {name} ({level}) with {len(core_functions)} functions"
    )
    return {
        "success": True,
        "id": str(lid)[:8],
        "message": f"Logic group '{name}' created with {len(core_functions)} core functions",
    }


def list_logic_groups_impl(status: str = None) -> Dict[str, Any]:
    scope = get_scope()
    if scope is None:
        return {"success": False, "error": "logic group tools run only inside a worker"}
    rows = [_public(g) for g in get_store().logic_groups(scope.worker_id)]
    return {"success": True, "logic_groups": rows, "count": len(rows)}


def get_logic_group_impl(lg_id: str) -> Dict[str, Any]:
    scope = get_scope()
    if scope is None:
        return {"success": False, "error": "logic group tools run only inside a worker"}
    want = (lg_id or "").strip().lower()
    for g in get_store().logic_groups(scope.worker_id):
        if want and str(g.id).startswith(want):
            return {"success": True, "logic_group": _public(g)}
    return {"success": False, "error": f"Logic group not found: {lg_id}"}


__all__ = [
    "set_logic_group_agent_id",
    "create_logic_group_impl",
    "list_logic_groups_impl",
    "get_logic_group_impl",
]
