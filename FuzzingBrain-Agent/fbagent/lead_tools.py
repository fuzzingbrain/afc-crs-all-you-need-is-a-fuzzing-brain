# SPDX-License-Identifier: Apache-2.0
"""Per-role tool sets: a whitelist of the built-in navigation tools plus the
Lead-board tools a stage needs, and a runner bound to one LeadBoard.

Agent takes `tools` (the schema list it exposes) and `tool_runner` (who runs a
call); this module builds both for a given role, so one loop serves discovery,
verification and reproduction without the loop changing. The built-in tools
(read / glob / grep / bash / trace / gates) come from tools.py unchanged; the
Lead tools (create_lead / update_lead) write to the board here, never touching
tools.py.

Tool sets (basic, ASan):
  discovery   : read glob grep bash + create_lead
  verify      : read glob grep bash trace + update_lead
  reproduce   : read glob grep bash trace gates          (no board tool; the
                controller banks a submit-backed crash on the Lead itself)
"""
from __future__ import annotations

from typing import Callable

from . import tools as _tools
from .lead import _DISCOVERY_FIELDS, _VERIFY_FIELDS, LeadBoard

ROLE_TOOLS = {
    "discovery": ["read", "glob", "grep", "bash", "create_lead"],
    "verify": ["read", "glob", "grep", "bash", "trace", "update_lead"],
    "reproduce": ["read", "glob", "grep", "bash", "trace", "gates"],
}

# JSON schemas for the two board tools, in the same shape tools.py uses.
_CREATE_LEAD_SCHEMA = {
    "name": "create_lead",
    "description": (
        "Record a suspicious point as a Lead: one crash-related operation you "
        "believe could make the sanitizer-instrumented harness crash. Create "
        "one per distinct operation. The score reflects only what the code shows, "
        "not the bug's type or importance."),
    "input_schema": {
        "type": "object",
        "properties": {
            "function": {"type": "string", "description": "function holding the suspicious operation (the likely crash site)"},
            "description": {"type": "string", "description": "root cause + the crash class (name the class in the text, e.g. heap-buffer-overflow)"},
            "important_controlflow": {"type": "string", "description": "key functions/variables on the path to the bug, one per line"},
            "file": {"type": "string", "description": "file:line of the operation, if known"},
        },
        "required": ["function", "description"],
    },
}
_UPDATE_LEAD_SCHEMA = {
    "name": "update_lead",
    "description": (
        "Record your verification verdict on this Lead in one call: the "
        "confidence score, the concrete evidence (facts FOR and AGAINST, each "
        "with file:line or a trace result), and pov_guidance (a seed and how far "
        "it got). Score reflects only whether the bug is real and reachable by "
        "THIS harness+sanitizer, never how hard a PoC is."),
    "input_schema": {
        "type": "object",
        "properties": {
            "score": {"type": "number", "description": "0.0-1.0 confidence the bug is real and reachable"},
            "evidence": {"type": "string", "description": "facts established, FOR and AGAINST, each with where it came from"},
            "pov_guidance": {"type": "string", "description": "how to trigger it: a seed and the trace of how far that seed got"},
            "description": {"type": "string", "description": "corrected root-cause description, if the incoming one was imprecise"},
            "deepest_reached": {"type": "string", "description": "the deepest function a seed actually reached, if you ran trace"},
        },
        "required": ["score", "evidence"],
    },
}
_BOARD_SCHEMAS = {"create_lead": _CREATE_LEAD_SCHEMA, "update_lead": _UPDATE_LEAD_SCHEMA}


def build(role: str, board: LeadBoard, *, lead_id: str | None = None,
          origin: str = "", harness: str = "", sanitizer: str = "address"):
    """Return (schemas, runner) for `role`. `lead_id` is the Lead a verify /
    reproduce instance is working (create_lead ignores it). The runner sends
    board tools to `board` and everything else to tools.run_tool."""
    names = ROLE_TOOLS[role]
    builtin = {s["name"]: s for s in _tools.SCHEMAS}
    schemas = []
    for n in names:
        if n in _BOARD_SCHEMAS:
            schemas.append(_BOARD_SCHEMAS[n])
        elif n in builtin:
            schemas.append(builtin[n])

    def runner(name: str, args: dict) -> tuple[str, bool]:
        if name == "create_lead":
            fields = {k: v for k, v in args.items() if k in _DISCOVERY_FIELDS}
            fields.update(origin=origin, harness=harness, sanitizer=sanitizer)
            lead = board.create(**fields)
            return (f"created {lead.id} on {lead.function} "
                    f"[{lead.crash_class or 'unspecified'}]", False)
        if name == "update_lead":
            if not lead_id:
                return ("error: update_lead called with no Lead in scope", True)
            fields = {k: v for k, v in args.items() if k in _VERIFY_FIELDS}
            lead = board.update(lead_id, allowed=_VERIFY_FIELDS, **fields)
            return (f"updated {lead.id}: score={lead.score}", False)
        return _tools.run_tool(name, args)

    return schemas, runner


def make_runner(role: str, board: LeadBoard, **kw) -> Callable[[str, dict], tuple[str, bool]]:
    """Just the runner (schemas discarded), for tests."""
    return build(role, board, **kw)[1]
