# SPDX-License-Identifier: Apache-2.0
"""Per-role tool sets: a whitelist of the built-in navigation tools plus the
VulnHypothesis-board tools a stage needs, and a runner bound to one HypothesisPool.

Agent takes `tools` (the schema list it exposes) and `tool_runner` (who runs a
call); this module builds both for a given role, so one loop serves discovery,
verification and reproduction without the loop changing. The built-in tools
(read / glob / grep / bash / trace / gates) come from tools.py unchanged; the
VulnHypothesis tools (create_hypothesis / update_hypothesis) write to the board here, never touching
tools.py.

Tool sets (basic, ASan):
  discovery   : read glob grep bash + create_hypothesis
  verify      : read glob grep bash trace + update_hypothesis
  reproduce   : read glob grep bash trace gates          (no board tool; the
                controller banks a submit-backed crash on the VulnHypothesis itself)
"""
# Provenance: original. Per-agent isolated tool set follows Claude Code
# subagents / fbv2's per-agent MCP factory. See PROVENANCE.md.
from __future__ import annotations

from typing import Callable

from . import tools as _tools
from .hypothesis import _DISCOVERY_FIELDS, _VERIFY_FIELDS, HypothesisPool

ROLE_TOOLS = {
    "discovery": ["read", "glob", "grep", "bash", "create_hypothesis"],
    "verify": ["read", "glob", "grep", "bash", "trace", "update_hypothesis"],
    "reproduce": ["read", "glob", "grep", "bash", "trace", "gates"],
}

# JSON schemas for the two board tools, in the same shape tools.py uses.
_CREATE_HYPOTHESIS_SCHEMA = {
    "name": "create_hypothesis",
    "description": (
        "Record a suspicious point as a VulnHypothesis: one crash-related operation you "
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
_UPDATE_HYPOTHESIS_SCHEMA = {
    "name": "update_hypothesis",
    "description": (
        "Record your verification verdict on this VulnHypothesis in one call: the "
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
_BOARD_SCHEMAS = {"create_hypothesis": _CREATE_HYPOTHESIS_SCHEMA, "update_hypothesis": _UPDATE_HYPOTHESIS_SCHEMA}


def build(role: str, board: HypothesisPool, *, vh_id: str | None = None,
          origin: str = "", harness: str = "", sanitizer: str = "address",
          with_trace: bool = True):
    """Return (schemas, runner) for `role`. `vh_id` is the VulnHypothesis a verify /
    reproduce instance is working (create_hypothesis ignores it). The runner sends
    board tools to `board` and everything else to tools.run_tool.

    `with_trace=False` drops the gdb `trace` tool — it is C/C++ only, so a
    Java/Jazzer target does not offer it and leans on ./submit instead."""
    names = [n for n in ROLE_TOOLS[role] if with_trace or n != "trace"]
    builtin = {s["name"]: s for s in _tools.SCHEMAS}
    schemas = []
    for n in names:
        if n in _BOARD_SCHEMAS:
            schemas.append(_BOARD_SCHEMAS[n])
        elif n in builtin:
            schemas.append(builtin[n])

    def runner(name: str, args: dict) -> tuple[str, bool]:
        if name == "create_hypothesis":
            fields = {k: v for k, v in args.items() if k in _DISCOVERY_FIELDS}
            fields.update(origin=origin, harness=harness, sanitizer=sanitizer)
            vh = board.create(**fields)
            return (f"created {vh.id} on {vh.function} "
                    f"[{vh.crash_class or 'unspecified'}]", False)
        if name == "update_hypothesis":
            if not vh_id:
                return ("error: update_hypothesis called with no VulnHypothesis in scope", True)
            fields = {k: v for k, v in args.items() if k in _VERIFY_FIELDS}
            vh = board.update(vh_id, allowed=_VERIFY_FIELDS, **fields)
            return (f"updated {vh.id}: score={vh.score}", False)
        return _tools.run_tool(name, args)

    return schemas, runner


def make_runner(role: str, board: HypothesisPool, **kw) -> Callable[[str, dict], tuple[str, bool]]:
    """Just the runner (schemas discarded), for tests."""
    return build(role, board, **kw)[1]
