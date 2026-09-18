# SPDX-License-Identifier: Apache-2.0
"""The three stages as functions over the shared Agent loop.

Each stage is an Agent instance with its own role prompt (prompts/roles/), tool
whitelist (lead_tools), budget, and a first user message built from the Lead.
Stages hand work to each other only through the LeadBoard, never through a
shared conversation — so one stage's context never leaks into another's.

Basic version, ASan: reproduction is implemented here; verification and
discovery follow. A crash is a bug only when ./submit backs it (task contract),
whichever stage's tools produced it — so the outcome scanner reads the agent's
own tool trace for a submit crash and banks it on the Lead.
"""
# Provenance: original. Stages hand off only through the LeadBoard (never a
# shared conversation) — the Claude Code subagent pattern. Prompts adapted
# from fbv2 (see prompts/roles/ and PROVENANCE.md).
from __future__ import annotations

from pathlib import Path

from . import lead_tools, store
from .agent import Agent
from .lead import Lead, LeadBoard
from .sanitizer_guidance import guidance_for
from .signature import is_submit_crash, signature_from_submit

_PROMPT_DIR = Path(__file__).resolve().parent.parent / "prompts" / "roles"
_HARNESS_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".java", ".in"}


def _role_prompt(name: str) -> str:
    return (_PROMPT_DIR / f"{name}.md").read_text().strip()


def _is_java(sanitizer: str) -> bool:
    """A Jazzer/JVM target: no sanitizer-instrumented binary and no gdb trace,
    so the trace tool is dropped and ./submit is the only dynamic feedback."""
    s = (sanitizer or "").lower()
    return "jazzer" in s or "jvm" in s or "java" in s


_NO_TRACE_NOTE = (
    "\n\n## Note for this target\n\nThis is a Java/Jazzer target: there is no "
    "gdb `trace` tool here. Confirm reachability by reading the Java call path "
    "and by running `./submit`.")


def harness_source(workspace: Path, limit_bytes: int = 200_000) -> str:
    """Every file under harness/, concatenated with a path banner each — the
    thing that defines the input format. Cached in the system prompt (see the
    'harness full, never truncate' rule); the cap is a last-resort guard against
    a pathological tree, not routine truncation."""
    hdir = Path(workspace) / "harness"
    if not hdir.is_dir():
        return "(no harness/ directory found)"
    parts, total = [], 0
    for p in sorted(hdir.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in _HARNESS_EXT:
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        rel = p.relative_to(workspace)
        parts.append(f"===== {rel} =====\n{text}")
        total += len(text)
        if total > limit_bytes:
            break
    return "\n\n".join(parts) if parts else "(no harness source found)"


def _lead_brief(lead: Lead) -> str:
    """The Lead rendered as the first user message for verify / reproduce."""
    lines = [f"Bug hypothesis to work (Lead {lead.id}):",
             f"- function: {lead.function}" + (f"  ({lead.file})" if lead.file else ""),
             f"- description: {lead.description}"]
    if lead.important_controlflow:
        lines.append(f"- key control flow:\n{lead.important_controlflow}")
    if lead.evidence:
        lines.append(f"- verifier evidence: {lead.evidence}")
    if lead.pov_guidance:
        lines.append(f"- pov guidance (seed + how far it got): {lead.pov_guidance}")
    return "\n".join(lines)


def _scan_outcome(agent: Agent, harness_names):
    """Read the finished agent's own tool trace for the run's outcome.

    Returns (signature|None, deepest_reached, best_candidate). A crash counts
    only from a ./submit verdict (task contract); trace crashes still have to be
    reproduced through submit, so we read the FIRST submit crash. On no crash we
    surface the deepest function any trace reported, for the Lead's record."""
    signature = None
    deepest = ""
    best_candidate = ""
    crash_text = ""
    last_submit_path = ""
    for rec in agent.trace():
        kind = rec.get("kind")
        if kind == "tool_call" and rec.get("tool") == "bash":
            cmd = (rec.get("input") or {}).get("command", "")
            m = _submit_path(cmd)
            if m:
                last_submit_path = m
        elif kind == "tool_result" and rec.get("tool") == "bash":
            out = rec.get("output", "")
            if signature is None and is_submit_crash(out):
                signature = signature_from_submit(out, harness_names=harness_names)
                best_candidate = last_submit_path
                crash_text = out
        elif kind == "tool_result" and rec.get("tool") == "trace":
            d = _deepest_from_trace(rec.get("output", ""))
            if d:
                deepest = d      # keep the last (typically deepest attempt)
    return signature, deepest, best_candidate, crash_text


def _submit_path(command: str) -> str:
    """The candidate path in a `./submit <file>` command, if this is one."""
    import re
    m = re.search(r"\./submit\s+(\S+)", command or "")
    return m.group(1).strip("'\"") if m else ""


def _deepest_from_trace(output: str) -> str:
    """The 'deepest call: <fn> (...)' line trace prints, if present."""
    import re
    m = re.search(r"deepest call:\s*(.+)", output or "")
    return m.group(1).strip() if m else ""


def run_discovery(*, llm, board: LeadBoard, workspace: str = ".",
                  harness: str = "", sanitizer: str = "address",
                  deadline_s: float | None = None, max_usd: float = 0.0) -> dict:
    """Explore the reachable code from the harness and create Leads for the
    sanitizer's crash classes. Free-exploration mode (the model drives the read);
    a worklist can feed candidate functions later. Returns the Leads created."""
    ws = Path(workspace)
    before = {ld.id for ld in board.all()}
    system = ("\n\n".join([_role_prompt("discovery"),
                           "## Sanitizer guidance (" + sanitizer + ")\n" + guidance_for(sanitizer),
                           "## Harness source\n\n" + harness_source(ws)]))
    schemas, runner = lead_tools.build("discovery", board, origin="discovery/llm",
                                       harness=harness, sanitizer=sanitizer)
    agent = Agent(system, llm=llm, tools=schemas, tool_runner=runner,
                  deadline_s=deadline_s, max_usd=max_usd, min_spend_fraction=0.0)
    opening = ("Find the operations in this project's harness-reachable code that "
               "could crash the sanitizer, and record each as a Lead with "
               "create_lead. Start at the harness and follow the code it drives.")
    result = agent.run(opening)
    created = [ld.id for ld in board.all() if ld.id not in before]
    return {"created": created, "n": len(created), "stop_reason": result["stop_reason"],
            "steps": result["steps"]}


def run_verification(lead: Lead, *, llm, board: LeadBoard, workspace: str = ".",
                     deadline_s: float | None = None, max_usd: float = 0.0,
                     harness_names=None) -> dict:
    """Drive verification of `lead`: the agent reads + traces, records a verdict
    via update_lead, and — since it holds bash + trace — may carry a crash. A
    submit-backed crash is banked straight away (skips reproduction). Returns
    the score and whether it crashed; the controller applies the >=0.5 gate."""
    ws = Path(workspace)
    rev0 = lead.rev          # snapshot: the board mutates the Lead in place
    hnames = harness_names or ([lead.harness.rsplit("/", 1)[-1]] if lead.harness else [])
    java = _is_java(lead.sanitizer)
    system = _role_prompt("verify") + (_NO_TRACE_NOTE if java else "") \
        + "\n\n## Harness source\n\n" + harness_source(ws)
    schemas, runner = lead_tools.build("verify", board, lead_id=lead.id,
                                       harness=lead.harness, sanitizer=lead.sanitizer,
                                       with_trace=not java)
    agent = Agent(system, llm=llm, tools=schemas, tool_runner=runner,
                  deadline_s=deadline_s, max_usd=max_usd, min_spend_fraction=0.0)
    result = agent.run(_lead_brief(lead))
    sig, deepest, best, crash_text = _scan_outcome(agent, hnames)
    store.archive_session(ws, "verify", lead.id, lead.attempts, agent,
                          {"stop_reason": result["stop_reason"], "crashed": bool(sig)})
    if sig and sig.crash_class:
        stored = store.save_candidate(ws, lead.id, lead.attempts, best)
        store.save_crash(ws, sig.key, stored or best, crash_text, lead.id)
        board.record_crash(lead.id, sig.key, candidate=stored or best)
        store.ledger_append(ws, {"stage": "verify", "lead": lead.id, "crashed": True,
                                 "signature": sig.key})
        return {"lead": lead.id, "crashed": True, "signature": sig.key,
                "score": 1.0, "stop_reason": result["stop_reason"]}
    fresh = board.get(lead.id)
    # No verdict recorded -> recall-first: proceed (score defaults to 0, so lift
    # it to the gate) rather than silently dropping a Lead the agent ran out on.
    score = fresh.score
    if fresh.rev == rev0:              # update_lead never fired
        score = 0.5
        board.update(lead.id, allowed=None, score=score,
                     evidence="(verifier recorded no verdict; recall-first proceed)")
    if deepest and not fresh.deepest_reached:
        board.update(lead.id, allowed=None, deepest_reached=deepest)
    store.ledger_append(ws, {"stage": "verify", "lead": lead.id, "crashed": False,
                             "score": score, "deepest_reached": deepest})
    return {"lead": lead.id, "crashed": False, "score": score,
            "stop_reason": result["stop_reason"]}


def run_reproduction(lead: Lead, *, llm, board: LeadBoard, workspace: str = ".",
                     deadline_s: float | None = None, max_usd: float = 0.0,
                     harness_names=None) -> dict:
    """Drive one reproduction attempt on `lead`. Records a submit-backed crash
    (signature -> Lead) or the deepest point reached, and returns a summary."""
    ws = Path(workspace)
    harness_names = harness_names or [lead.harness.rsplit("/", 1)[-1]] if lead.harness else []
    java = _is_java(lead.sanitizer)
    system = _role_prompt("reproduce") + (_NO_TRACE_NOTE if java else "") \
        + "\n\n## Harness source\n\n" + harness_source(ws)
    schemas, runner = lead_tools.build("reproduce", board, lead_id=lead.id,
                                       harness=lead.harness, sanitizer=lead.sanitizer,
                                       with_trace=not java)
    attempt = lead.attempts + 1
    agent = Agent(system, llm=llm, tools=schemas, tool_runner=runner,
                  deadline_s=deadline_s, max_usd=max_usd, min_spend_fraction=0.0)
    result = agent.run(_lead_brief(lead))
    sig, deepest, best, crash_text = _scan_outcome(agent, harness_names)
    store.archive_session(ws, "reproduce", lead.id, attempt, agent,
                          {"stop_reason": result["stop_reason"], "crashed": bool(sig)})
    if sig and sig.crash_class:
        stored = store.save_candidate(ws, lead.id, attempt, best)
        store.save_crash(ws, sig.key, stored or best, crash_text, lead.id)
        board.record_crash(lead.id, sig.key, candidate=stored or best)
        store.ledger_append(ws, {"stage": "reproduce", "lead": lead.id, "crashed": True,
                                 "signature": sig.key, "attempt": attempt})
        return {"lead": lead.id, "crashed": True, "signature": sig.key,
                "stop_reason": result["stop_reason"], "steps": result["steps"]}
    stored = store.save_candidate(ws, lead.id, attempt, best)
    board.update(lead.id, allowed=None, attempts=attempt,
                 deepest_reached=deepest or lead.deepest_reached,
                 best_candidate=stored or best)
    store.ledger_append(ws, {"stage": "reproduce", "lead": lead.id, "crashed": False,
                             "attempt": attempt, "deepest_reached": deepest})
    return {"lead": lead.id, "crashed": False, "deepest_reached": deepest,
            "stop_reason": result["stop_reason"], "steps": result["steps"]}
