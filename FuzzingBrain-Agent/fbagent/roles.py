# SPDX-License-Identifier: Apache-2.0
"""The three stages as functions over the shared Agent loop.

Each stage is an Agent instance with its own role prompt (prompts/roles/), tool
whitelist (hypothesis_tools), budget, and a first user message built from the VulnHypothesis.
Stages hand work to each other only through the HypothesisPool, never through a
shared conversation — so one stage's context never leaks into another's.

Basic version, ASan: reproduction is implemented here; verification and
discovery follow. A crash is a bug only when ./submit backs it (task contract),
whichever stage's tools produced it — so the outcome scanner reads the agent's
own tool trace for a submit crash and banks it on the VulnHypothesis.
"""
# Provenance: original. Stages hand off only through the HypothesisPool (never a
# shared conversation) — the Claude Code subagent pattern. Prompts adapted
# from fbv2 (see prompts/roles/ and PROVENANCE.md).
from __future__ import annotations

from pathlib import Path

from . import hypothesis_tools, store
from .agent import Agent
from .hypothesis import VulnHypothesis, HypothesisPool
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


def _hypothesis_brief(vh: VulnHypothesis) -> str:
    """The VulnHypothesis rendered as the first user message for verify / reproduce."""
    lines = [f"Bug hypothesis to work (VulnHypothesis {vh.id}):",
             f"- function: {vh.function}" + (f"  ({vh.file})" if vh.file else ""),
             f"- description: {vh.description}"]
    if vh.important_controlflow:
        lines.append(f"- key control flow:\n{vh.important_controlflow}")
    if vh.evidence:
        lines.append(f"- verifier evidence: {vh.evidence}")
    if vh.pov_guidance:
        lines.append(f"- pov guidance (seed + how far it got): {vh.pov_guidance}")
    return "\n".join(lines)


def _scan_outcome(agent: Agent, harness_names):
    """Read the finished agent's own tool trace for the run's outcome.

    Returns (signature|None, deepest_reached, best_candidate). A crash counts
    only from a ./submit verdict (task contract); trace crashes still have to be
    reproduced through submit, so we read the FIRST submit crash. On no crash we
    surface the deepest function any trace reported, for the VulnHypothesis's record."""
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


def run_discovery(*, llm, board: HypothesisPool, workspace: str = ".",
                  harness: str = "", sanitizer: str = "address",
                  deadline_s: float | None = None, max_usd: float = 0.0,
                  round_no: int = 1) -> dict:
    """Explore the reachable code from the harness and create hypotheses for the
    sanitizer's crash classes. Free-exploration mode (the model drives the read);
    a worklist can feed candidate functions later. Returns the hypotheses created.
    `round_no` names this round's session record (.fb/sessions/discovery-board-<n>)."""
    ws = Path(workspace)
    before = {ld.id for ld in board.all()}
    traj, ctx_dir = store.open_session(ws, "discovery", "board", round_no,
                                       {"harness": harness, "sanitizer": sanitizer})
    system = ("\n\n".join([_role_prompt("discovery"),
                           "## Sanitizer guidance (" + sanitizer + ")\n" + guidance_for(sanitizer),
                           "## Harness source\n\n" + harness_source(ws)]))
    schemas, runner = hypothesis_tools.build("discovery", board, origin="discovery/llm",
                                       harness=harness, sanitizer=sanitizer)
    agent = Agent(system, llm=llm, tools=schemas, tool_runner=runner,
                  deadline_s=deadline_s, max_usd=max_usd, min_spend_fraction=0.0,
                  traj=traj, evict_dir=ctx_dir)
    opening = ("Find the operations in this project's harness-reachable code that "
               "could crash the sanitizer, and record each as a VulnHypothesis with "
               "create_hypothesis. Start at the harness and follow the code it drives.")
    result = agent.run(opening)
    created = [ld.id for ld in board.all() if ld.id not in before]
    store.close_session(traj, {"stop_reason": result["stop_reason"], "steps": result["steps"],
                               "created": created, "compactions": result["compactions"],
                               "ledger": result.get("ledger")})
    return {"created": created, "n": len(created), "stop_reason": result["stop_reason"],
            "steps": result["steps"], "session": traj.paths[0] if traj.paths else None}


def run_verification(vh: VulnHypothesis, *, llm, board: HypothesisPool, workspace: str = ".",
                     deadline_s: float | None = None, max_usd: float = 0.0,
                     harness_names=None) -> dict:
    """Drive verification of `vh`: the agent reads + traces, records a verdict
    via update_hypothesis, and — since it holds bash + trace — may carry a crash. A
    submit-backed crash is banked straight away (skips reproduction). Returns
    the score and whether it crashed; the controller applies the >=0.5 gate."""
    ws = Path(workspace)
    rev0 = vh.rev          # snapshot: the board mutates the VulnHypothesis in place
    hnames = harness_names or ([vh.harness.rsplit("/", 1)[-1]] if vh.harness else [])
    java = _is_java(vh.sanitizer)
    system = _role_prompt("verify") + (_NO_TRACE_NOTE if java else "") \
        + "\n\n## Harness source\n\n" + harness_source(ws)
    schemas, runner = hypothesis_tools.build("verify", board, vh_id=vh.id,
                                       harness=vh.harness, sanitizer=vh.sanitizer,
                                       with_trace=not java)
    traj, ctx_dir = store.open_session(ws, "verify", vh.id, vh.attempts,
                                       {"function": vh.function})
    agent = Agent(system, llm=llm, tools=schemas, tool_runner=runner,
                  deadline_s=deadline_s, max_usd=max_usd, min_spend_fraction=0.0,
                  traj=traj, evict_dir=ctx_dir)
    result = agent.run(_hypothesis_brief(vh))
    sig, deepest, best, crash_text = _scan_outcome(agent, hnames)
    store.close_session(traj, {"stop_reason": result["stop_reason"], "crashed": bool(sig),
                               "steps": result["steps"], "compactions": result["compactions"],
                               "ledger": result.get("ledger")})
    if sig and sig.crash_class:
        stored = store.save_candidate(ws, vh.id, vh.attempts, best)
        store.save_crash(ws, sig.key, stored or best, crash_text, vh.id)
        board.record_crash(vh.id, sig.key, candidate=stored or best)
        store.ledger_append(ws, {"stage": "verify", "vh": vh.id, "crashed": True,
                                 "signature": sig.key})
        return {"vh": vh.id, "crashed": True, "signature": sig.key,
                "score": 1.0, "stop_reason": result["stop_reason"]}
    fresh = board.get(vh.id)
    # No verdict recorded -> recall-first: proceed (score defaults to 0, so lift
    # it to the gate) rather than silently dropping a VulnHypothesis the agent ran out on.
    score = fresh.score
    if fresh.rev == rev0:              # update_hypothesis never fired
        score = 0.5
        board.update(vh.id, allowed=None, score=score,
                     evidence="(verifier recorded no verdict; recall-first proceed)")
    if deepest and not fresh.deepest_reached:
        board.update(vh.id, allowed=None, deepest_reached=deepest)
    store.ledger_append(ws, {"stage": "verify", "vh": vh.id, "crashed": False,
                             "score": score, "deepest_reached": deepest})
    return {"vh": vh.id, "crashed": False, "score": score,
            "stop_reason": result["stop_reason"]}


def run_reproduction(vh: VulnHypothesis, *, llm, board: HypothesisPool, workspace: str = ".",
                     deadline_s: float | None = None, max_usd: float = 0.0,
                     harness_names=None) -> dict:
    """Drive one reproduction attempt on `vh`. Records a submit-backed crash
    (signature -> VulnHypothesis) or the deepest point reached, and returns a summary."""
    ws = Path(workspace)
    harness_names = harness_names or [vh.harness.rsplit("/", 1)[-1]] if vh.harness else []
    java = _is_java(vh.sanitizer)
    system = _role_prompt("reproduce") + (_NO_TRACE_NOTE if java else "") \
        + "\n\n## Harness source\n\n" + harness_source(ws)
    schemas, runner = hypothesis_tools.build("reproduce", board, vh_id=vh.id,
                                       harness=vh.harness, sanitizer=vh.sanitizer,
                                       with_trace=not java)
    attempt = vh.attempts + 1
    traj, ctx_dir = store.open_session(ws, "reproduce", vh.id, attempt,
                                       {"function": vh.function})
    agent = Agent(system, llm=llm, tools=schemas, tool_runner=runner,
                  deadline_s=deadline_s, max_usd=max_usd, min_spend_fraction=0.0,
                  traj=traj, evict_dir=ctx_dir)
    result = agent.run(_hypothesis_brief(vh))
    sig, deepest, best, crash_text = _scan_outcome(agent, harness_names)
    store.close_session(traj, {"stop_reason": result["stop_reason"], "crashed": bool(sig),
                               "steps": result["steps"], "compactions": result["compactions"],
                               "ledger": result.get("ledger")})
    if sig and sig.crash_class:
        stored = store.save_candidate(ws, vh.id, attempt, best)
        store.save_crash(ws, sig.key, stored or best, crash_text, vh.id)
        board.record_crash(vh.id, sig.key, candidate=stored or best)
        store.ledger_append(ws, {"stage": "reproduce", "vh": vh.id, "crashed": True,
                                 "signature": sig.key, "attempt": attempt})
        return {"vh": vh.id, "crashed": True, "signature": sig.key,
                "stop_reason": result["stop_reason"], "steps": result["steps"]}
    stored = store.save_candidate(ws, vh.id, attempt, best)
    board.update(vh.id, allowed=None, attempts=attempt,
                 deepest_reached=deepest or vh.deepest_reached,
                 best_candidate=stored or best)
    store.ledger_append(ws, {"stage": "reproduce", "vh": vh.id, "crashed": False,
                             "attempt": attempt, "deepest_reached": deepest})
    return {"vh": vh.id, "crashed": False, "deepest_reached": deepest,
            "stop_reason": result["stop_reason"], "steps": result["steps"]}
