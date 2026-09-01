# SPDX-License-Identifier: Apache-2.0
"""Entry point: run the agent once, in whatever directory it is started in.

The bench (or a person) starts this in the staged challenge directory, where
`./submit` already exists. The agent reads the source, tests candidates through
submit, and stops. Scoring is not our job here — the bench grades the blobs
submit produced; this just drives the loop and prints what it did.

    python3 -m fbagent.run --timeout 900
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from fbagent.agent import Agent
from fbagent.llm import LLM
from fbagent.prompts import OPENING, SYSTEM


def _opening_with_recon(recon: list | None = None) -> str:
    """The opening message, with the deterministic recon prepended.

    Before the model reads a line, the static substrate (analysis.py) has already
    built a call graph from the harness entry, pre-screened the source for sink
    patterns, and ranked the sinks the entry can actually reach by call-graph
    distance. That worklist is handed to the model up front so it starts from a
    computed set of targets instead of an unguided read. A failure here never
    stops the run -- the model just gets the plain opening and reads for itself.

    `recon`, if given, is filled with the generation trace (how the worklist was
    computed — files scanned, entry found or not, graph size, reachability) so a
    reader can audit not just the worklist but how it was produced.
    """
    from pathlib import Path
    try:
        from fbagent import analysis
        out = analysis.analyze(Path.cwd(), recon=recon)
        if out.get("entry") and out.get("reachable_sinks"):
            return (
                "Before you start, a deterministic static analysis of this "
                "challenge has already been run for you. Treat it as a computed "
                "worklist of where to look -- not as confirmed bugs.\n\n"
                + out["summary"]
                + "\n\nThree deterministic tools back this up: `gates <func>` gives "
                "the literal input constraints (magic bytes, lengths) on the path "
                "to a function, so you can build a seed that reaches it; `reached "
                "<stack>` maps a crash stack back onto this graph so you know "
                "where your input actually went; `diversify <crashed funcs>` names "
                "the reachable sinks furthest from what you already cracked, so your "
                "next crash is a different one. Use them.\n\n"
                "--- your task ---\n" + OPENING)
    except Exception as e:
        if recon is not None:
            recon.append({"kind": "recon", "phase": "error", "note": repr(e)})
    return OPENING


def _project_slug(cwd) -> str:
    """The working directory as a flat folder name, the way Claude Code slugs a
    project: the absolute path with every separator turned to '-'. Runs from the
    same directory land in the same project folder, whatever the task."""
    from pathlib import Path
    return str(Path(cwd).resolve()).replace("/", "-").replace("\\", "-")


def _archive(records: list, result: dict, llm, agent) -> str | None:
    """Persist this run the way Claude Code persists a session — the agent's own
    store, not the harness's, written for *every* run whatever the task:

        ~/.fbagent/projects/<project-slug>/<session-uuid>.jsonl

    one JSONL file per session, keyed by a fresh UUID, under a folder named for
    the working directory. The first line is a meta record (model, budgets,
    cost, outcome); the rest are the full transcript — system, opening, every
    step. Best-effort: a failure here never fails the run, and the root is
    overridable with FBAGENT_HOME. Returns the file path, or None on failure."""
    import os
    import uuid
    from datetime import datetime, timezone
    from pathlib import Path
    try:
        home = Path(os.environ.get("FBAGENT_HOME") or (Path.home() / ".fbagent"))
        proj = home / "projects" / _project_slug(Path.cwd())
        proj.mkdir(parents=True, exist_ok=True)
        sid = str(uuid.uuid4())
        meta = {"kind": "meta", "session": sid, "cwd": str(Path.cwd().resolve()),
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "model": llm.model, "effort": getattr(llm, "effort", None),
                "reasoning": getattr(llm, "reasoning", None),
                "stop_reason": result.get("stop_reason"), "steps": result.get("steps"),
                "cost_usd": round(llm.cost_usd, 4),
                "cache_hit_rate": result.get("cache_hit_rate"), "usage": result.get("usage"),
                "budgets": {"max_steps": agent.max_steps, "max_tokens": agent.max_tokens,
                            "max_usd": agent.max_usd}}
        path = proj / f"{sid}.jsonl"
        with path.open("w") as f:
            f.write(json.dumps(meta) + "\n")
            for rec in records:
                f.write(json.dumps(rec) + "\n")
        return str(path)
    except Exception as e:  # noqa: BLE001 — archiving must never take the run down
        print(f"[archive] skipped: {e}", file=sys.stderr)
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    # The budgets: time, steps, tokens, dollars. Any one that trips ends the
    # run; a zero turns one off. Time is what the bench sets and what binds by
    # default; the rest are off unless asked for, so a run is not guillotined
    # before the wall clock it was given. --max-usd defaults from the
    # FBAGENT_MAX_USD env var, which is how the bench passes a per-cell cap.
    ap.add_argument("--timeout", type=int, default=900, help="wall clock, seconds")
    ap.add_argument("--max-steps", type=int, default=0, help="loop steps, 0 = no cap")
    ap.add_argument("--max-tokens", type=int, default=0,
                    help="total tokens (sent + generated + cached), 0 = no cap")
    ap.add_argument("--max-usd", type=float,
                    default=float(os.environ.get("FBAGENT_MAX_USD", "0") or 0),
                    help="spend cap in USD, 0 = no cap (env: FBAGENT_MAX_USD)")
    ap.add_argument("--model", default=None)
    args = ap.parse_args()

    llm = LLM(model=args.model) if args.model else LLM()
    agent = Agent(SYSTEM, llm=llm, max_steps=args.max_steps,
                  max_tokens=args.max_tokens, max_usd=args.max_usd,
                  deadline_s=args.timeout)

    recon: list = []
    opening = _opening_with_recon(recon)
    result = agent.run(opening)

    # The complete trajectory: the system prompt, then the recon generation trace
    # (how the worklist was computed — files, entry, graph, reachability), then
    # the opening the model actually saw, then every step un-truncated. Leading
    # with system + recon + opening is what lets a reader audit not just what the
    # agent did but the ground it was handed and how that ground was produced.
    records = [{"step": 0, "kind": "system", "text": SYSTEM}]
    records += recon
    records += [{"step": 0, "kind": "opening", "text": opening}]
    records += agent.trace(max_chars=20000)

    # The agent's own archive — like Claude Code's session store, it is the
    # agent's, not the harness's, and it happens for every run whatever the task:
    # ~/.fbagent/projects/<project-slug>/<session-uuid>.jsonl.
    session_path = _archive(records, result, llm, agent)

    # The bench copies whatever the agent leaves at `.fbagent-trace.jsonl` out to
    # the cell as trace.jsonl, so the same complete record also goes there — no
    # bench change needed, it just preserves the file the agent already writes.
    from pathlib import Path
    with (Path.cwd() / ".fbagent-trace.jsonl").open("w") as tf:
        for rec in records:
            tf.write(json.dumps(rec) + "\n")

    # A compact record to stdout; the bench keeps this as the agent log.
    print(agent.transcript_text())
    print("\n" + "=" * 60)
    print(json.dumps({
        "stop_reason": result["stop_reason"],
        "steps": result["steps"],
        "cost_usd": round(llm.cost_usd, 4),
        "cache_hit_rate": result["cache_hit_rate"],
        "usage": result["usage"],
        "archived_to": session_path,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
