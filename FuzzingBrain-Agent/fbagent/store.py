# SPDX-License-Identifier: Apache-2.0
"""The `.fb/` run store — the on-disk artifacts the design's directory layout
calls for, beside the Lead board:

    .fb/leads.jsonl        the state board (lead.py owns this)
    .fb/ledger.jsonl       one line per stage outcome (this module)
    .fb/candidates/        <lead>-<n>.bin, the input a stage submitted
    .fb/crashes/<sig>/     input.bin + stderr.txt + meta.json, one per signature
    .fb/sessions/          <role>-<lead>-<n>.jsonl, each agent instance's full trace

Everything append-only or write-once, no database. Best-effort: a store failure
records a note and never takes a run down (the Lead board is the source of
truth; these are the audit trail beside it)."""
# Provenance: original. Layout from fbv2 research/proposal/agent-system-v2-zh.md
# §2 + Claude Code's per-project session store. See PROVENANCE.md.
from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path


def _fb(ws) -> Path:
    d = Path(ws) / ".fb"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sig_slug(signature: str) -> str:
    """A filesystem-safe directory name for a crash signature."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", signature or "unknown")[:120] or "unknown"


def session_paths(ws, role: str, lead_id: str, attempt: int) -> tuple[Path, Path]:
    """Where one agent instance's record lives:
        .fb/sessions/<role>-<lead>-<n>.jsonl   the trajectory (streamed)
        .fb/ctx/<role>-<lead>-<n>/             evicted results + context snapshots
    """
    name = f"{role}-{lead_id}-{attempt}"
    return _fb(ws) / "sessions" / f"{name}.jsonl", _fb(ws) / "ctx" / name


def open_session(ws, role: str, lead_id: str, attempt: int, meta: dict | None = None):
    """Start one agent instance's record: returns (Trajectory, evict_dir). The
    trajectory streams every message as it happens (see context.py), so the
    file is complete-so-far at any moment -- a run killed mid-flight keeps
    everything up to the kill, and compaction of the live context never touches
    it. The first line is a meta record naming the role, Lead and attempt."""
    from .context import Trajectory
    path, ctx = session_paths(ws, role, lead_id, attempt)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():           # a re-run of the same (role, lead, attempt)
            path.unlink()
    except OSError:
        pass
    traj = Trajectory([path])
    traj.write({"kind": "meta", "role": role, "lead": lead_id, "attempt": attempt,
                "ts": _now(), **(meta or {})})
    return traj, ctx


def close_session(traj, meta: dict) -> None:
    """The closing line of a session record: the outcome, once known."""
    try:
        traj.write({"kind": "end", "ts": _now(), **meta})
        traj.close()
    except Exception:  # noqa: BLE001
        pass


def archive_session(ws, role: str, lead_id: str, attempt: int, agent, meta: dict) -> str | None:
    """Write one agent instance's full trace in one go (an agent that was not
    given a streamed session): a meta line, then every record of agent.trace(),
    then an end line. Streamed sessions (open_session) do not need this."""
    try:
        path, _ = session_paths(ws, role, lead_id, attempt)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as f:
            f.write(json.dumps({"kind": "meta", "role": role, "lead": lead_id,
                                "attempt": attempt, "ts": _now(), **meta}) + "\n")
            for rec in agent.trace():
                f.write(json.dumps(rec, default=str) + "\n")
            f.write(json.dumps({"kind": "end", "ts": _now(), **meta}) + "\n")
        return str(path)
    except Exception as e:  # noqa: BLE001 — archiving must never fail a run
        return f"(session archive skipped: {e})"


def save_candidate(ws, lead_id: str, attempt: int, src_path: str) -> str:
    """Copy the input a stage submitted into .fb/candidates/<lead>-<n>.bin so the
    PoV survives beyond the agent's scratch path. Returns the stored path, or the
    original if the copy could not be made."""
    if not src_path:
        return ""
    try:
        src = Path(src_path)
        if not src.is_file():
            return src_path
        d = _fb(ws) / "candidates"
        d.mkdir(parents=True, exist_ok=True)
        dst = d / f"{lead_id}-{attempt}.bin"
        shutil.copyfile(src, dst)
        return str(dst)
    except Exception:  # noqa: BLE001
        return src_path


def save_crash(ws, signature: str, input_path: str, stderr_text: str, lead_id: str) -> str | None:
    """Archive a submit-backed crash under .fb/crashes/<sig>/: the crashing input,
    the verdict text the agent saw, and a meta.json. One directory per signature
    (a duplicate signature just overwrites, which is fine — it is the same bug)."""
    try:
        d = _fb(ws) / "crashes" / _sig_slug(signature)
        d.mkdir(parents=True, exist_ok=True)
        if input_path and Path(input_path).is_file():
            shutil.copyfile(input_path, d / "input.bin")
        (d / "stderr.txt").write_text(stderr_text or "")
        (d / "meta.json").write_text(json.dumps(
            {"signature": signature, "lead": lead_id, "ts": _now()}, indent=2))
        return str(d)
    except Exception as e:  # noqa: BLE001
        return f"(crash archive skipped: {e})"


def ledger_append(ws, record: dict) -> None:
    """Append one stage-outcome line to .fb/ledger.jsonl (the experiment log:
    which stage ran which Lead, what it produced). Append-only, tail-able."""
    try:
        rec = {"ts": _now(), **record}
        with (_fb(ws) / "ledger.jsonl").open("a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception:  # noqa: BLE001
        pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
