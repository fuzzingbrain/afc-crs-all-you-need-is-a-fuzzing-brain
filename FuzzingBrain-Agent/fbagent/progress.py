# SPDX-License-Identifier: Apache-2.0
"""A live, tailable record of what the agent is doing, written as it happens.

Everything else this agent produces is post-hoc. `_archive` writes the session
store after the loop returns, and the bench's external arm writes the whole cell
-- transcript, score, cost -- only once the agent process exits. So a run in
flight is invisible: `ps` says it is alive and nothing else is knowable until it
is over. A 30-minute cell that was never going to work looks exactly like one
that is about to score, and you pay for both.

This module is the missing half. One JSON line per step, flushed immediately, so
`tail -f` shows the run as it goes and a bad idea can be killed in the first two
minutes instead of the thirtieth.

Cheap by construction: one short line per step against a run that already sends
tens of thousands of tokens per step, and every failure is swallowed -- a
progress log must never be able to take down the run it is reporting on.

    FBAGENT_PROGRESS=/path/to/file.jsonl   explicit destination
    FBAGENT_PROGRESS=0                     off
    (default)                              ~/.fbagent/progress/<session>.jsonl
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

_fp = None
_path: str | None = None
_t0 = time.time()
_disabled = False


def start(session: str, meta: dict) -> str | None:
    """Open the log and write the header. Returns the path, or None if off."""
    global _fp, _path, _t0, _disabled
    setting = os.environ.get("FBAGENT_PROGRESS", "")
    if setting.strip().lower() in ("0", "off", "false", "no"):
        _disabled = True
        return None
    try:
        if setting.strip():
            p = Path(setting)
        else:
            home = Path(os.environ.get("FBAGENT_HOME") or (Path.home() / ".fbagent"))
            p = home / "progress" / f"{session}.jsonl"
        p.parent.mkdir(parents=True, exist_ok=True)
        _fp = p.open("w", buffering=1)          # line buffered
        _path = str(p)
        _t0 = time.time()
        emit("start", **meta)
        # Say where it is on stderr too: the bench captures that into agent.log,
        # and a human running the agent directly sees it immediately.
        print(f"[progress] {_path}", file=sys.stderr, flush=True)
        return _path
    except Exception:  # noqa: BLE001
        _disabled = True
        return None


def emit(kind: str, **fields) -> None:
    """Append one record. Never raises."""
    if _disabled or _fp is None:
        return
    try:
        rec = {"t": round(time.time() - _t0, 1), "kind": kind}
        rec.update(fields)
        _fp.write(json.dumps(rec, default=str) + "\n")
        _fp.flush()
    except Exception:  # noqa: BLE001
        pass


def step(n: int, cost: float, tools: list[str], verdicts: list[str],
         note: str | None = None) -> None:
    """The per-step line: what it called, what came back, what it costs so far.

    `verdicts` are the graded outcomes seen this step (`crash: <sig>` /
    `clean: ... N ms ...`), which is the single most useful thing to watch --
    it is the difference between an agent making progress and one spraying.
    """
    emit("step", n=n, usd=round(cost, 4), tools=tools,
         verdicts=verdicts, note=note)


def finish(stop_reason: str, steps: int, cost: float) -> None:
    emit("end", stop_reason=stop_reason, steps=steps, usd=round(cost, 4))
    try:
        if _fp is not None:
            _fp.close()
    except Exception:  # noqa: BLE001
        pass


def path() -> str | None:
    return _path
