#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read a session record: the trajectory one agent instance wrote.

    python3 tools/session.py <session.jsonl>              summary + step list
    python3 tools/session.py <session.jsonl> --step 37    everything at step 37, in full
    python3 tools/session.py <session.jsonl> --at 120     what the MODEL SAW going into
                                                          step 120 (the last compaction
                                                          snapshot at or before it, plus
                                                          every record appended since)
    python3 tools/session.py <session.jsonl> --ledger     the pinned facts, as last rendered

Works on ~/.fbagent/projects/<slug>/<uuid>.jsonl (run.py) and on
.fb/sessions/<role>-<lead>-<n>.jsonl (the three-stage roles) alike: the record
format is the same. The record is the permanent, un-compacted history; the
`--at` view is the compacted context, reconstructed from the snapshot the loop
wrote at each compaction (`context_snapshot` on the compaction event).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def _load(path: str) -> list[dict]:
    out = []
    for ln in Path(path).read_text().splitlines():
        ln = ln.strip()
        if ln:
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                pass
    return out


def _one_line(s: str, n: int = 100) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n - 1] + "…"


def summary(recs: list[dict]) -> None:
    meta = recs[0] if recs and recs[0].get("kind") == "meta" else {}
    end = recs[-1] if recs and recs[-1].get("kind") in ("end", "stop") else {}
    print("session:", meta.get("session") or f"{meta.get('role')}-{meta.get('lead')}-{meta.get('attempt')}")
    print("model:", meta.get("model"), "| stop:", end.get("stop_reason") or end.get("reason"),
          "| cost:", end.get("cost_usd"), "| compactions:", end.get("compactions"))
    kinds = Counter(r.get("kind") for r in recs)
    print("records:", dict(kinds))
    print()
    for r in recs:
        k = r.get("kind")
        step = r.get("step", "")
        if k == "tool_call":
            print(f"{step:>4}  call    {r.get('tool')}  {_one_line(json.dumps(r.get('input'), default=str))}")
        elif k == "tool_result":
            flag = "ERR " if r.get("is_error") else "    "
            print(f"{step:>4}  result  {flag}{r.get('tool')}  {len(r.get('output') or '')} chars"
                  f"  {_one_line(r.get('output') or '', 80)}")
        elif k == "text":
            print(f"{step:>4}  text    {_one_line(r.get('text') or '')}")
        elif k == "compaction":
            print(f"{step:>4}  COMPACT {r.get('trigger')}  reclaimed {r.get('reclaimed_chars')} chars,"
                  f" evicted refs {r.get('evicted_refs')}, ledger {len(r.get('ledger') or {})} facts")
        elif k in ("nudge", "continue", "progress_note"):
            print(f"{step:>4}  {k:<7} {_one_line(r.get('text') or '')}")


def step_view(recs: list[dict], step: int) -> None:
    for r in recs:
        if r.get("step") != step:
            continue
        k = r.get("kind")
        print(f"--- [{k}] " + ("-" * 60))
        if k == "tool_call":
            print(r.get("tool"), json.dumps(r.get("input"), indent=2, default=str))
        elif k == "tool_result":
            print(f"{r.get('tool')}  is_error={r.get('is_error')}  cost_usd={r.get('cost_usd')}")
            print(r.get("output"))
        elif k == "compaction":
            print(json.dumps({x: r.get(x) for x in ("trigger", "reclaimed_chars", "evicted_refs",
                                                     "context_chars", "context_snapshot")}, indent=2))
            for key, v in (r.get("ledger") or {}).items():
                print(f"  [{key}] {v}")
        else:
            print(r.get("text"))


def at_view(recs: list[dict], step: int) -> None:
    """The context going into `step`: the last snapshot at or before it, then
    the records appended after that snapshot up to `step` (exclusive)."""
    snaps = [r for r in recs if r.get("kind") == "compaction"
             and (r.get("step") or 0) <= step and r.get("context_snapshot")]
    base_step = 0
    if snaps:
        snap = snaps[-1]
        base_step = snap["step"]
        try:
            ctx = json.loads(Path(snap["context_snapshot"]).read_text())
        except OSError as e:
            print(f"(snapshot {snap['context_snapshot']} unreadable: {e})", file=sys.stderr)
            ctx = None
        if ctx:
            print(f"=== context snapshot taken at step {base_step} ({snap.get('trigger')}) ===")
            print("[system]", _one_line(ctx.get("system", ""), 200))
            for m in ctx.get("messages", []):
                c = m.get("content")
                if isinstance(c, str):
                    print(f"[{m['role']}] {c if c.startswith('## LEDGER') else _one_line(c, 200)}")
                else:
                    for b in c:
                        t = b.get("type")
                        if t == "tool_use":
                            print(f"[{m['role']}] tool_use {b.get('name')} {_one_line(json.dumps(b.get('input'), default=str), 120)}")
                        elif t == "tool_result":
                            print(f"[{m['role']}] tool_result {_one_line(str(b.get('content')), 160)}")
                        elif t == "text":
                            print(f"[{m['role']}] text {_one_line(b.get('text', ''), 160)}")
                        elif t == "thinking":
                            print(f"[{m['role']}] thinking ({len(b.get('thinking', ''))} chars)")
    else:
        print("=== no compaction before this step: the context is the record itself ===")
    print(f"=== records appended after step {base_step}, up to step {step} (verbatim) ===")
    for r in recs:
        s = r.get("step")
        if s is None or s <= base_step or s >= step:
            continue
        if r.get("kind") in ("compaction", "meta", "end", "stop"):
            continue
        k = r.get("kind")
        if k == "tool_result":
            print(f"[{s}] result {r.get('tool')}: {_one_line(r.get('output') or '', 160)}")
        elif k == "tool_call":
            print(f"[{s}] call {r.get('tool')} {_one_line(json.dumps(r.get('input'), default=str), 120)}")
        else:
            print(f"[{s}] {k}: {_one_line(r.get('text') or '', 160)}")


def ledger_view(recs: list[dict]) -> None:
    last = None
    for r in recs:
        if r.get("ledger"):
            last = r["ledger"]
    if not last:
        print("(no ledger recorded: the run never compacted and did not end with facts)")
        return
    for k, v in last.items():
        print(f"[{k}] {v}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("session")
    ap.add_argument("--step", type=int, help="print everything recorded at this step, in full")
    ap.add_argument("--at", type=int, help="reconstruct what the model saw going into this step")
    ap.add_argument("--ledger", action="store_true")
    a = ap.parse_args()
    recs = _load(a.session)
    if not recs:
        print("empty or unreadable session", file=sys.stderr)
        return 1
    if a.step is not None:
        step_view(recs, a.step)
    elif a.at is not None:
        at_view(recs, a.at)
    elif a.ledger:
        ledger_view(recs)
    else:
        summary(recs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
