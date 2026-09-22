# SPDX-License-Identifier: Apache-2.0
"""Context management beside the loop: the trajectory, the eviction store, and
the ledger. Ported from fbv2's BaseAgent (docs/CONTEXT_COMPRESSION_DESIGN.md)
onto this agent's message shape.

Three things the loop in agent.py leans on:

  Trajectory   the permanent record of a run, written as it happens -- every
               message the model produced or received, in full, plus one event
               per compaction saying what left the window and what the model
               saw instead. This is separate from `Agent.messages` (the context
               the model is sent), which compaction rewrites in place: the
               record is append-only and never compacted, so a crash verdict
               from step 12 is still there at step 400, and a run killed
               mid-flight has everything up to the kill.

  EvictStore   where an evicted tool result goes. Compaction is reversible: a
               large old result is moved out of the window to disk and a stub
               with its ref is left in its place; `recall(ref)` brings it back.
               A pure read (read / glob / grep / gates) is not stored -- the
               stub says to re-call the tool, which restores it for free.

  Ledger       the pinned facts. Deterministic extraction from the results
               whose shape we know (./submit verdicts, trace reports) plus what
               the model pins itself through `note`. Rendered as one user
               message right after the opening on every compaction, so what a
               summary would have destroyed stays in the window verbatim.

No summarizer model anywhere: everything here is mechanical, so nothing is
paraphrased and nothing is hallucinated.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

# --- Trajectory --------------------------------------------------------------

class Trajectory:
    """Append-only JSONL record of a run, flushed per record.

    `paths` are the files it tees to (the session archive, and for run.py the
    `.fbagent-trace.jsonl` the bench collects). With no paths it still keeps
    the in-memory `records`, which is what `Agent.trace()` reads. A write that
    fails is dropped, never raised: the record must never take down the run."""

    def __init__(self, paths=()):
        self.records: list[dict] = []
        self._fps = []
        self.paths: list[str] = []
        self._t0 = time.time()
        for p in paths or ():
            if not p:
                continue
            try:
                p = Path(p)
                p.parent.mkdir(parents=True, exist_ok=True)
                self._fps.append(p.open("a", buffering=1))
                self.paths.append(str(p))
            except OSError:
                pass

    def write(self, rec: dict) -> dict:
        rec = dict(rec)
        rec.setdefault("t", round(time.time() - self._t0, 1))
        self.records.append(rec)
        line = json.dumps(rec, default=str)
        for fp in self._fps:
            try:
                fp.write(line + "\n")
            except OSError:
                pass
        return rec

    def close(self) -> None:
        for fp in self._fps:
            try:
                fp.close()
            except OSError:
                pass
        self._fps = []


# --- Eviction store ------------------------------------------------------------

# Tools whose result is a pure function of the workspace: evicting one needs no
# storage, the model just calls it again. Everything else (bash: ./submit runs,
# builds, anything with a side effect; trace: a gdb run that cost 30-180s) is
# stored so recall() can restore it verbatim.
IDEMPOTENT_TOOLS = frozenset({"read", "glob", "grep", "gates", "diversify"})


class EvictStore:
    """Evicted tool results on disk, one file per ref. `None` dir = in-memory."""

    def __init__(self, directory=None):
        self.dir = Path(directory) if directory else None
        self._mem: dict[int, str] = {}
        self.seq = 0

    def store(self, content: str) -> int:
        self.seq += 1
        ref = self.seq
        if self.dir is not None:
            try:
                self.dir.mkdir(parents=True, exist_ok=True)
                (self.dir / f"{ref}.txt").write_text(content, encoding="utf-8")
                return ref
            except OSError:
                pass
        self._mem[ref] = content
        return ref

    def load(self, ref: int) -> str | None:
        if ref in self._mem:
            return self._mem[ref]
        if self.dir is not None:
            p = self.dir / f"{ref}.txt"
            if p.is_file():
                try:
                    return p.read_text(encoding="utf-8")
                except OSError:
                    return None
        return None


# --- Ledger ----------------------------------------------------------------

LEDGER_HEADER = "## LEDGER"
_LEDGER_MAX = 60          # entries; oldest non-crash, non-note entries go first
_FACT_CHARS = 400

_SUBMIT_RE = re.compile(r"\./submit\s+(\S+)")
_SUBMIT_CLASS = re.compile(r"crash: the harness faulted under the sanitizer \(([^)]*)\)")
_SUBMIT_FRAME = re.compile(r"^\s*#0\s+(\S+)\s+(\S+)", re.M)


class Ledger:
    """Key -> one-line fact. Insertion-ordered; a repeated key overwrites in
    place, so the ledger stays bounded and a later result on the same input
    supersedes the earlier one. Crash keys carry the signature, so a crash is
    never overwritten by a later clean run."""

    def __init__(self):
        self.facts: dict[str, str] = {}

    def __len__(self) -> int:
        return len(self.facts)

    def set(self, key: str, value: str) -> None:
        value = " ".join(str(value).split())[:_FACT_CHARS]
        if key in self.facts:
            del self.facts[key]          # move to the end: newest last
        self.facts[key] = value
        self._trim()

    def _trim(self) -> None:
        while len(self.facts) > _LEDGER_MAX:
            victim = next((k for k in self.facts
                           if not k.startswith(("submit:crash", "note:"))), None)
            if victim is None:
                victim = next(iter(self.facts))
            del self.facts[victim]

    def render(self) -> str:
        lines = [LEDGER_HEADER + " (verified facts, kept across context compaction; "
                 "newest last)"]
        lines += [f"- [{k}] {v}" for k, v in self.facts.items()]
        return "\n".join(lines)

    # -- deterministic extraction from results whose shape we know ----------
    def extract(self, tool: str, args: dict, output: str) -> None:
        """Pull the load-bearing facts out of one tool result. No model, no
        guessing: only fields of outputs whose format is ours (./submit's
        verdict, trace's report)."""
        out = output or ""
        if tool == "bash":
            m = _SUBMIT_RE.search(str((args or {}).get("command", "")))
            if not m:
                return
            path = m.group(1).strip("'\"")
            if "crash: the harness faulted" in out:
                cm = _SUBMIT_CLASS.search(out)
                fm = _SUBMIT_FRAME.search(out)
                klass = cm.group(1).strip() if cm else "fault"
                where = f"{fm.group(1)} {fm.group(2)}" if fm else "?"
                self.set(f"submit:crash:{klass}@{where.split()[0]}",
                         f"./submit {path} CRASHED: {klass} at {where}")
            elif out.lstrip().startswith("clean:"):
                first = out.strip().splitlines()[0]
                self.set(f"submit:clean:{path}", f"./submit {path} {first[:200]}")
        elif tool == "trace":
            path = str((args or {}).get("input", "?"))
            bits = []
            for ln in out.splitlines():
                s = ln.strip()
                if s.startswith(("outcome:", "deepest call:")):
                    bits.append(s)
                elif s.endswith("NOT reached") or " reached (" in s:
                    bits.append(s)
            if bits:
                self.set(f"trace:{path}", "; ".join(bits))
        elif tool == "note":
            key = str((args or {}).get("key", "")).strip()
            val = str((args or {}).get("value", "")).strip()
            if key and val:
                self.set(f"note:{key}", val)


# --- The two context tools the loop itself answers ---------------------------
# Descriptions are model-facing text and live in prompts/tools.yaml like every
# other tool's; the shape is here.

def context_tool_schemas() -> list[dict]:
    from .prompts import tool_description, tool_param

    def _p(tool, name, spec):
        line = tool_param(tool, name)
        return {**spec, "description": line} if line else dict(spec)

    return [
        {"name": "note",
         "description": tool_description("note"),
         "input_schema": {"type": "object",
                          "properties": {"key": _p("note", "key", {"type": "string"}),
                                         "value": _p("note", "value", {"type": "string"})},
                          "required": ["key", "value"]}},
        {"name": "recall",
         "description": tool_description("recall"),
         "input_schema": {"type": "object",
                          "properties": {"ref": _p("recall", "ref", {"type": "integer"})},
                          "required": ["ref"]}},
    ]
