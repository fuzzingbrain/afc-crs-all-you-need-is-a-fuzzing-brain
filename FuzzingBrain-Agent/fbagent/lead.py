# SPDX-License-Identifier: Apache-2.0
"""The Lead: a bug hypothesis carried across discovery -> verification ->
reproduction, and LeadBoard, its append-only jsonl store.

A Lead is FuzzingBrain v2's SuspiciousPoint minus the multi-process claim
fields (worker_id / processor / direction_id): one process, one workspace,
serial, so a file is enough. Every mutation appends one full record to
``.fb/leads.jsonl``; the last record for an id is its current state. That makes
the file an audit log (nothing is overwritten), tail-able for progress, and
crash-safe (a killed run keeps every line already written).

Status machine (ASan-only basic version):

    pending_verify --verify, score>=0.5--> pending_pov --claim--> generating_pov --> pov_generated
          |               |                                            |
          |               `--trace crashed (submit-backed)-------------------------> pov_generated
          `-- score<0.5 --> rejected                                   `-- attempts>=N --> failed

Only the controller writes `status`; discovery writes new Leads, verification
enriches them. The board never decides a bug on its own — a crash counts only
after ``./submit`` backs it (task contract §0.0), whichever stage produced it.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

# The six lifecycle states. `status` only ever moves between these, controller-side.
PENDING_VERIFY = "pending_verify"
PENDING_POV = "pending_pov"
GENERATING_POV = "generating_pov"
POV_GENERATED = "pov_generated"
REJECTED = "rejected"
FAILED = "failed"
_STATES = {PENDING_VERIFY, PENDING_POV, GENERATING_POV, POV_GENERATED, REJECTED, FAILED}

# The crash-class words we recognise in a description, for dedup keying. ASan
# only in the basic version; the vocabulary widens with UBSan/jazzer later.
_CLASS_WORDS = (
    "heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
    "buffer-overflow", "use-after-free", "use-after-return", "use-after-scope",
    "double-free", "invalid-free", "out-of-bounds", "oob", "segv",
    "null-dereference", "null-pointer", "uninitialized", "overflow",
    "memory-leak", "memory leak", "leak",
    # Jazzer / JVM crash classes (an uncaught throwable or a Jazzer finding)
    "arrayindexoutofbounds", "stringindexoutofbounds", "indexoutofbounds",
    "classcastexception", "nullpointerexception", "numberformatexception",
    "arithmeticexception", "negativearraysize", "stackoverflow", "outofmemory",
    "assertionerror", "illegalstate", "illegalargument", "command injection",
    "server side request forgery", "ssrf", "path traversal", "deserialization",
    "sql injection", "regex injection",
)


def crash_class(text: str) -> str:
    """The coarse ASan crash class named in a description, for dedup. Longest
    match wins ('heap-buffer-overflow' before 'overflow'); '' if none named."""
    low = (text or "").lower()
    best = ""
    for w in _CLASS_WORDS:
        if w in low and len(w) > len(best):
            best = w
    return best


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class Lead:
    id: str
    harness: str = ""
    sanitizer: str = "address"
    function: str = ""
    file: str = ""
    description: str = ""                 # root cause + crash class (class lives here, not a field)
    important_controlflow: str = ""
    origin: str = ""                      # discovery/llm | discovery/worklist | diversify | crash-neighbor
    status: str = PENDING_VERIFY
    score: float = 0.0
    evidence: str = ""
    pov_guidance: str = ""
    attempts: int = 0
    spent_usd: float = 0.0
    deepest_reached: str = ""
    best_candidate: str = ""
    signature: str | None = None
    merged_from: list = field(default_factory=list)
    rev: int = 0
    ts: str = field(default_factory=_now)

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

    @property
    def crash_class(self) -> str:
        return crash_class(self.description)

    @property
    def dedup_key(self) -> tuple[str, str]:
        return (self.function, self.crash_class)


# Fields a role agent may set through a tool; everything else is controller-only.
_DISCOVERY_FIELDS = {"harness", "sanitizer", "function", "file", "description",
                     "important_controlflow", "origin"}
_VERIFY_FIELDS = {"score", "evidence", "pov_guidance", "description",
                  "important_controlflow", "deepest_reached"}


class LeadBoard:
    """Append-only jsonl store of Leads, rebuilt into memory on open."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._leads: dict[str, Lead] = {}
        self._seq = 0
        self._offset = 0          # bytes of the file already folded into memory
        self._load()

    # ---- persistence ------------------------------------------------------
    def _fold(self, text: str, external: bool = False) -> int:
        """Fold jsonl lines into memory. `external` lines (appended by someone
        other than this board -- an operator injecting a Lead with
        tools/add_lead.py, another process) only ADD unknown ids or ADOPT a
        record with a higher rev than the one held, so this board's own state
        is never rolled back by a stale line. Returns lines taken."""
        taken = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            lead = Lead(**{k: v for k, v in d.items() if k in Lead.__dataclass_fields__})
            held = self._leads.get(lead.id)
            if external and held is not None and lead.rev <= held.rev:
                continue
            self._leads[lead.id] = lead   # last line for an id wins
            taken += 1
            n = int(re.sub(r"\D", "", lead.id) or 0)
            self._seq = max(self._seq, n)
        return taken

    def _load(self) -> None:
        if not self.path.is_file():
            return
        text = self.path.read_text()
        self._fold(text)
        self._offset = len(text.encode("utf-8"))

    def _refresh(self) -> int:
        """Pick up lines appended to the file since we last read it: a Lead
        injected into a LIVE run (tools/add_lead.py) shows up on the next
        query, with no restart. Returns the number of records adopted."""
        try:
            size = self.path.stat().st_size
        except OSError:
            return 0
        if size <= self._offset:
            return 0
        with self.path.open("rb") as f:
            f.seek(self._offset)
            chunk = f.read()
        self._offset += len(chunk)
        return self._fold(chunk.decode("utf-8", errors="replace"), external=True)

    def _append(self, lead: Lead) -> None:
        lead.ts = _now()
        with self.path.open("a") as f:
            try:
                os.lockf(f.fileno(), os.F_LOCK, 0)
            except OSError:
                pass
            f.write(lead.to_json() + "\n")
            f.flush()
            try:
                self._offset = f.tell()   # our own line is already in memory
            except OSError:
                pass
        self._leads[lead.id] = lead

    # ---- mutation ---------------------------------------------------------
    def create(self, **fields) -> Lead:
        """Create a Lead, or merge into an existing one with the same
        (function, crash class). Returns the live Lead either way."""
        fields = {k: v for k, v in fields.items() if k in _DISCOVERY_FIELDS}
        key = (fields.get("function", ""), crash_class(fields.get("description", "")))
        if key[0]:
            for lead in self._leads.values():
                if lead.dedup_key == key:
                    origin = fields.get("origin")
                    if origin and origin not in lead.merged_from:
                        lead.merged_from.append(origin)
                        lead.rev += 1
                        self._append(lead)
                    return lead
        self._seq += 1
        lead = Lead(id=f"L{self._seq:02d}", **fields)
        self._append(lead)
        return lead

    def update(self, lead_id: str, *, allowed: set[str] | None = None, **fields) -> Lead:
        """Update fields on a Lead. `allowed` restricts which keys are honoured
        (verification passes _VERIFY_FIELDS); controller calls with allowed=None."""
        lead = self._leads[lead_id]
        keys = fields if allowed is None else {k: v for k, v in fields.items() if k in allowed}
        for k, v in keys.items():
            setattr(lead, k, v)
        lead.rev += 1
        self._append(lead)
        return lead

    def set_status(self, lead_id: str, status: str) -> Lead:
        if status not in _STATES:
            raise ValueError(f"unknown status: {status}")
        return self.update(lead_id, status=status)

    def record_crash(self, lead_id: str, signature: str, candidate: str = "") -> Lead:
        """A submit-backed crash landed on this Lead (from any stage/tool).
        Records the signature (and the crashing input, the PoV) and marks it
        solved."""
        lead = self._leads[lead_id]
        lead.signature = signature
        if candidate:
            lead.best_candidate = candidate
        lead.status = POV_GENERATED
        lead.rev += 1
        self._append(lead)
        return lead

    # ---- queries ----------------------------------------------------------
    def get(self, lead_id: str) -> Lead | None:
        self._refresh()
        return self._leads.get(lead_id)

    def all(self) -> list[Lead]:
        self._refresh()
        return list(self._leads.values())

    def by_status(self, status: str) -> list[Lead]:
        self._refresh()
        return [ld for ld in self._leads.values() if ld.status == status]

    def solved_signatures(self) -> set[str]:
        return {ld.signature for ld in self._leads.values() if ld.signature}

    def next_for_pov(self) -> "Lead | None":
        """The next Lead to attempt reproduction on. Basic ordering: highest
        score, then fewest attempts, then oldest. (Furthest-Point-First from the
        already-solved crashes — steering toward a distinct fault — is a later
        refinement that needs the call graph; score/attempts is enough to start.)"""
        pend = self.by_status(PENDING_POV)
        if not pend:
            return None
        return sorted(pend, key=lambda ld: (-ld.score, ld.attempts, ld.rev))[0]
