"""The run's record: one SQLite file plus an append-only event stream.

    <run>/fbv3.sqlite   sessions, harness rounds, harnesses, VHs, crashes, seeds, coverage
    <run>/events.jsonl  one JSON line per write, in order

SQLite is the source of truth; ``events.jsonl`` is the same history as a
stream (``tail -f`` it during a run). The interface is small on purpose: a
different backend (PostgreSQL, as FBv2 uses) is one class with the same
methods.

Thread-safe: the directed scheduler writes from many threads.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

VH_STATUSES = (
    "pending_verify", "verifying", "rejected",
    "pending_poc", "generating_poc", "poc_generated", "poc_failed",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, task TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'running', end_reason TEXT, error TEXT,
  started_at REAL NOT NULL, ended_at REAL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, scope TEXT NOT NULL, role TEXT NOT NULL, backend TEXT NOT NULL,
  subject TEXT, status TEXT NOT NULL, turns INTEGER, duration_s REAL, error TEXT,
  usage TEXT, session_dir TEXT, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS harness_rounds (
  id TEXT PRIMARY KEY, target TEXT NOT NULL, round INTEGER NOT NULL,
  overlay TEXT, binary TEXT, source_path TEXT,
  build_ok INTEGER, gate TEXT, review TEXT, verdict TEXT,
  generator_session TEXT, reviewer_session TEXT, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS harnesses (
  target TEXT PRIMARY KEY, status TEXT NOT NULL, overlay TEXT, binary TEXT,
  source_path TEXT, builds TEXT, rounds INTEGER, notes TEXT, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS vhs (
  id TEXT PRIMARY KEY, lg TEXT NOT NULL, function_name TEXT NOT NULL, function_file TEXT,
  description TEXT, finder_score REAL, important_controlflow TEXT, sink_code TEXT, sink_line INTEGER,
  status TEXT NOT NULL CHECK (status IN ('pending_verify','verifying','rejected','pending_poc',
                                         'generating_poc','poc_generated','poc_failed')),
  score REAL, evidence TEXT, verification_notes TEXT, poc_guidance TEXT,
  poc_status TEXT, poc_blob TEXT, crash_id TEXT,
  finder_session TEXT, verifier_session TEXT, poc_sessions TEXT, fp_seed_session TEXT,
  created_at REAL NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS vh_events (
  vh_id TEXT NOT NULL, ts REAL NOT NULL, from_status TEXT, to_status TEXT,
  session TEXT, reason TEXT
);
CREATE TABLE IF NOT EXISTS crashes (
  id TEXT PRIMARY KEY, lg TEXT NOT NULL, signature TEXT NOT NULL, signature_short TEXT NOT NULL,
  crash_class TEXT, source TEXT, vh_id TEXT, artifact TEXT, top_frames TEXT, cycle TEXT, output_tail TEXT,
  created_at REAL NOT NULL, UNIQUE (lg, signature_short)
);
CREATE TABLE IF NOT EXISTS seeds (
  lg TEXT NOT NULL, session TEXT, role TEXT, sha1 TEXT NOT NULL, size INTEGER,
  corpus TEXT, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS coverage (
  lg TEXT NOT NULL, t REAL NOT NULL, edges INTEGER, features INTEGER, exec_s INTEGER,
  corpus INTEGER, functions_covered INTEGER
);
"""


def _now() -> float:
    return time.time()


class Store:
    def __init__(self, run_dir: Path):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.run_dir / "fbv3.sqlite"
        self.events = self.run_dir / "events.jsonl"
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self.run_id = ""

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- plumbing -------------------------------------------------------------------

    def _x(self, sql: str, args: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, tuple(args))

    def _rows(self, sql: str, args: Iterable[Any] = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, tuple(args)).fetchall()]

    def emit(self, event: str, **fields: Any) -> None:
        rec = {"ts": round(_now(), 3), "event": event, **{k: v for k, v in fields.items() if v is not None}}
        line = json.dumps(rec, default=str, ensure_ascii=False) + "\n"
        with self._lock, self.events.open("a", encoding="utf-8") as fh:
            fh.write(line)

    # -- run --------------------------------------------------------------------------

    def start_run(self, name: str, task: dict) -> str:
        self.run_id = uuid.uuid4().hex
        self._x("INSERT INTO runs (id, name, task, started_at) VALUES (?,?,?,?)",
                (self.run_id, name, json.dumps(task), _now()))
        self.emit("run_started", run_id=self.run_id, name=name)
        return self.run_id

    def end_run(self, status: str, end_reason: str = "", error: str = "") -> None:
        self._x("UPDATE runs SET status=?, end_reason=?, error=?, ended_at=? WHERE id=?",
                (status, end_reason or None, error or None, _now(), self.run_id))
        self.emit("run_ended", run_id=self.run_id, status=status, end_reason=end_reason or None,
                  error=error[:500] if error else None)

    def run(self) -> dict:
        rows = self._rows("SELECT * FROM runs WHERE id=?", (self.run_id,))
        return rows[0] if rows else {}

    # -- sessions -----------------------------------------------------------------------

    def record_session(self, result, scope: str, subject: str = "") -> None:
        self._x(
            "INSERT OR REPLACE INTO sessions (id, scope, role, backend, subject, status, turns, duration_s,"
            " error, usage, session_dir, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (result.session_id, scope, result.role, result.backend, subject, result.status, result.turns,
             result.duration_s, result.error[:2000], json.dumps(result.usage), result.session_dir, _now()),
        )
        self.emit("session", session_id=result.session_id, scope=scope, role=result.role,
                  backend=result.backend, subject=subject or None, status=result.status,
                  turns=result.turns, duration_s=result.duration_s, error=result.error[:300] or None)

    def sessions(self, scope: str | None = None) -> list[dict]:
        if scope is None:
            return self._rows("SELECT * FROM sessions ORDER BY created_at")
        return self._rows("SELECT * FROM sessions WHERE scope=? ORDER BY created_at", (scope,))

    # -- harness generation ------------------------------------------------------------------

    def add_harness_round(self, target: str, round_no: int, **f: Any) -> str:
        rid = uuid.uuid4().hex[:12]
        self._x(
            "INSERT INTO harness_rounds (id, target, round, overlay, binary, source_path, build_ok, gate,"
            " review, verdict, generator_session, reviewer_session, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, target, round_no, f.get("overlay"), f.get("binary"), f.get("source_path"),
             None if f.get("build_ok") is None else int(bool(f["build_ok"])),
             json.dumps(f.get("gate")) if f.get("gate") is not None else None,
             json.dumps(f.get("review")) if f.get("review") is not None else None,
             f.get("verdict"), f.get("generator_session"), f.get("reviewer_session"), _now()),
        )
        self.emit("harness_round", target=target, round=round_no, verdict=f.get("verdict"),
                  build_ok=f.get("build_ok"))
        return rid

    def harness_rounds(self, target: str) -> list[dict]:
        return self._rows("SELECT * FROM harness_rounds WHERE target=? ORDER BY round", (target,))

    def set_harness(self, target: str, status: str, **f: Any) -> None:
        self._x(
            "INSERT OR REPLACE INTO harnesses (target, status, overlay, binary, source_path, builds, rounds,"
            " notes, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (target, status, f.get("overlay"), f.get("binary"), f.get("source_path"),
             json.dumps(f.get("builds") or {}), f.get("rounds"), f.get("notes"), _now()),
        )
        self.emit("harness", target=target, status=status, binary=f.get("binary"))

    def harnesses(self) -> list[dict]:
        rows = self._rows("SELECT * FROM harnesses ORDER BY target")
        for r in rows:
            r["builds"] = json.loads(r["builds"] or "{}")
        return rows

    # -- VHs ------------------------------------------------------------------------------

    def create_vh(self, lg: str, **f: Any) -> str:
        vid = uuid.uuid4().hex[:12]
        now = _now()
        self._x(
            "INSERT INTO vhs (id, lg, function_name, function_file, description, finder_score,"
            " important_controlflow, sink_code, sink_line, status, finder_session, poc_sessions,"
            " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (vid, lg, f["function_name"], f.get("function_file", ""), f.get("description", ""),
             float(f.get("finder_score", 0.5)), f.get("important_controlflow", ""), f.get("sink_code", ""),
             int(f.get("sink_line") or 0), "pending_verify", f.get("finder_session", ""), "[]", now, now),
        )
        self._x("INSERT INTO vh_events VALUES (?,?,?,?,?,?)",
                (vid, now, "", "pending_verify", f.get("finder_session", ""), "created by finder"))
        self.emit("vh_created", lg=lg, vh_id=vid, function=f["function_name"],
                  finder_score=f.get("finder_score"))
        return vid

    def get_vh(self, vh_id: str) -> dict:
        rows = self._rows("SELECT * FROM vhs WHERE id=?", (vh_id,))
        if not rows:
            raise KeyError(vh_id)
        r = rows[0]
        r["poc_sessions"] = json.loads(r["poc_sessions"] or "[]")
        return r

    def vhs(self, lg: str | None = None) -> list[dict]:
        rows = self._rows("SELECT * FROM vhs" + (" WHERE lg=?" if lg else "") + " ORDER BY created_at",
                          (lg,) if lg else ())
        for r in rows:
            r["poc_sessions"] = json.loads(r["poc_sessions"] or "[]")
        return rows

    def move_vh(self, vh_id: str, to: str, *, frm: tuple[str, ...] = (), session: str = "",
                reason: str = "") -> bool:
        """Move a VH to ``to``; with ``frm``, only from one of those statuses."""
        assert to in VH_STATUSES, to
        with self._lock:
            cur = self.get_vh(vh_id)["status"]
            if frm and cur not in frm:
                return False
            self._x("UPDATE vhs SET status=?, updated_at=? WHERE id=?", (to, _now(), vh_id))
            self._x("INSERT INTO vh_events VALUES (?,?,?,?,?,?)", (vh_id, _now(), cur, to, session, reason))
        self.emit("vh_moved", vh_id=vh_id, from_status=cur, to_status=to, reason=reason or None)
        return True

    def update_vh(self, vh_id: str, **f: Any) -> None:
        allowed = {"description", "important_controlflow", "score", "evidence", "verification_notes",
                   "poc_guidance", "poc_status", "poc_blob", "crash_id", "verifier_session",
                   "poc_sessions", "fp_seed_session"}
        bad = set(f) - allowed
        if bad:
            raise KeyError(f"update_vh: {sorted(bad)}")
        if not f:
            return
        if "poc_sessions" in f:
            f["poc_sessions"] = json.dumps(f["poc_sessions"])
        cols = ", ".join(f"{k}=?" for k in f)
        self._x(f"UPDATE vhs SET {cols}, updated_at=? WHERE id=?", (*f.values(), _now(), vh_id))

    def vh_events(self, vh_id: str) -> list[dict]:
        return self._rows("SELECT * FROM vh_events WHERE vh_id=? ORDER BY ts", (vh_id,))

    # -- crashes ---------------------------------------------------------------------------

    def add_crash(self, lg: str, signature: str, signature_short: str, **f: Any) -> tuple[str, bool]:
        """(crash id, new?) -- one row per distinct signature per logic group."""
        cid = uuid.uuid4().hex[:12]
        with self._lock:
            cur = self._x(
                "INSERT OR IGNORE INTO crashes (id, lg, signature, signature_short, crash_class, source, vh_id,"
                " artifact, top_frames, cycle, output_tail, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (cid, lg, signature, signature_short, f.get("crash_class"), f.get("source"), f.get("vh_id"),
                 f.get("artifact"), json.dumps(f.get("top_frames") or []),
                 json.dumps(f.get("cycle") or []), (f.get("output_tail") or "")[-8000:], _now()),
            )
            new = cur.rowcount == 1
            if not new:
                cid = self._rows("SELECT id FROM crashes WHERE lg=? AND signature_short=?",
                                 (lg, signature_short))[0]["id"]
        if new:
            self.emit("crash", lg=lg, crash_id=cid, signature=signature_short, crash_class=f.get("crash_class"),
                      source=f.get("source"), vh_id=f.get("vh_id"))
        return cid, new

    def crashes(self, lg: str | None = None) -> list[dict]:
        rows = self._rows("SELECT * FROM crashes" + (" WHERE lg=?" if lg else "") + " ORDER BY created_at",
                          (lg,) if lg else ())
        for r in rows:
            r["top_frames"] = json.loads(r["top_frames"] or "[]")
            r["cycle"] = json.loads(r["cycle"] or "[]")
        return rows

    # -- seeds and coverage ---------------------------------------------------------------------

    def add_seeds(self, lg: str, session: str, role: str, seeds: list[dict]) -> None:
        now = _now()
        for s in seeds:
            self._x("INSERT INTO seeds VALUES (?,?,?,?,?,?,?)",
                    (lg, session, role, s["sha1"], s.get("size"), s.get("corpus"), now))
        if seeds:
            self.emit("seeds", lg=lg, session=session, role=role, count=len(seeds))

    def seed_count(self, lg: str) -> int:
        return self._rows("SELECT count(*) AS n FROM seeds WHERE lg=?", (lg,))[0]["n"]

    def add_coverage(self, lg: str, t: float, **f: Any) -> None:
        self._x("INSERT INTO coverage VALUES (?,?,?,?,?,?,?)",
                (lg, t, f.get("edges"), f.get("features"), f.get("exec_s"), f.get("corpus"),
                 f.get("functions_covered")))

    def coverage(self, lg: str) -> list[dict]:
        return self._rows("SELECT * FROM coverage WHERE lg=? ORDER BY t", (lg,))
