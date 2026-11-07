# SPDX-License-Identifier: Apache-2.0
"""Every read and write of run data, against PostgreSQL.

One Store per process (get_store()), each operation one short transaction.
Reads return detached ORM rows (pg/models.py) whose attributes stay readable
after the session closes; nothing is lazy-loaded.

Status changes are conditional updates (`WHERE status = <from>`), so two
agents of one worker cannot both take a VH, and a finished VH is never moved
back. docs/db-design.md explains the tables.
"""

import hashlib
import json
import os
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import Text, create_engine, func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from .pg.models import (
    Agent,
    Crash,
    FunctionAnalysis,
    Graph,
    GraphHarness,
    Harness,
    HarnessBinary,
    LLMCall,
    LLMMessage,
    LogicGroup,
    PocAttempt,
    Run,
    ToolCall,
    VHMerge,
    VulnerabilityHypothesis,
    Worker,
)

# A VH at or above this score goes on to PoC generation after verification.
VH_POC_THRESHOLD = 0.5

# What a text column gets instead of a NUL byte, which PostgreSQL text refuses.
NUL_MARK = "\\x00"


def now() -> datetime:
    return datetime.now(timezone.utc)


def as_uuid(value) -> Optional[uuid.UUID]:
    if value is None or value == "":
        return None
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))


def clean_text(value):
    """A NUL-free copy of `value` (str), or `value` unchanged."""
    if isinstance(value, str) and "\x00" in value:
        return value.replace("\x00", NUL_MARK)
    return value


def _clean(values: Dict[str, Any]) -> Dict[str, Any]:
    return {k: clean_text(v) for k, v in values.items()}


def message_sha256(message: Dict[str, Any]) -> str:
    """The identity of a message: its canonical JSON (keys sorted)."""
    canonical = json.dumps(message, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()


def as_dict(row) -> Dict[str, Any]:
    """A row's columns as plain JSON-friendly values (ids and times as str)."""
    out = {}
    for col in row.__table__.columns:
        v = getattr(row, col.key)
        if isinstance(v, uuid.UUID):
            v = str(v)
        elif isinstance(v, datetime):
            v = v.isoformat()
        elif isinstance(v, Decimal):
            v = float(v)
        elif isinstance(v, (bytes, memoryview)):
            continue
        out[col.key] = v
    return out


def vh_dict(vh) -> Dict[str, Any]:
    """A VH row as the dict agents and prompts read (with the old key names)."""
    d = as_dict(vh)
    d["vulnerability_hypothesis_id"] = d["id"]
    d["_id"] = d["id"]
    d["short_id"] = d["id"][:8]
    d["file_path"] = d.get("function_file")
    d["line_number"] = d.get("sink_line")
    return d


def lg_dict(lg) -> Dict[str, Any]:
    d = as_dict(lg)
    d["lg_id"] = d["id"]
    d["short_id"] = d["id"][:8]
    return d


class StoreError(RuntimeError):
    pass


class Store:
    """The run database. Thread-safe; one engine per process."""

    def __init__(self, url: str, pool_size: int = 5):
        self.url = url
        self.engine = create_engine(
            url,
            pool_pre_ping=True,
            pool_size=pool_size,
            max_overflow=10,
            pool_recycle=1800,
        )
        self._session = sessionmaker(self.engine, expire_on_commit=False)

    @contextmanager
    def session(self) -> Session:
        s = self._session()
        try:
            yield s
            s.commit()
        except BaseException:
            s.rollback()
            raise
        finally:
            s.close()

    def close(self) -> None:
        self.engine.dispose()

    # ------------------------------------------------------------------ runs

    def create_run(
        self,
        run_id: str,
        project_name: str,
        scan_mode: str,
        config: Dict[str, Any],
        config_given: Dict[str, str],
        workspace_path: str,
        code_version: Optional[str] = None,
        label: Optional[str] = None,
    ) -> None:
        with self.session() as s:
            s.add(
                Run(
                    id=as_uuid(run_id),
                    project_name=project_name,
                    task_type="poc",
                    scan_mode=scan_mode,
                    status="preparing",
                    config=config,
                    config_given=config_given,
                    workspace_path=workspace_path,
                    code_version=code_version,
                    label=label,
                    heartbeat_at=now(),
                )
            )

    def get_run(self, run_id) -> Optional[Run]:
        with self.session() as s:
            return s.get(Run, as_uuid(run_id))

    def run_dispatched(self, run_id) -> None:
        with self.session() as s:
            s.execute(
                update(Run)
                .where(Run.id == as_uuid(run_id), Run.status == "preparing")
                .values(status="running", dispatched_at=now(), heartbeat_at=now())
            )

    def run_heartbeat(self, run_id) -> None:
        with self.session() as s:
            s.execute(
                update(Run).where(Run.id == as_uuid(run_id)).values(heartbeat_at=now())
            )

    def end_run(
        self,
        run_id,
        status: str,
        end_reason: Optional[str] = None,
        error: Optional[str] = None,
    ) -> bool:
        """Move a run that has not ended yet to its final status."""
        with self.session() as s:
            r = s.execute(
                update(Run)
                .where(
                    Run.id == as_uuid(run_id),
                    Run.status.in_(("preparing", "running")),
                )
                .values(
                    status=status,
                    end_reason=end_reason if status == "completed" else None,
                    error=clean_text(error) if status == "error" else None,
                    ended_at=now(),
                    heartbeat_at=now(),
                )
            )
            return r.rowcount == 1

    def run_cost(self, run_id) -> float:
        with self.session() as s:
            v = s.scalar(
                select(func.coalesce(func.sum(LLMCall.cost), 0)).where(
                    LLMCall.run_id == as_uuid(run_id)
                )
            )
            return float(v or 0)

    # ------------------------------------------------------------- harnesses

    def add_harness(
        self, run_id, name: str, source_path: str, binaries: Dict[str, str]
    ) -> uuid.UUID:
        """A built harness and its binaries, one per sanitizer."""
        hid = uuid.uuid4()
        with self.session() as s:
            s.add(
                Harness(id=hid, run_id=as_uuid(run_id), name=name, source_path=source_path)
            )
            s.flush()
            for sanitizer, path in sorted(binaries.items()):
                s.add(HarnessBinary(harness_id=hid, sanitizer=sanitizer, binary_path=path))
        return hid

    def harnesses(self, run_id) -> List[Harness]:
        with self.session() as s:
            return list(
                s.scalars(
                    select(Harness)
                    .where(Harness.run_id == as_uuid(run_id))
                    .order_by(Harness.name)
                )
            )

    def harness(self, harness_id) -> Optional[Harness]:
        with self.session() as s:
            return s.get(Harness, as_uuid(harness_id))

    def harness_binaries(self, harness_id) -> Dict[str, str]:
        with self.session() as s:
            rows = s.scalars(
                select(HarnessBinary).where(HarnessBinary.harness_id == as_uuid(harness_id))
            )
            return {b.sanitizer: b.binary_path for b in rows}

    # ---------------------------------------------------------------- graphs

    def register_graph(
        self,
        run_id,
        commit: str,
        path: str,
        content_sha256: str,
        n_functions: int,
        n_edges: int,
        n_indirect_edges: int,
        harness_reach: Dict[Any, Tuple[int, int]],
    ) -> uuid.UUID:
        """The index file a run uses, and per harness (n_reachable, max_depth)."""
        gid = uuid.uuid4()
        with self.session() as s:
            s.add(
                Graph(
                    id=gid,
                    run_id=as_uuid(run_id),
                    commit=commit,
                    path=path,
                    content_sha256=content_sha256,
                    n_functions=n_functions,
                    n_edges=n_edges,
                    n_indirect_edges=n_indirect_edges,
                )
            )
            s.flush()
            for harness_id, (n_reachable, max_depth) in harness_reach.items():
                s.add(
                    GraphHarness(
                        graph_id=gid,
                        harness_id=as_uuid(harness_id),
                        n_reachable=n_reachable,
                        max_depth=max_depth,
                    )
                )
        return gid

    # --------------------------------------------------------------- workers

    def create_worker(self, run_id, harness_id, workspace_path: str) -> uuid.UUID:
        wid = uuid.uuid4()
        with self.session() as s:
            s.add(
                Worker(
                    id=wid,
                    run_id=as_uuid(run_id),
                    harness_id=as_uuid(harness_id),
                    status="queued",
                    workspace_path=workspace_path,
                )
            )
        return wid

    def set_worker_job(self, worker_id, celery_job_id: str) -> None:
        with self.session() as s:
            s.execute(
                update(Worker)
                .where(Worker.id == as_uuid(worker_id))
                .values(celery_job_id=celery_job_id)
            )

    def worker_started(self, worker_id) -> bool:
        with self.session() as s:
            r = s.execute(
                update(Worker)
                .where(Worker.id == as_uuid(worker_id), Worker.status == "queued")
                .values(status="running", started_at=now(), heartbeat_at=now())
            )
            return r.rowcount == 1

    def worker_heartbeat(self, worker_id) -> None:
        with self.session() as s:
            s.execute(
                update(Worker)
                .where(Worker.id == as_uuid(worker_id))
                .values(heartbeat_at=now())
            )

    def end_worker(
        self,
        worker_id,
        status: str,
        end_reason: Optional[str] = None,
        error: Optional[str] = None,
    ) -> bool:
        with self.session() as s:
            r = s.execute(
                update(Worker)
                .where(
                    Worker.id == as_uuid(worker_id),
                    Worker.status.in_(("queued", "running")),
                )
                .values(
                    status=status,
                    end_reason=end_reason if status == "completed" else None,
                    error=clean_text(error) if status == "error" else None,
                    ended_at=now(),
                )
            )
            return r.rowcount == 1

    def end_open_workers(
        self, run_id, status: str, end_reason: Optional[str] = None
    ) -> int:
        """End every worker of the run still queued or running."""
        with self.session() as s:
            r = s.execute(
                update(Worker)
                .where(
                    Worker.run_id == as_uuid(run_id),
                    Worker.status.in_(("queued", "running")),
                )
                .values(
                    status=status,
                    end_reason=end_reason if status == "completed" else None,
                    ended_at=now(),
                )
            )
            return r.rowcount

    def get_worker(self, worker_id) -> Optional[Worker]:
        with self.session() as s:
            return s.get(Worker, as_uuid(worker_id))

    def workers(self, run_id) -> List[Worker]:
        with self.session() as s:
            return list(
                s.scalars(
                    select(Worker)
                    .where(Worker.run_id == as_uuid(run_id))
                    .order_by(Worker.created_at)
                )
            )

    # ---------------------------------------------------------------- agents

    def start_agent(
        self,
        agent_id,
        run_id,
        worker_id,
        agent_type: str,
        vh_id=None,
        lg_id=None,
        crash_id=None,
        function: Optional[Tuple[str, str, int]] = None,
        log_path: Optional[str] = None,
    ) -> None:
        f_file, f_name, f_line = function or (None, None, None)
        with self.session() as s:
            s.add(
                Agent(
                    id=as_uuid(agent_id),
                    run_id=as_uuid(run_id),
                    worker_id=as_uuid(worker_id),
                    agent_type=agent_type,
                    vh_id=as_uuid(vh_id),
                    lg_id=as_uuid(lg_id),
                    crash_id=as_uuid(crash_id),
                    function_file=f_file,
                    function_name=f_name,
                    function_start_line=f_line,
                    status="running",
                    log_path=log_path,
                )
            )

    def agent_progress(
        self,
        agent_id,
        iterations: Optional[int] = None,
        seeds_generated: Optional[int] = None,
        log_path: Optional[str] = None,
    ) -> None:
        values = {}
        if iterations is not None:
            values["iterations"] = iterations
        if seeds_generated is not None:
            values["seeds_generated"] = seeds_generated
        if log_path is not None:
            values["log_path"] = log_path
        if not values:
            return
        with self.session() as s:
            s.execute(update(Agent).where(Agent.id == as_uuid(agent_id)).values(**values))

    def end_agent(
        self,
        agent_id,
        status: str,
        end_reason: Optional[str] = None,
        error: Optional[str] = None,
        iterations: Optional[int] = None,
        seeds_generated: Optional[int] = None,
    ) -> bool:
        values = dict(
            status=status,
            end_reason=end_reason if status == "completed" else None,
            error=clean_text(error) if status == "error" else None,
            ended_at=now(),
        )
        if iterations is not None:
            values["iterations"] = iterations
        if seeds_generated is not None:
            values["seeds_generated"] = seeds_generated
        with self.session() as s:
            r = s.execute(
                update(Agent)
                .where(Agent.id == as_uuid(agent_id), Agent.status == "running")
                .values(**values)
            )
            return r.rowcount == 1

    def end_running_agents(
        self,
        run_id=None,
        worker_id=None,
        status: str = "cancelled",
        end_reason: Optional[str] = None,
    ) -> int:
        """End the agents still marked running (their process is gone or stopped)."""
        cond = [Agent.status == "running"]
        if run_id is not None:
            cond.append(Agent.run_id == as_uuid(run_id))
        if worker_id is not None:
            cond.append(Agent.worker_id == as_uuid(worker_id))
        with self.session() as s:
            r = s.execute(
                update(Agent)
                .where(*cond)
                .values(
                    status=status,
                    end_reason=end_reason if status == "completed" else None,
                    ended_at=now(),
                )
            )
            return r.rowcount

    def get_agent(self, agent_id) -> Optional[Agent]:
        with self.session() as s:
            return s.get(Agent, as_uuid(agent_id))

    def agents(self, run_id) -> List[Agent]:
        with self.session() as s:
            return list(
                s.scalars(
                    select(Agent)
                    .where(Agent.run_id == as_uuid(run_id))
                    .order_by(Agent.started_at)
                )
            )

    def poc_agent_for_vh(self, vh_id) -> Optional[uuid.UUID]:
        """The latest POCAgent working the VH (a VH fuzzer's crash belongs to it)."""
        with self.session() as s:
            return s.scalar(
                select(Agent.id)
                .where(Agent.vh_id == as_uuid(vh_id), Agent.agent_type == "POCAgent")
                .order_by(Agent.started_at.desc())
                .limit(1)
            )

    # ---------------------------------------------------------- logic groups

    def create_logic_group(
        self,
        run_id,
        worker_id,
        agent_id,
        name: str,
        risk_level: str,
        core_functions: Sequence[str],
        entry_functions: Sequence[str],
        summary: Optional[str] = None,
    ) -> uuid.UUID:
        lid = uuid.uuid4()
        with self.session() as s:
            s.add(
                LogicGroup(
                    id=lid,
                    run_id=as_uuid(run_id),
                    worker_id=as_uuid(worker_id),
                    created_by_agent_id=as_uuid(agent_id),
                    name=clean_text(name),
                    risk_level=risk_level,
                    core_functions=[clean_text(f) for f in core_functions],
                    entry_functions=[clean_text(f) for f in entry_functions],
                    summary=clean_text(summary),
                )
            )
        return lid

    def get_logic_group(self, lg_id) -> Optional[LogicGroup]:
        with self.session() as s:
            return s.get(LogicGroup, as_uuid(lg_id))

    def logic_groups(self, worker_id) -> List[LogicGroup]:
        """A worker's logic groups, highest risk first, then oldest."""
        rank = {"high": 0, "medium": 1, "low": 2}
        with self.session() as s:
            rows = list(
                s.scalars(
                    select(LogicGroup)
                    .where(LogicGroup.worker_id == as_uuid(worker_id))
                    .order_by(LogicGroup.created_at)
                )
            )
        rows.sort(key=lambda g: rank.get(g.risk_level, 3))
        return rows

    def set_planned_functions(self, lg_id, n: int) -> None:
        with self.session() as s:
            s.execute(
                update(LogicGroup)
                .where(LogicGroup.id == as_uuid(lg_id))
                .values(planned_functions=n)
            )

    def record_function_analysis(
        self,
        lg_id,
        function_file: str,
        function_name: str,
        start_line: int,
        end_line: int,
        agent_id,
    ) -> None:
        """A finder finished a function. A second record for it is a bug: it raises."""
        with self.session() as s:
            s.add(
                FunctionAnalysis(
                    lg_id=as_uuid(lg_id),
                    function_file=function_file,
                    function_name=function_name,
                    function_start_line=start_line,
                    function_end_line=max(end_line or start_line, start_line),
                    agent_id=as_uuid(agent_id),
                )
            )

    def analyzed_functions(self, worker_id) -> set:
        """(file, name, start_line) of every function analysed in this worker."""
        with self.session() as s:
            rows = s.execute(
                select(
                    FunctionAnalysis.function_file,
                    FunctionAnalysis.function_name,
                    FunctionAnalysis.function_start_line,
                )
                .join(LogicGroup, LogicGroup.id == FunctionAnalysis.lg_id)
                .where(LogicGroup.worker_id == as_uuid(worker_id))
            )
            return {tuple(r) for r in rows}

    def analysis_count(self, lg_id) -> int:
        with self.session() as s:
            return s.scalar(
                select(func.count()).where(FunctionAnalysis.lg_id == as_uuid(lg_id))
            )

    # ---------------------------------------------------------------- VHs

    def create_vh(
        self,
        run_id,
        worker_id,
        function_file: str,
        function_name: str,
        description: str,
        score: float,
        agent_id=None,
        lg_id=None,
        sink_code: Optional[str] = None,
        sink_line: Optional[int] = None,
        sanitizer: Optional[str] = None,
        important_controlflow: Optional[str] = None,
    ) -> uuid.UUID:
        vid = uuid.uuid4()
        score = min(max(float(score), 0.0), 1.0)
        with self.session() as s:
            s.add(
                VulnerabilityHypothesis(
                    **_clean(
                        dict(
                            function_file=function_file,
                            function_name=function_name,
                            sink_code=sink_code,
                            finder_description=description,
                            description=description,
                            important_controlflow=important_controlflow,
                        )
                    ),
                    id=vid,
                    run_id=as_uuid(run_id),
                    worker_id=as_uuid(worker_id),
                    sink_line=sink_line,
                    lg_id=as_uuid(lg_id),
                    sanitizer=sanitizer,
                    created_by_agent_id=as_uuid(agent_id),
                    finder_score=score,
                    score=score,
                    status="pending_verify",
                )
            )
        return vid

    def get_vh(self, vh_id) -> Optional[VulnerabilityHypothesis]:
        with self.session() as s:
            return s.get(VulnerabilityHypothesis, as_uuid(vh_id))

    def find_vh_by_prefix(self, worker_id, prefix: str) -> Optional[VulnerabilityHypothesis]:
        """A VH of this worker by full id or by the short id the agents are shown."""
        prefix = (prefix or "").strip().lower()
        if not prefix:
            return None
        try:
            return self.get_vh(uuid.UUID(prefix))
        except ValueError:
            pass
        with self.session() as s:
            rows = list(
                s.scalars(
                    select(VulnerabilityHypothesis).where(
                        VulnerabilityHypothesis.worker_id == as_uuid(worker_id),
                        VulnerabilityHypothesis.id.cast(Text).like(prefix + "%"),
                    )
                )
            )
        return rows[0] if len(rows) == 1 else None

    def vhs(
        self, worker_id=None, run_id=None, statuses: Optional[Iterable[str]] = None
    ) -> List[VulnerabilityHypothesis]:
        cond = []
        if worker_id is not None:
            cond.append(VulnerabilityHypothesis.worker_id == as_uuid(worker_id))
        if run_id is not None:
            cond.append(VulnerabilityHypothesis.run_id == as_uuid(run_id))
        if statuses:
            cond.append(VulnerabilityHypothesis.status.in_(tuple(statuses)))
        with self.session() as s:
            return list(
                s.scalars(
                    select(VulnerabilityHypothesis)
                    .where(*cond)
                    .order_by(VulnerabilityHypothesis.created_at)
                )
            )

    def vhs_in_function(self, worker_id, function_name: str) -> List[VulnerabilityHypothesis]:
        with self.session() as s:
            return list(
                s.scalars(
                    select(VulnerabilityHypothesis).where(
                        VulnerabilityHypothesis.worker_id == as_uuid(worker_id),
                        VulnerabilityHypothesis.function_name == function_name,
                    )
                )
            )

    def merge_vh(self, vh_id, agent_id, description: str, finder_score: float) -> None:
        with self.session() as s:
            s.add(
                VHMerge(
                    vh_id=as_uuid(vh_id),
                    agent_id=as_uuid(agent_id),
                    description=clean_text(description),
                    finder_score=min(max(float(finder_score), 0.0), 1.0),
                )
            )

    def vh_status_counts(self, worker_id=None, run_id=None) -> Dict[str, int]:
        cond = []
        if worker_id is not None:
            cond.append(VulnerabilityHypothesis.worker_id == as_uuid(worker_id))
        if run_id is not None:
            cond.append(VulnerabilityHypothesis.run_id == as_uuid(run_id))
        with self.session() as s:
            rows = s.execute(
                select(VulnerabilityHypothesis.status, func.count())
                .where(*cond)
                .group_by(VulnerabilityHypothesis.status)
            )
            return {status: n for status, n in rows}

    def merge_count(self, worker_id=None, run_id=None) -> int:
        cond = []
        if worker_id is not None:
            cond.append(VulnerabilityHypothesis.worker_id == as_uuid(worker_id))
        if run_id is not None:
            cond.append(VulnerabilityHypothesis.run_id == as_uuid(run_id))
        with self.session() as s:
            return s.scalar(
                select(func.count())
                .select_from(VHMerge)
                .join(VulnerabilityHypothesis, VulnerabilityHypothesis.id == VHMerge.vh_id)
                .where(*cond)
            )

    def claim_vh(self, worker_id, from_status: str, to_status: str,
                 min_score: Optional[float] = None) -> Optional[VulnerabilityHypothesis]:
        """Take this worker's best VH in `from_status` and move it to `to_status`."""
        cond = [
            VulnerabilityHypothesis.worker_id == as_uuid(worker_id),
            VulnerabilityHypothesis.status == from_status,
        ]
        if min_score is not None:
            cond.append(VulnerabilityHypothesis.score >= min_score)
        with self.session() as s:
            row = s.scalars(
                select(VulnerabilityHypothesis)
                .where(*cond)
                .order_by(
                    VulnerabilityHypothesis.score.desc(),
                    VulnerabilityHypothesis.created_at,
                )
                .limit(1)
                .with_for_update(skip_locked=True)
            ).first()
            if row is None:
                return None
            row.status = to_status
            s.flush()
            return row

    def move_vh(self, vh_id, from_status: str, to_status: str, **fields) -> bool:
        """Move a VH on only if it is still in `from_status`; set `fields` with it."""
        with self.session() as s:
            r = s.execute(
                update(VulnerabilityHypothesis)
                .where(
                    VulnerabilityHypothesis.id == as_uuid(vh_id),
                    VulnerabilityHypothesis.status == from_status,
                )
                .values(status=to_status, **_clean(fields))
            )
            return r.rowcount == 1

    def update_vh(self, vh_id, **fields) -> bool:
        """The verifier's fields (score, evidence, notes, guidance, rewrites)."""
        if not fields:
            return False
        if "score" in fields and fields["score"] is not None:
            fields["score"] = min(max(float(fields["score"]), 0.0), 1.0)
        with self.session() as s:
            r = s.execute(
                update(VulnerabilityHypothesis)
                .where(VulnerabilityHypothesis.id == as_uuid(vh_id))
                .values(**_clean(fields))
            )
            return r.rowcount == 1

    def return_stuck_vhs(self, worker_id) -> int:
        """Put a dead worker's in-flight VHs back in their queues."""
        n = 0
        for busy, pending in (("verifying", "pending_verify"), ("generating_poc", "pending_poc")):
            with self.session() as s:
                n += s.execute(
                    update(VulnerabilityHypothesis)
                    .where(
                        VulnerabilityHypothesis.worker_id == as_uuid(worker_id),
                        VulnerabilityHypothesis.status == busy,
                    )
                    .values(status=pending)
                ).rowcount
        return n

    # ------------------------------------------------------ PoCs and crashes

    def add_poc_attempt(
        self,
        run_id,
        source: str,
        harness_id,
        sanitizer: str,
        blob: bytes,
        vh_id=None,
        worker_id=None,
        agent_id=None,
        attempt: Optional[int] = None,
        variant: Optional[int] = None,
        generator_code: Optional[str] = None,
    ) -> uuid.UUID:
        pid = uuid.uuid4()
        with self.session() as s:
            s.add(
                PocAttempt(
                    id=pid,
                    run_id=as_uuid(run_id),
                    vh_id=as_uuid(vh_id),
                    worker_id=as_uuid(worker_id),
                    agent_id=as_uuid(agent_id),
                    source=source,
                    harness_id=as_uuid(harness_id),
                    sanitizer=sanitizer,
                    attempt=attempt,
                    variant=variant,
                    blob=blob,
                    blob_sha256=hashlib.sha256(blob).hexdigest(),
                    generator_code=clean_text(generator_code),
                    status="pending",
                )
            )
        return pid

    def get_poc_attempt(self, attempt_id) -> Optional[PocAttempt]:
        with self.session() as s:
            return s.get(PocAttempt, as_uuid(attempt_id))

    def poc_attempts(self, run_id=None, vh_id=None, agent_id=None) -> List[PocAttempt]:
        cond = []
        if run_id is not None:
            cond.append(PocAttempt.run_id == as_uuid(run_id))
        if vh_id is not None:
            cond.append(PocAttempt.vh_id == as_uuid(vh_id))
        if agent_id is not None:
            cond.append(PocAttempt.agent_id == as_uuid(agent_id))
        with self.session() as s:
            return list(
                s.scalars(select(PocAttempt).where(*cond).order_by(PocAttempt.created_at))
            )

    def end_pending_attempts(self, run_id) -> int:
        """At a run's stop: inputs that never finished running are errors."""
        with self.session() as s:
            return s.execute(
                update(PocAttempt)
                .where(PocAttempt.run_id == as_uuid(run_id), PocAttempt.status == "pending")
                .values(status="error")
            ).rowcount

    def attempt_ran(self, attempt_id, status: str) -> None:
        """A run that did not crash (no_crash) or could not run (error)."""
        assert status in ("no_crash", "error")
        with self.session() as s:
            s.execute(
                update(PocAttempt)
                .where(PocAttempt.id == as_uuid(attempt_id), PocAttempt.status == "pending")
                .values(status=status)
            )

    def attempt_crashed(
        self, attempt_id, signature: str, vuln_type: Optional[str], sanitizer_output: str
    ) -> Tuple[uuid.UUID, bool]:
        """Record a crash: (crash id, whether this attempt found it first).

        One row per distinct signature in the run, whoever hits it: VH agents,
        the global fuzzer and VH fuzzers all come through here, and two equal
        crashes at once still make one row.
        """
        aid = as_uuid(attempt_id)
        with self.session() as s:
            run_id = s.scalar(select(PocAttempt.run_id).where(PocAttempt.id == aid))
            if run_id is None:
                raise StoreError(f"no PoC attempt {attempt_id}")
            new_id = uuid.uuid4()
            inserted = s.scalar(
                pg_insert(Crash)
                .values(
                    id=new_id,
                    run_id=run_id,
                    signature=signature,
                    vuln_type=vuln_type or "unknown",
                    first_attempt_id=aid,
                )
                .on_conflict_do_nothing(index_elements=["run_id", "signature"])
                .returning(Crash.id)
            )
            crash_id = inserted or s.scalar(
                select(Crash.id).where(Crash.run_id == run_id, Crash.signature == signature)
            )
            s.execute(
                update(PocAttempt)
                .where(PocAttempt.id == aid)
                .values(
                    status="crashed",
                    crash_id=crash_id,
                    sanitizer_output=clean_text(sanitizer_output or "(empty)"),
                )
            )
            # The VH this input was built for now has its PoC.
            vh_id = s.scalar(select(PocAttempt.vh_id).where(PocAttempt.id == aid))
            if vh_id is not None:
                s.execute(
                    update(VulnerabilityHypothesis)
                    .where(
                        VulnerabilityHypothesis.id == vh_id,
                        VulnerabilityHypothesis.status.in_(
                            ("pending_poc", "generating_poc", "poc_failed")
                        ),
                    )
                    .values(status="poc_generated")
                )
            return crash_id, inserted is not None

    def get_crash(self, crash_id) -> Optional[Crash]:
        with self.session() as s:
            return s.get(Crash, as_uuid(crash_id))

    def crash_by_signature(self, run_id, signature: str) -> Optional[Crash]:
        with self.session() as s:
            return s.scalars(
                select(Crash).where(
                    Crash.run_id == as_uuid(run_id), Crash.signature == signature
                )
            ).first()

    def crashes(self, run_id) -> List[Crash]:
        with self.session() as s:
            return list(
                s.scalars(
                    select(Crash)
                    .where(Crash.run_id == as_uuid(run_id))
                    .order_by(Crash.created_at)
                )
            )

    def crash_count(self, run_id) -> int:
        with self.session() as s:
            return s.scalar(
                select(func.count()).where(Crash.run_id == as_uuid(run_id))
            )

    def set_crash_package(self, crash_id, package_path: str) -> None:
        with self.session() as s:
            s.execute(
                update(Crash)
                .where(Crash.id == as_uuid(crash_id))
                .values(package_path=package_path)
            )

    def set_crash_vuln_type(self, crash_id, vuln_type: str) -> None:
        with self.session() as s:
            s.execute(
                update(Crash)
                .where(Crash.id == as_uuid(crash_id))
                .values(vuln_type=clean_text(vuln_type))
            )

    def set_crash_report(self, crash_id, report: str) -> None:
        with self.session() as s:
            s.execute(
                update(Crash)
                .where(Crash.id == as_uuid(crash_id))
                .values(report=clean_text(report))
            )

    # ------------------------------------------------- LLM calls / tool calls

    def message_ids(self, run_id, messages: Sequence[Tuple[str, str, Any]]) -> Dict[str, int]:
        """Store (sha256, role, content) messages once per run; sha256 -> id."""
        if not messages:
            return {}
        rid = as_uuid(run_id)
        unique = {}
        for sha, role, content in messages:
            unique.setdefault(sha, (role, content))
        with self.session() as s:
            rows = [
                {"run_id": rid, "sha256": sha, "role": role, "content": content}
                for sha, (role, content) in unique.items()
            ]
            got = dict(
                s.execute(
                    pg_insert(LLMMessage)
                    .values(rows)
                    .on_conflict_do_nothing(index_elements=["run_id", "sha256"])
                    .returning(LLMMessage.sha256, LLMMessage.id)
                ).all()
            )
            missing = [sha for sha in unique if sha not in got]
            if missing:
                got.update(
                    s.execute(
                        select(LLMMessage.sha256, LLMMessage.id).where(
                            LLMMessage.run_id == rid, LLMMessage.sha256.in_(missing)
                        )
                    ).all()
                )
            return got

    def insert_llm_calls(self, rows: List[Dict[str, Any]]) -> List[int]:
        """Insert call rows (already resolved to message ids); their ids, in order."""
        if not rows:
            return []
        with self.session() as s:
            ids = []
            for row in rows:
                ids.append(
                    s.scalar(
                        pg_insert(LLMCall).values(**_clean(row)).returning(LLMCall.id)
                    )
                )
            return ids

    def insert_tool_calls(self, rows: List[Dict[str, Any]]) -> None:
        if not rows:
            return
        with self.session() as s:
            s.execute(pg_insert(ToolCall).values([_clean(r) for r in rows]))

    def conversation(self, llm_call_id: int) -> List[Dict[str, Any]]:
        """The messages one call sent, in order, then its reply."""
        with self.session() as s:
            call = s.get(LLMCall, llm_call_id)
            if call is None:
                return []
            ids = list(call.input_message_ids) + (
                [call.output_message_id] if call.output_message_id else []
            )
            by_id = {
                m.id: m
                for m in s.scalars(select(LLMMessage).where(LLMMessage.id.in_(ids)))
            }
            return [by_id[i].content for i in ids if i in by_id]

    def agent_conversation(self, agent_id) -> List[Dict[str, Any]]:
        """The agent's last call's messages plus its reply: its whole transcript."""
        with self.session() as s:
            last = s.scalar(
                select(LLMCall.id)
                .where(LLMCall.agent_id == as_uuid(agent_id), LLMCall.success.is_(True))
                .order_by(LLMCall.id.desc())
                .limit(1)
            )
        return self.conversation(last) if last else []

    # -------------------------------------------------------------- summary

    def run_summary(self, run_id) -> Dict[str, Any]:
        """Counts for the end-of-run table: per worker and for the run."""
        rid = as_uuid(run_id)
        with self.session() as s:
            harness_names = dict(
                s.execute(select(Harness.id, Harness.name).where(Harness.run_id == rid)).all()
            )
            workers = list(s.scalars(select(Worker).where(Worker.run_id == rid)))
            vh_counts = dict(
                s.execute(
                    select(VulnerabilityHypothesis.worker_id, func.count())
                    .where(VulnerabilityHypothesis.run_id == rid)
                    .group_by(VulnerabilityHypothesis.worker_id)
                ).all()
            )
            merge_counts = dict(
                s.execute(
                    select(VulnerabilityHypothesis.worker_id, func.count())
                    .select_from(VHMerge)
                    .join(VulnerabilityHypothesis, VulnerabilityHypothesis.id == VHMerge.vh_id)
                    .where(VulnerabilityHypothesis.run_id == rid)
                    .group_by(VulnerabilityHypothesis.worker_id)
                ).all()
            )
            # Distinct bugs each harness found first.
            crash_by_harness = dict(
                s.execute(
                    select(PocAttempt.harness_id, func.count(func.distinct(Crash.id)))
                    .join(Crash, Crash.first_attempt_id == PocAttempt.id)
                    .where(Crash.run_id == rid)
                    .group_by(PocAttempt.harness_id)
                ).all()
            )
            cost_by_worker = dict(
                s.execute(
                    select(LLMCall.worker_id, func.coalesce(func.sum(LLMCall.cost), 0))
                    .where(LLMCall.run_id == rid)
                    .group_by(LLMCall.worker_id)
                ).all()
            )
        out = []
        for w in workers:
            out.append(
                {
                    "worker_id": str(w.id),
                    "fuzzer": harness_names.get(w.harness_id, "?"),
                    "status": w.status,
                    "end_reason": w.end_reason,
                    "error": w.error,
                    "started_at": w.started_at,
                    "ended_at": w.ended_at,
                    "vhs_found": vh_counts.get(w.id, 0),
                    "vhs_merged": merge_counts.get(w.id, 0),
                    "crashes": crash_by_harness.get(w.harness_id, 0),
                    "cost": float(cost_by_worker.get(w.id, 0) or 0),
                }
            )
        return {
            "workers": out,
            "crashes": self.crash_count(rid),
            "cost": self.run_cost(rid),
        }


# ------------------------------------------------------------------ events
#
# The writes that change a run's state also go to <output>/events.jsonl
# (core/events.py), with the ids of the rows they wrote. Wrapping the methods
# here keeps the event names and the database in one place.

_EVENTS = {
    # method: (event, result field, condition on the result)
    "create_run": ("run_created", None, None),
    "run_dispatched": ("run_dispatched", None, None),
    "end_run": ("run_ended", None, bool),
    "create_worker": ("worker_created", "worker_id", None),
    "worker_started": ("worker_started", None, bool),
    "end_worker": ("worker_ended", None, bool),
    "end_open_workers": ("workers_closed", "count", bool),
    "start_agent": ("agent_started", None, None),
    "end_agent": ("agent_ended", None, bool),
    "end_running_agents": ("agents_closed", "count", bool),
    "create_logic_group": ("logic_group_created", "lg_id", None),
    "create_vh": ("vh_created", "vh_id", None),
    "merge_vh": ("vh_merged", None, None),
    "move_vh": ("vh_moved", None, bool),
    "attempt_crashed": ("crash", None, None),
    "set_crash_package": ("crash_packaged", None, None),
}
# Arguments too large or too free-form for the stream; the rows have them.
_EVENT_SKIP = {
    "self", "config", "config_given", "description", "sink_code", "important_controlflow",
    "sanitizer_output", "core_functions", "entry_functions", "summary", "error", "workspace_path",
    "code_version",
}


def _with_event(name, fn):
    import functools
    import inspect

    from ..core import events

    event, result_field, cond = _EVENTS[name]
    sig = inspect.signature(fn)

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        result = fn(*args, **kwargs)
        if events.events_path() is None or (cond is not None and not cond(result)):
            return result
        try:
            a = sig.bind(*args, **kwargs)
            fields = {k: v for k, v in a.arguments.items() if k not in _EVENT_SKIP}
            extra = fields.pop("fields", None)
            if isinstance(extra, dict):
                fields.update({k: v for k, v in extra.items() if k in ("score", "verifier_reproduced")})
            if name == "attempt_crashed":
                fields["crash_id"], fields["new"] = result
            elif result_field:
                fields[result_field] = result
            if name in ("end_run", "end_worker", "end_agent") and a.arguments.get("error"):
                fields["error"] = str(a.arguments["error"]).strip().splitlines()[-1][:300]
            events.emit(event, **fields)
        except Exception:
            pass
        return result

    return wrapper


for _name in _EVENTS:
    setattr(Store, _name, _with_event(_name, getattr(Store, _name)))


# ---------------------------------------------------------------- process-wide

_store: Optional[Store] = None
_store_pid: Optional[int] = None
_store_lock = threading.Lock()


def get_store(url: Optional[str] = None) -> Store:
    """This process's Store. A forked child gets its own engine."""
    global _store, _store_pid
    with _store_lock:
        if _store is not None and _store_pid == os.getpid():
            return _store
        url = url or os.environ.get("POSTGRES_URL")
        if not url:
            raise StoreError("POSTGRES_URL is not set")
        _store = Store(url)
        _store_pid = os.getpid()
        os.environ["POSTGRES_URL"] = url
        return _store


def reset_store() -> None:
    """Forget this process's Store (tests)."""
    global _store, _store_pid
    with _store_lock:
        if _store is not None and _store_pid == os.getpid():
            _store.close()
        _store = None
        _store_pid = None


def ping(url: str) -> None:
    eng = create_engine(url)
    try:
        with eng.connect() as c:
            c.execute(text("SELECT 1"))
    finally:
        eng.dispose()
