# SPDX-License-Identifier: Apache-2.0
"""The PostgreSQL schema, defined once.

Every table, column and constraint lives here; the Alembic migrations are
generated from it and the tests compare the two. docs/db-design.md explains
why each field exists. Comments here only say what a constraint protects.

Two id kinds: uuid for anything another table points at (generated in Python,
because a worker's or agent's id names its directory and Redis keys before the
row is written), bigint identity for the high-volume logs.

No relationships are declared: callers query explicitly, so nothing loads a
graph of rows behind their back.

Deletes cascade only along ownership: a run owns every row it produced, and a
harness, graph, logic group or VH owns its child rows. A reference from one
record to another (an agent's VH, a PoC's crash) never deletes anything, and is
checked at commit (see _ref).
"""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, List, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    PrimaryKeyConstraint,
    REAL,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Stable constraint names, so a migration can drop or alter one by name.
NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

SANITIZERS = ("address", "memory", "undefined")


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


def _in(column: str, values) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _run_fk() -> Mapped[uuid.UUID]:
    # Deleting a run deletes everything it produced.
    return mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True
    )


def _ref(target: str, **kw) -> ForeignKey:
    """A reference from one record to another (not ownership).

    Checked at commit rather than per statement: deleting a run cascades down
    several paths at once (run -> agents, run -> logic groups -> analyses), and
    a per-statement check fires before the other path has removed the rows
    still pointing at a deleted agent.
    """
    return ForeignKey(target, deferrable=True, initially="DEFERRED", **kw)


def _created_at() -> Mapped[datetime]:
    return mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


def _ts(nullable: bool = True) -> Mapped[Optional[datetime]]:
    return mapped_column(DateTime(timezone=True), nullable=nullable)


def _lifecycle_checks(statuses, end_reasons) -> tuple:
    """status / end_reason / error, shared by runs, workers and agents.

    end_reason says which normal stop a `completed` was, so it exists exactly
    when the status is `completed`; error holds the traceback of an `error`.
    """
    return (
        CheckConstraint(_in("status", statuses), name="status"),
        CheckConstraint(_in("end_reason", end_reasons), name="end_reason"),
        CheckConstraint(
            "(end_reason IS NOT NULL) = (status = 'completed')",
            name="end_reason_iff_completed",
        ),
        CheckConstraint(
            "(error IS NOT NULL) = (status = 'error')", name="error_iff_error"
        ),
    )


# --- run --------------------------------------------------------------------


class Run(Base):
    __tablename__ = "runs"
    __table_args__ = (
        CheckConstraint("task_type = 'poc'", name="task_type"),
        CheckConstraint(_in("scan_mode", ("full", "delta")), name="scan_mode"),
        *_lifecycle_checks(
            ("preparing", "running", "completed", "cancelled", "error", "lost"),
            ("poc_target", "timeout", "budget"),
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    project_name: Mapped[str] = mapped_column(Text, nullable=False)
    task_type: Mapped[str] = mapped_column(Text, nullable=False)
    scan_mode: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    end_reason: Mapped[Optional[str]] = mapped_column(Text)
    error: Mapped[Optional[str]] = mapped_column(Text)
    heartbeat_at: Mapped[Optional[datetime]] = _ts()
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)
    config_given: Mapped[dict] = mapped_column(JSONB, nullable=False)
    workspace_path: Mapped[str] = mapped_column(Text, nullable=False)
    code_version: Mapped[Optional[str]] = mapped_column(Text)
    label: Mapped[Optional[str]] = mapped_column(Text, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    dispatched_at: Mapped[Optional[datetime]] = _ts()
    ended_at: Mapped[Optional[datetime]] = _ts()


# --- harnesses --------------------------------------------------------------


class Harness(Base):
    __tablename__ = "harnesses"
    __table_args__ = (UniqueConstraint("run_id", "name"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    run_id: Mapped[uuid.UUID] = _run_fk()
    name: Mapped[str] = mapped_column(Text, nullable=False)
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _created_at()


class HarnessBinary(Base):
    """One built (or placed) binary per harness and sanitizer."""

    __tablename__ = "harness_binaries"
    __table_args__ = (
        PrimaryKeyConstraint("harness_id", "sanitizer"),
        CheckConstraint(_in("sanitizer", SANITIZERS), name="sanitizer"),
    )

    harness_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("harnesses.id", ondelete="CASCADE")
    )
    sanitizer: Mapped[str] = mapped_column(Text)
    binary_path: Mapped[str] = mapped_column(Text, nullable=False)


# --- call graph index -------------------------------------------------------


class Graph(Base):
    """A function index / call graph file a run uses. The graph is not in PG."""

    __tablename__ = "graphs"
    __table_args__ = (
        UniqueConstraint("run_id", "commit"),
        CheckConstraint(
            "n_functions >= 0 AND n_edges >= 0 AND n_indirect_edges >= 0",
            name="counts",
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    run_id: Mapped[uuid.UUID] = _run_fk()
    commit: Mapped[str] = mapped_column(Text, nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    content_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    n_functions: Mapped[int] = mapped_column(Integer, nullable=False)
    n_edges: Mapped[int] = mapped_column(Integer, nullable=False)
    n_indirect_edges: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = _created_at()


class GraphHarness(Base):
    """A harness the graph has reachability for. No row: no graph for it."""

    __tablename__ = "graph_harnesses"
    __table_args__ = (
        PrimaryKeyConstraint("graph_id", "harness_id"),
        CheckConstraint("n_reachable >= 0 AND max_depth >= 0", name="counts"),
    )

    graph_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("graphs.id", ondelete="CASCADE")
    )
    harness_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("harnesses.id", ondelete="CASCADE")
    )
    n_reachable: Mapped[int] = mapped_column(Integer, nullable=False)
    max_depth: Mapped[int] = mapped_column(Integer, nullable=False)


# --- workers and agents -----------------------------------------------------


class Worker(Base):
    """One worker per harness."""

    __tablename__ = "workers"
    __table_args__ = (
        UniqueConstraint("run_id", "harness_id"),
        *_lifecycle_checks(
            ("queued", "running", "completed", "cancelled", "error", "lost"),
            ("work_done", "poc_target", "timeout", "budget"),
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    run_id: Mapped[uuid.UUID] = _run_fk()
    harness_id: Mapped[uuid.UUID] = mapped_column(
        _ref("harnesses.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(Text, nullable=False)
    end_reason: Mapped[Optional[str]] = mapped_column(Text)
    error: Mapped[Optional[str]] = mapped_column(Text)
    heartbeat_at: Mapped[Optional[datetime]] = _ts()
    celery_job_id: Mapped[Optional[str]] = mapped_column(Text)
    # For people reading the database; code builds the path with worker_dir().
    workspace_path: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _created_at()
    started_at: Mapped[Optional[datetime]] = _ts()
    ended_at: Mapped[Optional[datetime]] = _ts()


AGENT_TYPES = (
    "LGPlanningAgent",
    "FullVHGenerator",
    "LargeFullVHGenerator",
    "DeltaVHGenerator",
    "VHVerifier",
    "POCAgent",
    "POCReportAgent",
    "SeedAgent",
)
FULL_VH_FINDERS = ("FullVHGenerator", "LargeFullVHGenerator")


class Agent(Base):
    """One row per agent run. What it works on depends on its type."""

    __tablename__ = "agents"
    __table_args__ = (
        CheckConstraint(_in("agent_type", AGENT_TYPES), name="agent_type"),
        *_lifecycle_checks(
            ("running", "completed", "cancelled", "error", "lost"),
            ("work_done", "max_iterations", "poc_target", "timeout", "budget"),
        ),
        # Only a report agent on a global-fuzzer crash runs outside a worker.
        CheckConstraint(
            "worker_id IS NOT NULL OR agent_type = 'POCReportAgent'",
            name="worker_unless_report",
        ),
        CheckConstraint(
            "(crash_id IS NOT NULL) = (agent_type = 'POCReportAgent')",
            name="crash_iff_report",
        ),
        CheckConstraint(
            "(vh_id IS NOT NULL) = (agent_type IN ('VHVerifier', 'POCAgent'))",
            name="vh_iff_verifier_or_poc",
        ),
        # A full-scan VH finder is handed one function in one logic group, and
        # nothing else is handed a function.
        CheckConstraint(
            f"({_in('agent_type', FULL_VH_FINDERS)}) = (function_name IS NOT NULL)",
            name="function_iff_full_finder",
        ),
        CheckConstraint(
            "(function_file IS NULL) = (function_name IS NULL)"
            " AND (function_name IS NULL) = (function_start_line IS NULL)",
            name="function_all_or_none",
        ),
        CheckConstraint(
            f"lg_id IS NOT NULL OR NOT ({_in('agent_type', FULL_VH_FINDERS)})",
            name="full_finder_has_lg",
        ),
        CheckConstraint(
            f"lg_id IS NULL OR {_in('agent_type', FULL_VH_FINDERS + ('SeedAgent',))}",
            name="lg_only_finder_or_seed",
        ),
        CheckConstraint(
            "seeds_generated IS NULL OR agent_type = 'SeedAgent'",
            name="seeds_only_seed",
        ),
        CheckConstraint("iterations >= 0", name="iterations"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    run_id: Mapped[uuid.UUID] = _run_fk()
    worker_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("workers.id"), index=True
    )
    agent_type: Mapped[str] = mapped_column(Text, nullable=False)
    # agents <-> crashes / VHs / logic groups point at each other; these three
    # are added after the tables exist.
    crash_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("crashes.id", use_alter=True)
    )
    function_file: Mapped[Optional[str]] = mapped_column(Text)
    function_name: Mapped[Optional[str]] = mapped_column(Text)
    function_start_line: Mapped[Optional[int]] = mapped_column(Integer)
    vh_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("vulnerability_hypotheses.id", use_alter=True),
        index=True,
    )
    lg_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("logic_groups.id", use_alter=True)
    )
    status: Mapped[str] = mapped_column(Text, nullable=False)
    end_reason: Mapped[Optional[str]] = mapped_column(Text)
    error: Mapped[Optional[str]] = mapped_column(Text)
    iterations: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    seeds_generated: Mapped[Optional[int]] = mapped_column(Integer)
    log_path: Mapped[Optional[str]] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    ended_at: Mapped[Optional[datetime]] = _ts()


# --- logic groups -----------------------------------------------------------


class LogicGroup(Base):
    __tablename__ = "logic_groups"
    __table_args__ = (
        CheckConstraint(_in("risk_level", ("high", "medium", "low")), name="risk_level"),
        CheckConstraint("planned_functions >= 0", name="planned_functions"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    run_id: Mapped[uuid.UUID] = _run_fk()
    worker_id: Mapped[uuid.UUID] = mapped_column(
        _ref("workers.id"), nullable=False, index=True
    )
    created_by_agent_id: Mapped[uuid.UUID] = mapped_column(
        _ref("agents.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(Text, nullable=False)
    # Names as the LLM gave them; code resolves them against the function index.
    core_functions: Mapped[List[str]] = mapped_column(ARRAY(Text), nullable=False)
    entry_functions: Mapped[List[str]] = mapped_column(ARRAY(Text), nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text)
    planned_functions: Mapped[Optional[int]] = mapped_column(Integer)
    created_at: Mapped[datetime] = _created_at()


class FunctionAnalysis(Base):
    """A function a VH finder finished analysing within a logic group.

    A function is analysed at most once per group, so a key collision is a bug
    and is left to raise.
    """

    __tablename__ = "function_analysis"
    __table_args__ = (
        PrimaryKeyConstraint(
            "lg_id", "function_file", "function_name", "function_start_line"
        ),
        CheckConstraint(
            "function_start_line > 0 AND function_end_line >= function_start_line",
            name="lines",
        ),
    )

    lg_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("logic_groups.id", ondelete="CASCADE")
    )
    function_file: Mapped[str] = mapped_column(Text)
    function_name: Mapped[str] = mapped_column(Text)
    function_start_line: Mapped[int] = mapped_column(Integer)
    function_end_line: Mapped[int] = mapped_column(Integer, nullable=False)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        _ref("agents.id"), nullable=False
    )
    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# --- vulnerability hypotheses ----------------------------------------------

VH_STATUSES = (
    "pending_verify",
    "verifying",
    "rejected",
    "pending_poc",
    "generating_poc",
    "poc_generated",
    "poc_failed",
)


class VulnerabilityHypothesis(Base):
    """A VH, owned for its whole life by the worker that found it."""

    __tablename__ = "vulnerability_hypotheses"
    __table_args__ = (
        CheckConstraint(_in("status", VH_STATUSES), name="status"),
        CheckConstraint(_in("sanitizer", SANITIZERS), name="sanitizer"),
        CheckConstraint("finder_score BETWEEN 0 AND 1", name="finder_score"),
        CheckConstraint("score BETWEEN 0 AND 1", name="score"),
        # A located sink was located from the code the LLM quoted.
        CheckConstraint(
            "sink_line IS NULL OR sink_code IS NOT NULL", name="sink_line_needs_code"
        ),
        # Only a VH injected by hand may lack the sink line.
        CheckConstraint(
            "created_by_agent_id IS NULL OR sink_code IS NOT NULL",
            name="agent_vh_has_sink",
        ),
        # What a worker picks next: its own, in a status, best score first.
        Index("ix_vh_worker_status_score", "worker_id", "status", "score"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    run_id: Mapped[uuid.UUID] = _run_fk()
    worker_id: Mapped[uuid.UUID] = mapped_column(
        _ref("workers.id"), nullable=False
    )
    function_file: Mapped[str] = mapped_column(Text, nullable=False)
    function_name: Mapped[str] = mapped_column(Text, nullable=False)
    sink_code: Mapped[Optional[str]] = mapped_column(Text)
    sink_line: Mapped[Optional[int]] = mapped_column(Integer)
    lg_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("logic_groups.id")
    )
    # NULL: the configured default sanitizer, resolved when a PoC runs.
    sanitizer: Mapped[Optional[str]] = mapped_column(Text)
    # NULL: injected by hand rather than found by an agent.
    created_by_agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("agents.id")
    )
    finder_description: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    finder_score: Mapped[float] = mapped_column(REAL, nullable=False)
    score: Mapped[float] = mapped_column(REAL, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    verifier_reproduced: Mapped[Optional[bool]] = mapped_column(Boolean)
    evidence: Mapped[Optional[str]] = mapped_column(Text)
    important_controlflow: Mapped[Optional[str]] = mapped_column(Text)
    verification_notes: Mapped[Optional[str]] = mapped_column(Text)
    poc_guidance: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = _created_at()


class VHMerge(Base):
    """A later report of the same VH within one worker, folded into it."""

    __tablename__ = "vh_merges"
    __table_args__ = (
        CheckConstraint("finder_score BETWEEN 0 AND 1", name="finder_score"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    vh_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vulnerability_hypotheses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("agents.id")
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    finder_score: Mapped[float] = mapped_column(REAL, nullable=False)
    merged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# --- PoC attempts and crashes -----------------------------------------------


class PocAttempt(Base):
    """Every input run against a binary, crashing or not."""

    __tablename__ = "poc_attempts"
    __table_args__ = (
        CheckConstraint(
            _in("source", ("vh_agent", "global_fuzzer", "vh_fuzzer")), name="source"
        ),
        CheckConstraint(
            _in("status", ("pending", "crashed", "no_crash", "error")), name="status"
        ),
        CheckConstraint(_in("sanitizer", SANITIZERS), name="sanitizer"),
        # The input ran on a binary that exists (a reference, see _ref).
        ForeignKeyConstraint(
            ["harness_id", "sanitizer"],
            ["harness_binaries.harness_id", "harness_binaries.sanitizer"],
            deferrable=True,
            initially="DEFERRED",
        ),
        CheckConstraint(
            "(crash_id IS NOT NULL) = (status = 'crashed')", name="crash_iff_crashed"
        ),
        CheckConstraint(
            "(sanitizer_output IS NOT NULL) = (status = 'crashed')",
            name="output_iff_crashed",
        ),
        # Which columns each source fills.
        CheckConstraint(
            "source <> 'vh_agent' OR (vh_id IS NOT NULL AND agent_id IS NOT NULL"
            " AND worker_id IS NOT NULL AND attempt IS NOT NULL"
            " AND variant IS NOT NULL AND generator_code IS NOT NULL)",
            name="vh_agent_columns",
        ),
        CheckConstraint(
            "source <> 'vh_fuzzer' OR (vh_id IS NOT NULL AND agent_id IS NULL"
            " AND worker_id IS NOT NULL AND attempt IS NULL"
            " AND variant IS NULL AND generator_code IS NULL)",
            name="vh_fuzzer_columns",
        ),
        CheckConstraint(
            "source <> 'global_fuzzer' OR (vh_id IS NULL AND agent_id IS NULL"
            " AND worker_id IS NULL AND attempt IS NULL"
            " AND variant IS NULL AND generator_code IS NULL)",
            name="global_fuzzer_columns",
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    run_id: Mapped[uuid.UUID] = _run_fk()
    vh_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("vulnerability_hypotheses.id"), index=True
    )
    worker_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("workers.id")
    )
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("agents.id"), index=True
    )
    source: Mapped[str] = mapped_column(Text, nullable=False)
    harness_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    sanitizer: Mapped[str] = mapped_column(Text, nullable=False)
    attempt: Mapped[Optional[int]] = mapped_column(Integer)
    variant: Mapped[Optional[int]] = mapped_column(Integer)
    blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    blob_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    generator_code: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    sanitizer_output: Mapped[Optional[str]] = mapped_column(Text)
    crash_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("crashes.id"), index=True
    )
    created_at: Mapped[datetime] = _created_at()


class Crash(Base):
    """One distinct bug: every crash signature a run found, once."""

    __tablename__ = "crashes"
    __table_args__ = (UniqueConstraint("run_id", "signature"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    run_id: Mapped[uuid.UUID] = _run_fk()
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    # 'unknown' when the sanitizer report names no type.
    vuln_type: Mapped[str] = mapped_column(Text, nullable=False)
    first_attempt_id: Mapped[uuid.UUID] = mapped_column(
        _ref("poc_attempts.id", use_alter=True),
        nullable=False,
    )
    package_path: Mapped[Optional[str]] = mapped_column(Text)
    report: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = _created_at()


# --- LLM and tool calls -----------------------------------------------------

LLM_ROLES = ("lg_planner", "finder", "verifier", "poc", "seed", "utility")


class LLMMessage(Base):
    """A message sent to or received from a model, stored once per run."""

    __tablename__ = "llm_messages"
    __table_args__ = (
        UniqueConstraint("run_id", "sha256"),
        CheckConstraint(
            _in("role", ("system", "user", "assistant", "tool")), name="role"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    sha256: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    content: Mapped[Any] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = _created_at()


class LLMCall(Base):
    """One model call, failed calls included. Every cost total sums these.

    Token counts and cost a model does not report are NULL, never 0; a failed
    call may report no tokens at all.
    """

    __tablename__ = "llm_calls"
    __table_args__ = (
        CheckConstraint(_in("role", LLM_ROLES), name="role"),
        CheckConstraint(
            "input_tokens >= 0 AND output_tokens >= 0"
            " AND cache_read_tokens >= 0 AND cache_creation_tokens >= 0"
            " AND reasoning_tokens >= 0 AND cost >= 0 AND latency_ms >= 0",
            name="non_negative",
        ),
        CheckConstraint(
            "(output_message_id IS NOT NULL) = success", name="output_iff_success"
        ),
        CheckConstraint("error_msg IS NULL OR NOT success", name="error_only_failed"),
        # Every model reports these on success; a failed call may have none.
        CheckConstraint(
            "NOT success OR (input_tokens IS NOT NULL AND output_tokens IS NOT NULL)",
            name="tokens_on_success",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    run_id: Mapped[uuid.UUID] = _run_fk()
    worker_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("workers.id"), index=True
    )
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        _ref("agents.id"), index=True
    )
    role: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str] = mapped_column(Text, nullable=False)
    requested_model: Mapped[Optional[str]] = mapped_column(Text)
    # The parameters actually sent, after per-model rewriting.
    params: Mapped[dict] = mapped_column(JSONB, nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    input_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    output_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    cache_read_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    cache_creation_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    reasoning_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    cost: Mapped[Optional[Decimal]] = mapped_column(Numeric(12, 6))
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error_msg: Mapped[Optional[str]] = mapped_column(Text)
    # The messages actually sent, in order (llm_messages ids; an array cannot
    # carry a foreign key).
    input_message_ids: Mapped[List[int]] = mapped_column(
        ARRAY(BigInteger), nullable=False
    )
    output_message_id: Mapped[Optional[int]] = mapped_column(
        _ref("llm_messages.id")
    )
    created_at: Mapped[datetime] = _created_at()


class ToolCall(Base):
    """One tool execution. Its arguments and result are in llm_messages."""

    __tablename__ = "tool_calls"
    __table_args__ = (
        CheckConstraint("latency_ms >= 0", name="latency"),
        CheckConstraint("error IS NULL OR NOT success", name="error_only_failed"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    run_id: Mapped[uuid.UUID] = _run_fk()
    llm_call_id: Mapped[int] = mapped_column(
        _ref("llm_calls.id"), nullable=False, index=True
    )
    result_message_id: Mapped[Optional[int]] = mapped_column(
        _ref("llm_messages.id")
    )
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error: Mapped[Optional[str]] = mapped_column(Text)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = _created_at()
