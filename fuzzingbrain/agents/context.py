# SPDX-License-Identifier: Apache-2.0
"""
Agent context: one per agent run, and its row in the agents table.

The row is inserted when the context opens (status running), with what the
agent works on -- its VH, logic group, crash or function, depending on the
type (the table's CHECKs say which) -- and closed when it exits:

    completed + end_reason   the agent stopped normally
    cancelled                the run stopped it
    error + traceback        it raised

Tools find the context of the agent calling them with get_agent_context().
"""

import threading
import traceback
import uuid
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import logging

logger = logging.getLogger(__name__)

_agent_contexts: Dict[str, "AgentContext"] = {}
_agent_contexts_lock = threading.Lock()

# What an agent's stop_reason becomes in agents.end_reason.
_END_REASONS = {
    None: "work_done",
    "": "work_done",
    "completed": "work_done",
    "work_done": "work_done",
    "max_iterations": "max_iterations",
    "poc_target": "poc_target",
    "timeout": "timeout",
    "budget": "budget",
}


def get_agent_context(agent_id: str) -> Optional["AgentContext"]:
    with _agent_contexts_lock:
        return _agent_contexts.get(str(agent_id))


def get_all_agent_contexts() -> Dict[str, "AgentContext"]:
    with _agent_contexts_lock:
        return dict(_agent_contexts)


def _store():
    from ..db.store import get_store

    return get_store()


class AgentContext:
    """Runtime state of one agent, and its agents row."""

    PROGRESS_EVERY = 5  # iterations between progress writes

    def __init__(
        self,
        run_id: str,
        worker_id: Optional[str],
        agent_type: str,
        target: str = "",
        fuzzer: str = "",
        sanitizer: str = "",
        vh_id: Optional[str] = None,
        lg_id: Optional[str] = None,
        crash_id: Optional[str] = None,
        function: Optional[Tuple[str, str, int]] = None,
        agent_id: Optional[str] = None,
    ):
        self.agent_id = agent_id or str(uuid.uuid4())
        self.run_id = run_id
        self.worker_id = worker_id or None
        self.agent_type = agent_type
        self.target = target
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.vh_id = vh_id
        self.lg_id = lg_id
        self.crash_id = crash_id
        self.function = function

        self.started_at: Optional[datetime] = None
        self.ended_at: Optional[datetime] = None
        self.status = "pending"
        self.stop_reason: Optional[str] = None
        self.iterations = 0
        self.tool_calls = 0
        self.error: Optional[str] = None
        self.log_path: Optional[str] = None
        self.result_summary: Dict[str, Any] = {}

        # Tool state
        self.poc_iteration = 0
        self.poc_attempt = 0
        self.fuzzer_path: Optional[str] = None
        self.delta_id: Optional[str] = None
        self.seeds_generated = 0
        self.fuzzer_manager: Any = None
        self.vh_created = False
        self.vh_details: Optional[Dict[str, Any]] = None
        self.verify_result: Optional[Dict[str, Any]] = None

        self.agent = None  # the BaseAgent, for cancel()
        self._row = False
        self._last_progress = 0

    # ------------------------------------------------------------ lifecycle

    def __enter__(self) -> "AgentContext":
        if self.status == "running":
            return self
        self.started_at = datetime.now()
        self.status = "running"
        with _agent_contexts_lock:
            _agent_contexts[self.agent_id] = self
        try:
            _store().start_agent(
                self.agent_id,
                self.run_id,
                self.worker_id,
                self.agent_type,
                vh_id=self.vh_id if self.agent_type in ("VHVerifier", "POCAgent") else None,
                lg_id=self.lg_id,
                crash_id=self.crash_id,
                function=self.function,
                log_path=self.log_path,
            )
            self._row = True
        except Exception as e:
            # Every LLM call of this agent names it: without the row they
            # cannot be written either, so this is worth saying loudly.
            logger.error(f"agent {self.agent_type} {self.agent_id[:8]}: no agents row: {e}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.ended_at = datetime.now()
        if exc_type is not None:
            self.status = "error"
            self.error = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
        elif self.status == "cancelled" or self.stop_reason == "cancelled":
            self.status = "cancelled"
        elif self.stop_reason == "error":
            self.status = "error"
            self.error = self.error or "the agent stopped on an error"
        else:
            self.status = "completed"
        if self._row:
            try:
                _store().end_agent(
                    self.agent_id,
                    self.status,
                    end_reason=_END_REASONS.get(self.stop_reason, "work_done")
                    if self.status == "completed"
                    else None,
                    error=self.error if self.status == "error" else None,
                    iterations=self.iterations,
                    seeds_generated=self.seeds_generated
                    if self.agent_type == "SeedAgent"
                    else None,
                )
            except Exception as e:
                logger.warning(f"agent {self.agent_id[:8]}: could not close its row: {e}")
        with _agent_contexts_lock:
            _agent_contexts.pop(self.agent_id, None)

    def cancel(self) -> None:
        self.status = "cancelled"
        if self.agent is not None:
            self.agent.cancel()

    # ------------------------------------------------------------- progress

    def _progress(self, force: bool = False) -> None:
        if not self._row:
            return
        if not force and self.iterations - self._last_progress < self.PROGRESS_EVERY:
            return
        self._last_progress = self.iterations
        try:
            _store().agent_progress(
                self.agent_id,
                iterations=self.iterations,
                seeds_generated=self.seeds_generated
                if self.agent_type == "SeedAgent"
                else None,
                log_path=self.log_path,
            )
        except Exception as e:
            logger.debug(f"agent {self.agent_id[:8]}: progress write failed: {e}")

    def increment_iteration(self) -> None:
        self.iterations += 1
        self._progress()

    def increment_tool_calls(self) -> None:
        self.tool_calls += 1

    def set_vh_created(self, vh_details: Dict[str, Any]) -> None:
        self.vh_created = True
        self.vh_details = vh_details

    def set_seeds_generated(self, count: int) -> None:
        self.seeds_generated = count
        self._progress(force=True)

    def set_log_path(self, log_path: str) -> None:
        """Written at once: the transcript is found through it while running."""
        self.log_path = log_path
        self._progress(force=True)

    def set_poc_progress(self, iteration: int, attempt: int) -> None:
        self.poc_iteration = iteration
        self.poc_attempt = attempt

    def set_verify_result(self, result: Dict[str, Any]) -> None:
        self.verify_result = result

    def update_result_summary(self, **kwargs) -> None:
        self.result_summary.update(kwargs)

    @property
    def duration_seconds(self) -> float:
        if self.started_at and self.ended_at:
            return (self.ended_at - self.started_at).total_seconds()
        if self.started_at:
            return (datetime.now() - self.started_at).total_seconds()
        return 0.0

    def __repr__(self) -> str:
        return f"AgentContext(id={self.agent_id[:8]}, type={self.agent_type}, status={self.status})"


def cancel_agents_by_worker(worker_id: str) -> int:
    """Cancel this process's running agents of one worker."""
    n = 0
    for ctx in get_all_agent_contexts().values():
        if str(ctx.worker_id) == str(worker_id) and ctx.status == "running":
            ctx.cancel()
            n += 1
    return n
