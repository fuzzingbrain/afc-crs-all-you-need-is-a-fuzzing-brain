"""
Agent Context

Provides isolated runtime context for each Agent instance.
Uses MongoDB ObjectId as unique identifier for both runtime isolation and persistence.

Hierarchy:
    Task (ObjectId)
    └── Worker (ObjectId)
        └── Agent (ObjectId)

Persistence Strategy:
    - Initial save on __enter__ (status: running)
    - Periodic save every N iterations or on significant events
    - Final save on __exit__ (status: completed/failed)
    - Incremental updates using $set for efficiency
"""

import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional

from bson import ObjectId
from loguru import logger

from ..core.utils import safe_object_id


# Global registry of active agent contexts
_agent_contexts: Dict[str, "AgentContext"] = {}
_agent_contexts_lock = threading.Lock()


def get_agent_context(agent_id: str) -> Optional["AgentContext"]:
    """Get agent context by ID."""
    with _agent_contexts_lock:
        return _agent_contexts.get(agent_id)


def get_all_agent_contexts() -> Dict[str, "AgentContext"]:
    """Get all active agent contexts (copy)."""
    with _agent_contexts_lock:
        return dict(_agent_contexts)


class AgentContext:
    """
    Encapsulates all runtime resources for a single Agent instance.

    Features:
    - Unique ObjectId for isolation and persistence
    - Context manager for automatic lifecycle management
    - Centralized state management for tools
    - Periodic persistence to MongoDB
    - Real-time status updates

    Usage:
        with AgentContext(task_id, worker_id, "POVAgent") as ctx:
            # ctx.agent_id is unique
            # Tools can look up ctx by agent_id
            ctx.increment_iteration()  # Auto-persists periodically
            ...
        # Automatically cleaned up and persisted

    Persistence:
        - Saves on enter (status: running)
        - Saves every 5 iterations
        - Saves on significant events (SP created, POV generated)
        - Saves on exit (status: completed/failed)
    """

    # Save every N iterations
    SAVE_INTERVAL_ITERATIONS = 5
    # Minimum interval between saves (seconds)
    SAVE_INTERVAL_SECONDS = 10.0

    def __init__(
        self,
        task_id: str,
        worker_id: str,
        agent_type: str,
        target: str = "",
        fuzzer: str = "",
        sanitizer: str = "",
    ):
        """
        Initialize agent context.

        Args:
            task_id: Task ID (MongoDB ObjectId string)
            worker_id: Worker ID (MongoDB ObjectId string)
            agent_type: Agent class name (e.g., "POVAgent", "FullSPGenerator")
            target: Target being analyzed (function_name or sp_id)
            fuzzer: Fuzzer name
            sanitizer: Sanitizer type
        """
        # Unique identifier - MongoDB ObjectId
        self.agent_id = str(ObjectId())

        # Identity
        self.task_id = task_id
        self.worker_id = worker_id
        self.agent_type = agent_type
        self.target = target
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer

        # Lifecycle state
        self.started_at: Optional[datetime] = None
        self.ended_at: Optional[datetime] = None
        self.status: str = "pending"  # pending | running | completed | failed
        self.iterations: int = 0
        self.tool_calls: int = 0
        self.error: Optional[str] = None

        # Result summary (populated by agent)
        self.result_summary: Dict[str, Any] = {}

        # Log storage path (set after saving)
        self.log_path: Optional[str] = None

        # === Tool-specific state ===

        # POV Agent state
        self.pov_iteration: int = 0
        self.pov_attempt: int = 0
        self.fuzzer_path: Optional[str] = None
        self.sp_id: Optional[str] = None

        # Seed Agent state
        self.direction_id: Optional[str] = None
        self.delta_id: Optional[str] = None
        self.seeds_generated: int = 0
        self.fuzzer_manager: Any = None  # FuzzerManager instance

        # SP Generator state
        self.sp_created: bool = False
        self.sp_details: Optional[Dict[str, Any]] = None

        # SP Verifier state
        self.verify_result: Optional[Dict[str, Any]] = None

        # LLM usage aggregates (updated by flush)
        self.llm_calls: int = 0
        self.llm_cost: float = 0.0
        self.llm_input_tokens: int = 0
        self.llm_output_tokens: int = 0

        # Back-reference to BaseAgent (set by run_async for cancellation)
        self.agent = None

        # Persistence tracking
        self._dirty = False
        self._last_save_time: float = 0
        self._last_save_iteration: int = 0
        self._save_lock = threading.Lock()

    def __enter__(self) -> "AgentContext":
        """Enter context - register and start tracking."""
        if self.status == "running":
            return self

        self.started_at = datetime.now()
        self.status = "running"

        with _agent_contexts_lock:
            _agent_contexts[self.agent_id] = self

        # Persist initial record to MongoDB
        self._save_to_db(force=True)
        self._last_save_time = time.time()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context - cleanup and persist."""
        self.ended_at = datetime.now()

        if exc_type:
            self.status = "failed"
            self.error = str(exc_val) if exc_val else str(exc_type)
        elif self.status != "cancelled":
            self.status = "completed"

        # Persist final state to MongoDB with retry.
        # Layer 1: Retry with backoff for transient DB failures.
        # Layer 2: If all retries fail, keep in memory registry so
        #          query APIs return correct status via in-memory merge.
        saved = False
        for attempt in range(3):
            saved = self._save_to_db(force=True)
            if saved:
                break
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))

        if saved:
            with _agent_contexts_lock:
                _agent_contexts.pop(self.agent_id, None)
        else:
            logger.warning(
                f"Agent {self.agent_id[:8]}: final save failed after 3 attempts, "
                f"keeping in memory registry with status={self.status}"
            )

    def cancel(self) -> None:
        """Cancel this agent context and its underlying agent."""
        self.status = "cancelled"
        if self.agent is not None:
            self.agent.cancel()

    def _save_to_db(self, force: bool = False) -> bool:
        """
        Save agent record to MongoDB.

        Args:
            force: If True, save immediately regardless of dirty state or timing

        Returns:
            True if saved, False if skipped
        """
        with self._save_lock:
            # Skip if not dirty and not forced
            if not force and not self._dirty:
                return False

            # Skip if saved recently (unless forced)
            time_since_save = time.time() - self._last_save_time
            iter_since_save = self.iterations - self._last_save_iteration

            if not force:
                if time_since_save < self.SAVE_INTERVAL_SECONDS:
                    if iter_since_save < self.SAVE_INTERVAL_ITERATIONS:
                        return False

            try:
                from ..db import get_database

                db = get_database()
                if db is None:
                    return False

                doc = {
                    "_id": safe_object_id(
                        self.agent_id
                    ),  # May be ObjectId or custom string
                    "task_id": safe_object_id(self.task_id),
                    # Store worker_id as ObjectId reference for proper foreign key linking
                    "worker_id": safe_object_id(self.worker_id),
                    "agent_type": self.agent_type,
                    "target": self.target,
                    "fuzzer": self.fuzzer,
                    "sanitizer": self.sanitizer,
                    "status": self.status,
                    "started_at": self.started_at,
                    "ended_at": self.ended_at,
                    "iterations": self.iterations,
                    "tool_calls": self.tool_calls,
                    "error": self.error,
                    "result_summary": self.result_summary,
                    "log_path": self.log_path,
                    # Tool-specific state (for recovery/debugging)
                    "sp_id": self.sp_id,  # SP being processed (POV Agent)
                    "direction_id": self.direction_id,  # Direction being processed (Seed Agent)
                    "delta_id": self.delta_id,  # Delta scan ID
                    "sp_created": self.sp_created,
                    "seeds_generated": self.seeds_generated,
                    "pov_iteration": self.pov_iteration,
                    "pov_attempt": self.pov_attempt,
                    # NOTE: llm_calls/llm_cost/llm_input_tokens/llm_output_tokens
                    # are managed exclusively by WorkerLLMBuffer via $inc.
                    # Do NOT $set them here — it would overwrite the buffer's increments.
                    "updated_at": datetime.now(),
                }

                # Upsert - insert or update
                db.agents.update_one(
                    {"_id": safe_object_id(self.agent_id)},
                    {"$set": doc},
                    upsert=True,
                )

                self._dirty = False
                self._last_save_time = time.time()
                self._last_save_iteration = self.iterations
                return True

            except Exception as e:
                # Log but don't fail agent execution
                logger.warning(f"Failed to save agent context: {e}")
                return False

    def _mark_dirty_and_maybe_save(self) -> None:
        """Mark as dirty and save if enough time/iterations have passed."""
        self._dirty = True
        self._save_to_db(force=False)

    # =========================================================================
    # Increment methods - auto-persist periodically
    # =========================================================================

    def increment_iteration(self) -> None:
        """Increment iteration counter and maybe persist."""
        self.iterations += 1
        self._mark_dirty_and_maybe_save()

    def increment_tool_calls(self) -> None:
        """Increment tool call counter."""
        self.tool_calls += 1
        self._dirty = True
        # Don't save on every tool call, let iteration handle it

    def set_sp_created(self, sp_details: Dict[str, Any]) -> None:
        """Mark SP as created and persist immediately."""
        self.sp_created = True
        self.sp_details = sp_details
        self.result_summary["sp_created"] = True
        self.result_summary["sp_details"] = sp_details
        self._dirty = True
        self._save_to_db(force=True)

    def set_seeds_generated(self, count: int) -> None:
        """Update seeds generated count and persist."""
        self.seeds_generated = count
        self._mark_dirty_and_maybe_save()

    def set_pov_progress(self, iteration: int, attempt: int) -> None:
        """Update POV progress and persist."""
        self.pov_iteration = iteration
        self.pov_attempt = attempt
        self._mark_dirty_and_maybe_save()

    def set_verify_result(self, result: Dict[str, Any]) -> None:
        """Set verification result and persist immediately."""
        self.verify_result = result
        self.result_summary["verify_result"] = result
        self._dirty = True
        self._save_to_db(force=True)

    def update_result_summary(self, **kwargs) -> None:
        """Update result summary with key-value pairs."""
        self.result_summary.update(kwargs)
        self._mark_dirty_and_maybe_save()

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def duration_seconds(self) -> float:
        """Get duration in seconds."""
        if self.started_at and self.ended_at:
            return (self.ended_at - self.started_at).total_seconds()
        elif self.started_at:
            return (datetime.now() - self.started_at).total_seconds()
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "agent_type": self.agent_type,
            "target": self.target,
            "fuzzer": self.fuzzer,
            "sanitizer": self.sanitizer,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": self.duration_seconds,
            "iterations": self.iterations,
            "tool_calls": self.tool_calls,
            "error": self.error,
            "result_summary": self.result_summary,
            "log_path": self.log_path,
            # Tool-specific state
            "sp_id": self.sp_id,
            "direction_id": self.direction_id,
            "delta_id": self.delta_id,
            "sp_created": self.sp_created,
            "seeds_generated": self.seeds_generated,
            "pov_iteration": self.pov_iteration,
            "pov_attempt": self.pov_attempt,
            # LLM usage
            "llm_calls": self.llm_calls,
            "llm_cost": self.llm_cost,
            "llm_input_tokens": self.llm_input_tokens,
            "llm_output_tokens": self.llm_output_tokens,
        }

    def __repr__(self) -> str:
        return (
            f"AgentContext(id={self.agent_id[:8]}..., "
            f"type={self.agent_type}, status={self.status})"
        )


# =============================================================================
# Monitoring API
# =============================================================================


def get_agent_status(agent_id: str) -> Optional[Dict[str, Any]]:
    """
    Get agent status from memory or database.

    First checks in-memory registry (for running agents),
    then falls back to database (for completed agents).

    Args:
        agent_id: Agent ID (ObjectId string)

    Returns:
        Agent status dict or None if not found
    """
    # Check in-memory first (running agents)
    ctx = get_agent_context(agent_id)
    if ctx:
        return ctx.to_dict()

    # Fall back to database (completed agents)
    try:
        from ..db import get_database

        db = get_database()
        if db is None:
            return None

        doc = db.agents.find_one({"_id": ObjectId(agent_id)})
        if doc:
            # Convert ObjectId to string
            doc["agent_id"] = str(doc.pop("_id"))
            doc["task_id"] = str(doc["task_id"]) if doc.get("task_id") else None
            doc["worker_id"] = str(doc["worker_id"]) if doc.get("worker_id") else None
            return doc

    except Exception:
        pass

    return None


def get_agents_by_worker(worker_id: str) -> list:
    """
    Get all agents for a worker.

    Args:
        worker_id: Worker ID (ObjectId string)

    Returns:
        List of agent status dicts
    """
    agents = []

    try:
        from ..db import get_database

        db = get_database()
        if db is None:
            return agents

        cursor = db.agents.find({"worker_id": ObjectId(worker_id)})
        for doc in cursor:
            doc["agent_id"] = str(doc.pop("_id"))
            doc["task_id"] = str(doc["task_id"]) if doc.get("task_id") else None
            doc["worker_id"] = str(doc["worker_id"]) if doc.get("worker_id") else None
            agents.append(doc)

    except Exception:
        pass

    # Merge with in-memory data (for running agents with fresher stats)
    in_memory = get_all_agent_contexts()
    for ctx in in_memory.values():
        if ctx.worker_id == worker_id:
            # Replace or add in-memory version
            found = False
            for i, a in enumerate(agents):
                if a["agent_id"] == ctx.agent_id:
                    agents[i] = ctx.to_dict()
                    found = True
                    break
            if not found:
                agents.append(ctx.to_dict())

    return agents


def get_agents_by_task(task_id: str) -> list:
    """
    Get all agents for a task.

    Args:
        task_id: Task ID (ObjectId string)

    Returns:
        List of agent status dicts
    """
    agents = []

    try:
        from ..db import get_database

        db = get_database()
        if db is None:
            return agents

        cursor = db.agents.find({"task_id": ObjectId(task_id)})
        for doc in cursor:
            doc["agent_id"] = str(doc.pop("_id"))
            doc["task_id"] = str(doc["task_id"]) if doc.get("task_id") else None
            doc["worker_id"] = str(doc["worker_id"]) if doc.get("worker_id") else None
            agents.append(doc)

    except Exception:
        pass

    # Merge with in-memory data
    in_memory = get_all_agent_contexts()
    for ctx in in_memory.values():
        if ctx.task_id == task_id:
            found = False
            for i, a in enumerate(agents):
                if a["agent_id"] == ctx.agent_id:
                    agents[i] = ctx.to_dict()
                    found = True
                    break
            if not found:
                agents.append(ctx.to_dict())

    return agents


def get_active_agents() -> list:
    """
    Get all currently running agents.

    Returns:
        List of active agent status dicts
    """
    return [ctx.to_dict() for ctx in get_all_agent_contexts().values()]


def cancel_agents_by_worker(worker_id: str) -> int:
    """
    Cancel all running agents for a given worker.

    Best-effort: logs errors but does not raise.

    Args:
        worker_id: Worker ID (ObjectId string)

    Returns:
        Number of agents cancelled
    """
    cancelled = 0
    for ctx in get_all_agent_contexts().values():
        if ctx.worker_id == worker_id and ctx.status == "running":
            try:
                ctx.cancel()
                cancelled += 1
                logger.info(f"Cancelled agent {ctx.agent_id[:8]} ({ctx.agent_type})")
            except Exception as e:
                logger.warning(f"Failed to cancel agent {ctx.agent_id[:8]}: {e}")
    return cancelled


def force_cleanup_agents(task_id: str, db) -> int:
    """
    Force-update any still-running agent records in MongoDB for a task.

    Catches agents whose in-memory cancel did not persist
    (e.g. process was killed before __exit__).

    Args:
        task_id: Task ID (ObjectId string)
        db: MongoDB database handle

    Returns:
        Number of agent records updated
    """
    try:
        result = db.agents.update_many(
            {"task_id": ObjectId(task_id), "status": "running"},
            {"$set": {"status": "cancelled", "ended_at": datetime.now()}},
        )
        count = result.modified_count
        if count:
            logger.info(f"Force-cleaned {count} zombie agent(s) for task {task_id[:8]}")
        return count
    except Exception as e:
        logger.warning(f"force_cleanup_agents failed: {e}")
        return 0
