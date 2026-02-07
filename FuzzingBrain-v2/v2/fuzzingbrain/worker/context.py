"""
Worker Context

Provides isolated runtime context for each Worker instance.
Uses MongoDB ObjectId as unique identifier for both runtime isolation and persistence.

This is the ONLY place where Worker records are created and persisted.
Dispatcher does NOT create Worker records - it only dispatches Celery tasks.

Hierarchy:
    Task (ObjectId)
    └── Worker (ObjectId)  ← Created here
        └── Agent (ObjectId)

Persistence Strategy:
    - Initial save on __enter__ (status: running)
    - Periodic save every N seconds or on significant events
    - Final save on __exit__ (status: completed/failed)
    - Writes directly to 'workers' collection
"""

import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional, Callable

from bson import ObjectId
from loguru import logger

from ..core.utils import safe_object_id


# Global registry of active worker contexts
_worker_contexts: Dict[str, "WorkerContext"] = {}
_worker_contexts_lock = threading.Lock()


def get_worker_context(worker_id: str) -> Optional["WorkerContext"]:
    """Get worker context by ID."""
    with _worker_contexts_lock:
        return _worker_contexts.get(worker_id)


def get_all_worker_contexts() -> Dict[str, "WorkerContext"]:
    """Get all active worker contexts (copy)."""
    with _worker_contexts_lock:
        return dict(_worker_contexts)


class WorkerContext:
    """
    Encapsulates all runtime resources for a single Worker instance.

    This is the canonical source for Worker records in MongoDB.
    Dispatcher does NOT create Worker records - WorkerContext does.

    Features:
    - Unique ObjectId for isolation and persistence
    - Context manager for automatic lifecycle management
    - Links to parent Task via task_id (ObjectId)
    - All child Agents link back via worker_id (ObjectId)
    - Periodic persistence to MongoDB 'workers' collection
    - Real-time status updates

    Usage:
        with WorkerContext(task_id, fuzzer, sanitizer) as ctx:
            # ctx.worker_id is unique ObjectId
            # Pass ctx.worker_id to all Agents
            ctx.increment_agents_spawned()  # Auto-persists
            ...
        # Automatically cleaned up and persisted

    Persistence:
        - Saves on enter (status: running)
        - Saves on significant events (agent spawn, SP found, etc.)
        - Saves periodically if dirty
        - Saves on exit (status: completed/failed)
    """

    # Minimum interval between saves (seconds)
    SAVE_INTERVAL = 5.0

    def __init__(
        self,
        task_id: str,
        fuzzer: str,
        sanitizer: str,
        scan_mode: str = "full",
        project_name: str = "",
        task_type: str = "pov",
        workspace_path: str = "",
        celery_job_id: str = None,
    ):
        """
        Initialize worker context.

        Args:
            task_id: Task ID (MongoDB ObjectId string)
            fuzzer: Fuzzer name
            sanitizer: Sanitizer type
            scan_mode: Scan mode ("full" or "delta")
            project_name: Project name
            task_type: Job type (pov, patch, pov-patch, harness)
            workspace_path: Worker workspace path
            celery_job_id: Celery task ID (set by tasks.py)
        """
        # Unique identifier - MongoDB ObjectId
        self.worker_id = str(ObjectId())

        # Parent Task linkage (ObjectId)
        self.task_id = task_id

        # Celery job ID (for tracking)
        self.celery_job_id = celery_job_id

        # Worker identity
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.scan_mode = scan_mode
        self.project_name = project_name
        self.task_type = task_type
        self.workspace_path = workspace_path

        # Lifecycle state
        self.started_at: Optional[datetime] = None
        self.ended_at: Optional[datetime] = None
        self.status: str = "pending"  # pending | running | completed | failed
        self.error: Optional[str] = None

        # Statistics (these get incremented during execution)
        self.agents_spawned: int = 0
        self.agents_completed: int = 0
        self.agents_failed: int = 0
        self.sp_found: int = 0
        self.sp_verified: int = 0
        self.pov_generated: int = 0
        self.patch_generated: int = 0

        # Strategy tracking
        self.current_strategy: Optional[str] = None
        self.strategy_history: list = []

        # Phase timing (seconds) - for performance analysis
        self.phase_build: float = 0.0
        self.phase_reachability: float = 0.0
        self.phase_find_sp: float = 0.0
        self.phase_verify: float = 0.0
        self.phase_pov: float = 0.0
        self.phase_save: float = 0.0

        # LLM usage aggregates (updated by buffer flush)
        self.llm_calls: int = 0
        self.llm_cost: float = 0.0
        self.llm_input_tokens: int = 0
        self.llm_output_tokens: int = 0

        # Result summary
        self.result_summary: Dict[str, Any] = {}

        # Persistence tracking
        self._dirty = False
        self._last_save_time: float = 0
        self._save_lock = threading.Lock()

    def __enter__(self) -> "WorkerContext":
        """Enter context - register and start tracking."""
        self.started_at = datetime.now()
        self.status = "running"

        with _worker_contexts_lock:
            _worker_contexts[self.worker_id] = self

        # Persist initial record to MongoDB (synchronous, must succeed)
        self._save_to_db(force=True)
        self._last_save_time = time.time()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context - cleanup and persist."""
        self.ended_at = datetime.now()

        if exc_type:
            self.status = "failed"
            self.error = str(exc_val) if exc_val else str(exc_type)
        else:
            self.status = "completed"

        # Remove from global registry
        with _worker_contexts_lock:
            _worker_contexts.pop(self.worker_id, None)

        # Persist final state to MongoDB (synchronous, must succeed)
        self._save_to_db(force=True)

        # Cleanup Redis counters for this worker
        try:
            from ..llms.buffer import get_llm_call_buffer

            buffer = get_llm_call_buffer()
            if buffer:
                buffer.cleanup_worker_counters_sync(self.worker_id)
        except Exception as e:
            logger.warning(f"Failed to cleanup worker counters: {e}")

    def _save_to_db(self, force: bool = False) -> bool:
        """
        Save worker record to MongoDB 'workers' collection.

        This writes directly to the same collection used by WorkerRepository,
        ensuring Worker records are consistent across the system.

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
            if not force and (time.time() - self._last_save_time) < self.SAVE_INTERVAL:
                return False

            try:
                from ..db import get_database

                db = get_database()
                if db is None:
                    return False

                # Build document matching Worker model schema
                doc = {
                    "_id": safe_object_id(self.worker_id),
                    # Note: worker_id removed - use _id only
                    "celery_job_id": self.celery_job_id,
                    "task_id": safe_object_id(self.task_id),
                    # Identity
                    "task_type": self.task_type,
                    "fuzzer": self.fuzzer,
                    "sanitizer": self.sanitizer,
                    "scan_mode": self.scan_mode,
                    "project_name": self.project_name,
                    "workspace_path": self.workspace_path,
                    # Strategy
                    "current_strategy": self.current_strategy,
                    "strategy_history": self.strategy_history,
                    # Status
                    "status": self.status,
                    "error_msg": self.error,
                    # Statistics
                    "agents_spawned": self.agents_spawned,
                    "agents_completed": self.agents_completed,
                    "agents_failed": self.agents_failed,
                    "sp_found": self.sp_found,
                    "sp_verified": self.sp_verified,
                    "pov_generated": self.pov_generated,
                    "patch_generated": self.patch_generated,
                    # Timestamps
                    "created_at": self.started_at or datetime.now(),
                    "updated_at": datetime.now(),
                    "started_at": self.started_at,
                    "finished_at": self.ended_at,
                    # Phase timing
                    "phase_build": self.phase_build,
                    "phase_reachability": self.phase_reachability,
                    "phase_find_sp": self.phase_find_sp,
                    "phase_verify": self.phase_verify,
                    "phase_pov": self.phase_pov,
                    "phase_save": self.phase_save,
                    # LLM usage
                    "llm_calls": self.llm_calls,
                    "llm_cost": self.llm_cost,
                    "llm_input_tokens": self.llm_input_tokens,
                    "llm_output_tokens": self.llm_output_tokens,
                    # Result
                    "result_summary": self.result_summary,
                }

                # Upsert to 'workers' collection
                db.workers.update_one(
                    {"_id": safe_object_id(self.worker_id)},
                    {"$set": doc},
                    upsert=True,
                )

                self._dirty = False
                self._last_save_time = time.time()
                return True

            except Exception as e:
                # Log but don't fail worker execution
                logger.warning(f"Failed to save worker context: {e}")
                return False

    def _mark_dirty_and_maybe_save(self) -> None:
        """Mark as dirty and save if enough time has passed."""
        self._dirty = True
        self._save_to_db(force=False)

    # =========================================================================
    # Increment methods - auto-persist on significant events
    # =========================================================================

    def increment_agents_spawned(self) -> None:
        """Increment agents spawned counter and persist."""
        self.agents_spawned += 1
        self._mark_dirty_and_maybe_save()

    def increment_agents_completed(self) -> None:
        """Increment agents completed counter and persist."""
        self.agents_completed += 1
        self._mark_dirty_and_maybe_save()

    def increment_agents_failed(self) -> None:
        """Increment agents failed counter and persist."""
        self.agents_failed += 1
        self._mark_dirty_and_maybe_save()

    def increment_sp_found(self, count: int = 1) -> None:
        """Increment SP found counter and persist."""
        self.sp_found += count
        # SP found is significant - force immediate save
        self._dirty = True
        self._save_to_db(force=True)

    def increment_sp_verified(self, count: int = 1) -> None:
        """Increment SP verified counter and persist."""
        self.sp_verified += count
        self._mark_dirty_and_maybe_save()

    def increment_pov_generated(self, count: int = 1) -> None:
        """Increment POV generated counter and persist."""
        self.pov_generated += count
        # POV generated is significant - force immediate save
        self._dirty = True
        self._save_to_db(force=True)

    def increment_patch_generated(self, count: int = 1) -> None:
        """Increment patch generated counter and persist."""
        self.patch_generated += count
        # Patch generated is significant - force immediate save
        self._dirty = True
        self._save_to_db(force=True)

    def update_status(self, status: str, error: Optional[str] = None) -> None:
        """Update worker status and persist immediately."""
        self.status = status
        if error:
            self.error = error
        self._dirty = True
        self._save_to_db(force=True)

    def set_result_summary(self, summary: Dict[str, Any]) -> None:
        """Set result summary and persist."""
        self.result_summary = summary
        self._mark_dirty_and_maybe_save()

    def set_strategy(self, strategy: str) -> None:
        """Set current strategy and add to history."""
        self.current_strategy = strategy
        if strategy not in self.strategy_history:
            self.strategy_history.append(strategy)
        self._mark_dirty_and_maybe_save()

    def set_phase_timing(
        self,
        build: float = None,
        reachability: float = None,
        find_sp: float = None,
        verify: float = None,
        pov: float = None,
        save: float = None,
    ) -> None:
        """Update phase timing values."""
        if build is not None:
            self.phase_build = build
        if reachability is not None:
            self.phase_reachability = reachability
        if find_sp is not None:
            self.phase_find_sp = find_sp
        if verify is not None:
            self.phase_verify = verify
        if pov is not None:
            self.phase_pov = pov
        if save is not None:
            self.phase_save = save
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

    @property
    def display_name(self) -> str:
        """Get human-readable worker name."""
        return f"{self.fuzzer}_{self.sanitizer}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "worker_id": self.worker_id,
            "task_id": self.task_id,
            "fuzzer": self.fuzzer,
            "sanitizer": self.sanitizer,
            "scan_mode": self.scan_mode,
            "project_name": self.project_name,
            "current_strategy": self.current_strategy,
            "strategy_history": self.strategy_history,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            "agents_spawned": self.agents_spawned,
            "agents_completed": self.agents_completed,
            "agents_failed": self.agents_failed,
            "sp_found": self.sp_found,
            "sp_verified": self.sp_verified,
            "pov_generated": self.pov_generated,
            "patch_generated": self.patch_generated,
            "phase_build": self.phase_build,
            "phase_reachability": self.phase_reachability,
            "phase_find_sp": self.phase_find_sp,
            "phase_verify": self.phase_verify,
            "phase_pov": self.phase_pov,
            "phase_save": self.phase_save,
            "llm_calls": self.llm_calls,
            "llm_cost": self.llm_cost,
            "llm_input_tokens": self.llm_input_tokens,
            "llm_output_tokens": self.llm_output_tokens,
            "result_summary": self.result_summary,
        }

    def __repr__(self) -> str:
        return (
            f"WorkerContext(id={self.worker_id[:8]}..., "
            f"fuzzer={self.fuzzer}, san={self.sanitizer}, status={self.status})"
        )


# =============================================================================
# Monitoring API
# =============================================================================


def get_worker_status(worker_id: str) -> Optional[Dict[str, Any]]:
    """
    Get worker status from memory or database.

    First checks in-memory registry (for running workers),
    then falls back to database (for completed workers).

    Args:
        worker_id: Worker ID (ObjectId string)

    Returns:
        Worker status dict or None if not found
    """
    # Check in-memory first (running workers)
    ctx = get_worker_context(worker_id)
    if ctx:
        return ctx.to_dict()

    # Fall back to database (completed workers)
    try:
        from ..db import get_database

        db = get_database()
        if db is None:
            return None

        doc = db.workers.find_one({"_id": ObjectId(worker_id)})
        if doc:
            # Convert ObjectId to string
            doc["worker_id"] = str(doc.pop("_id"))
            doc["task_id"] = str(doc["task_id"]) if doc.get("task_id") else None
            return doc

    except Exception:
        pass

    return None


def get_workers_by_task(task_id: str) -> list:
    """
    Get all workers for a task.

    Args:
        task_id: Task ID (ObjectId string)

    Returns:
        List of worker status dicts
    """
    workers = []

    try:
        from ..db import get_database

        db = get_database()
        if db is None:
            return workers

        cursor = db.workers.find({"task_id": ObjectId(task_id)})
        for doc in cursor:
            doc["worker_id"] = str(doc.pop("_id"))
            doc["task_id"] = str(doc["task_id"]) if doc.get("task_id") else None
            workers.append(doc)

    except Exception:
        pass

    # Merge with in-memory data (for running workers with fresher stats)
    in_memory = get_all_worker_contexts()
    for ctx in in_memory.values():
        if ctx.task_id == task_id:
            # Replace or add in-memory version
            found = False
            for i, w in enumerate(workers):
                if w["worker_id"] == ctx.worker_id:
                    workers[i] = ctx.to_dict()
                    found = True
                    break
            if not found:
                workers.append(ctx.to_dict())

    return workers


def get_active_workers() -> list:
    """
    Get all currently running workers.

    Returns:
        List of active worker status dicts
    """
    return [ctx.to_dict() for ctx in get_all_worker_contexts().values()]
