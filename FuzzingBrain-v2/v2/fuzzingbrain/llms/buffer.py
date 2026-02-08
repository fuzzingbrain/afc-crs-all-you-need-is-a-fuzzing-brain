"""
LLM Call Buffer

Per-worker buffer for LLM call records with real-time Redis cost tracking
and periodic MongoDB persistence.

Architecture:
    LLM Call -> Redis INCRBYFLOAT (real-time cost, per-call)
             -> Worker memory list (batch accumulation)
             -> MongoDB (2-second periodic flush via daemon thread)

Lifecycle:
    WorkerContext.__enter__  -> WorkerLLMBuffer.start()
    Agent LLM calls          -> buffer.record(call)
    Every 2 seconds (thread) -> flush to MongoDB
    WorkerContext.__exit__   -> buffer.stop() (final flush)
"""

import threading
from collections import defaultdict
from typing import Optional, List

from bson import ObjectId
from loguru import logger

from ..core.models.llm_call import LLMCall


class WorkerLLMBuffer:
    """
    Per-worker buffer for LLM call tracking.

    Uses a daemon thread for periodic MongoDB persistence (no asyncio dependency).
    Uses sync Redis client for real-time cost counters (INCRBYFLOAT per call).

    Thread-safe: record() can be called from any thread (async worker threads,
    main thread, etc.) - all protected by _lock.
    """

    FLUSH_INTERVAL = 2.0  # Seconds between flushes
    COUNTER_PREFIX = "fuzzingbrain:counters"

    def __init__(self, redis_url: str, mongo_db):
        """
        Initialize the worker LLM buffer.

        Args:
            redis_url: Redis connection URL
            mongo_db: MongoDB database instance
        """
        self.redis_url = redis_url
        self.mongo_db = mongo_db

        # Sync Redis client for INCRBYFLOAT (microsecond per-call updates)
        self._redis = None

        # In-memory record accumulation
        self._records: List[dict] = []
        self._lock = threading.Lock()

        # Flush thread
        self._flush_thread: Optional[threading.Thread] = None
        self._running = False
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the buffer and flush daemon thread."""
        if self._running:
            return

        # Connect to Redis (sync client)
        self._connect_redis()

        self._running = True
        self._stop_event.clear()
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name="llm-buffer-flush",
            daemon=True,
        )
        self._flush_thread.start()
        logger.info("WorkerLLMBuffer started (2s flush interval)")

    def stop(self) -> None:
        """Stop the flush thread and do a final flush with retry."""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()

        # Wait for flush thread to finish
        if self._flush_thread:
            self._flush_thread.join(timeout=10)

        # Final flush with retry — if _flush() fails, records are put back
        # into _records but this buffer is about to be discarded. Retry to
        # avoid silent data loss.
        for attempt in range(3):
            self._flush()
            with self._lock:
                remaining = len(self._records)
            if remaining == 0:
                break
            if attempt < 2:
                import time

                time.sleep(0.5 * (attempt + 1))

        with self._lock:
            if self._records:
                logger.error(
                    f"WorkerLLMBuffer: {len(self._records)} LLM call records "
                    f"lost after 3 flush attempts"
                )

        # Close Redis
        if self._redis:
            try:
                self._redis.close()
            except Exception:
                pass
            self._redis = None

        logger.info("WorkerLLMBuffer stopped")

    def record(self, call: LLMCall) -> None:
        """
        Record an LLM call.

        - Updates Redis cost counters in real-time (INCRBYFLOAT)
        - Appends full record to memory list for periodic MongoDB flush

        Thread-safe: can be called from any thread.

        Args:
            call: LLMCall instance with all fields populated
        """
        # 1. Real-time Redis cost update (per-call, microseconds)
        if self._redis and call.cost > 0:
            try:
                pipe = self._redis.pipeline(transaction=False)
                if call.task_id:
                    pipe.incrbyfloat(
                        f"{self.COUNTER_PREFIX}:task:{call.task_id}:cost",
                        call.cost,
                    )
                    pipe.incr(f"{self.COUNTER_PREFIX}:task:{call.task_id}:calls")
                if call.worker_id:
                    pipe.incrbyfloat(
                        f"{self.COUNTER_PREFIX}:worker:{call.worker_id}:cost",
                        call.cost,
                    )
                if call.agent_id:
                    pipe.incrbyfloat(
                        f"{self.COUNTER_PREFIX}:agent:{call.agent_id}:cost",
                        call.cost,
                    )
                pipe.execute()
            except Exception as e:
                logger.warning(f"Redis INCRBYFLOAT failed: {e}")

        # 2. Append to memory list for batch MongoDB flush
        with self._lock:
            self._records.append(call.to_dict())

    def _connect_redis(self) -> None:
        """Connect sync Redis client."""
        try:
            import redis as sync_redis

            self._redis = sync_redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            self._redis.ping()
            logger.info(f"WorkerLLMBuffer Redis connected: {self.redis_url}")
        except ImportError:
            logger.warning("redis package not installed, skipping real-time counters")
            self._redis = None
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}, skipping real-time counters")
            self._redis = None

    def _flush_loop(self) -> None:
        """Daemon thread: flush records to MongoDB every FLUSH_INTERVAL seconds."""
        while not self._stop_event.wait(timeout=self.FLUSH_INTERVAL):
            try:
                count = self._flush()
                if count > 0:
                    logger.debug(f"WorkerLLMBuffer flushed {count} records to MongoDB")
            except Exception as e:
                logger.error(f"WorkerLLMBuffer flush error: {e}")

    def _flush(self) -> int:
        """
        Flush accumulated records to MongoDB.

        1. insert_many into llm_calls collection
        2. $inc aggregates on tasks/workers/agents collections

        Returns:
            Number of records flushed
        """
        # Grab current batch under lock
        with self._lock:
            if not self._records:
                return 0
            batch = self._records[:]
            self._records.clear()

        if self.mongo_db is None:
            return 0

        try:
            # Bulk insert to llm_calls collection
            self.mongo_db.llm_calls.insert_many(batch)

            # Update aggregated fields
            _update_aggregates(self.mongo_db, batch)

            return len(batch)
        except Exception as e:
            logger.error(f"Failed to flush LLM calls to MongoDB: {e}")
            # Put records back so they're not lost
            with self._lock:
                self._records = batch + self._records
            return 0

    def cleanup_redis_keys(self, task_id: str = "", worker_id: str = "") -> None:
        """Clean up Redis counter keys for completed task/worker."""
        if not self._redis:
            return

        keys_to_delete = []
        if task_id:
            keys_to_delete.extend(
                [
                    f"{self.COUNTER_PREFIX}:task:{task_id}:cost",
                    f"{self.COUNTER_PREFIX}:task:{task_id}:calls",
                ]
            )
        if worker_id:
            keys_to_delete.extend(
                [
                    f"{self.COUNTER_PREFIX}:worker:{worker_id}:cost",
                ]
            )

        if keys_to_delete:
            try:
                self._redis.delete(*keys_to_delete)
            except Exception as e:
                logger.warning(f"Failed to cleanup Redis keys: {e}")


def _update_aggregates(mongo_db, docs: list) -> None:
    """
    Update aggregated LLM usage fields in Task, Worker, Agent collections.

    Groups docs by ID and uses $inc for atomic updates.

    Args:
        mongo_db: MongoDB database instance
        docs: List of LLMCall dicts (from to_dict())
    """
    task_stats = defaultdict(lambda: {"calls": 0, "cost": 0.0, "input": 0, "output": 0})
    worker_stats = defaultdict(
        lambda: {"calls": 0, "cost": 0.0, "input": 0, "output": 0}
    )
    agent_stats = defaultdict(
        lambda: {"calls": 0, "cost": 0.0, "input": 0, "output": 0}
    )

    for doc in docs:
        task_id = doc.get("task_id")
        worker_id = doc.get("worker_id")
        agent_id = doc.get("agent_id")
        cost = doc.get("cost", 0.0)
        input_tokens = doc.get("input_tokens", 0)
        output_tokens = doc.get("output_tokens", 0)

        if task_id:
            task_stats[task_id]["calls"] += 1
            task_stats[task_id]["cost"] += cost
            task_stats[task_id]["input"] += input_tokens
            task_stats[task_id]["output"] += output_tokens

        if worker_id:
            worker_stats[worker_id]["calls"] += 1
            worker_stats[worker_id]["cost"] += cost
            worker_stats[worker_id]["input"] += input_tokens
            worker_stats[worker_id]["output"] += output_tokens

        if agent_id:
            agent_stats[agent_id]["calls"] += 1
            agent_stats[agent_id]["cost"] += cost
            agent_stats[agent_id]["input"] += input_tokens
            agent_stats[agent_id]["output"] += output_tokens

    # Update Task collection
    for task_id, stats in task_stats.items():
        try:
            mongo_db.tasks.update_one(
                {
                    "_id": task_id
                    if isinstance(task_id, ObjectId)
                    else ObjectId(task_id)
                },
                {
                    "$inc": {
                        "llm_calls": stats["calls"],
                        "llm_cost": stats["cost"],
                        "llm_input_tokens": stats["input"],
                        "llm_output_tokens": stats["output"],
                    }
                },
            )
        except Exception as e:
            logger.warning(f"Failed to update task aggregates: {e}")

    # Update Worker collection
    for worker_id, stats in worker_stats.items():
        try:
            mongo_db.workers.update_one(
                {
                    "_id": worker_id
                    if isinstance(worker_id, ObjectId)
                    else ObjectId(worker_id)
                },
                {
                    "$inc": {
                        "llm_calls": stats["calls"],
                        "llm_cost": stats["cost"],
                        "llm_input_tokens": stats["input"],
                        "llm_output_tokens": stats["output"],
                    }
                },
            )
        except Exception as e:
            logger.warning(f"Failed to update worker aggregates: {e}")

    # Update Agent collection
    for agent_id, stats in agent_stats.items():
        try:
            mongo_db.agents.update_one(
                {
                    "_id": agent_id
                    if isinstance(agent_id, ObjectId)
                    else ObjectId(agent_id)
                },
                {
                    "$inc": {
                        "llm_calls": stats["calls"],
                        "llm_cost": stats["cost"],
                        "llm_input_tokens": stats["input"],
                        "llm_output_tokens": stats["output"],
                    }
                },
            )
        except Exception as e:
            logger.warning(f"Failed to update agent aggregates: {e}")


# =============================================================================
# Module-level current buffer (one per Celery worker process)
# =============================================================================

_current_buffer: Optional[WorkerLLMBuffer] = None


def get_worker_buffer() -> Optional[WorkerLLMBuffer]:
    """Get the current worker's LLM buffer."""
    return _current_buffer


def set_worker_buffer(buffer: Optional[WorkerLLMBuffer]) -> None:
    """Set the current worker's LLM buffer."""
    global _current_buffer
    _current_buffer = buffer


# =============================================================================
# Backward compatibility aliases
# =============================================================================


def get_llm_call_buffer() -> Optional[WorkerLLMBuffer]:
    """Backward compatibility: returns the current worker buffer."""
    return _current_buffer
