"""
LLM Call Buffer

Redis-based buffer for LLM call records with periodic batch writes to MongoDB.

Architecture:
    LLM Call -> Redis (fast, in-memory) -> MongoDB (batch, persistent)

This provides:
    - Low-latency recording (microseconds via Redis)
    - Durable storage (MongoDB)
    - Real-time counters (Redis)
    - Historical queries (MongoDB)
"""

import asyncio
import json
import threading
import time
from datetime import datetime
from typing import Optional, List, Dict, Any

from loguru import logger

from ..core.models.llm_call import LLMCall


class LLMCallBuffer:
    """
    Redis buffer for LLM call records with MongoDB batch persistence.

    Usage:
        buffer = LLMCallBuffer(redis_url, mongo_db)
        await buffer.start()

        # Record calls (fast)
        await buffer.record(call)

        # Stop and flush remaining
        await buffer.stop()

    The buffer automatically flushes to MongoDB every FLUSH_INTERVAL seconds
    or when FLUSH_BATCH_SIZE records accumulate.
    """

    # Buffer key in Redis
    BUFFER_KEY = "fuzzingbrain:llm_calls_buffer"

    # Flush settings
    FLUSH_INTERVAL = 5.0  # Seconds between flushes
    FLUSH_BATCH_SIZE = 100  # Max records per flush

    # Counter key prefixes
    COUNTER_PREFIX = "fuzzingbrain:counters"

    def __init__(
        self,
        redis_url: str = None,
        mongo_db=None,
        flush_interval: float = None,
        flush_batch_size: int = None,
    ):
        """
        Initialize the LLM call buffer.

        Args:
            redis_url: Redis connection URL
            mongo_db: MongoDB database instance
            flush_interval: Override default flush interval
            flush_batch_size: Override default batch size
        """
        self.redis_url = redis_url or "redis://localhost:6379/0"
        self.mongo_db = mongo_db
        self.flush_interval = flush_interval or self.FLUSH_INTERVAL
        self.flush_batch_size = flush_batch_size or self.FLUSH_BATCH_SIZE

        self._redis = None
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False
        self._lock = asyncio.Lock()

        # Fallback: in-memory buffer when Redis unavailable
        self._memory_buffer: List[dict] = []
        self._memory_lock = threading.Lock()

    async def connect(self) -> bool:
        """
        Connect to Redis.

        Returns:
            True if connected, False if Redis unavailable
        """
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(
                self.redis_url,
                decode_responses=True,
            )
            await self._redis.ping()
            logger.info(f"LLMCallBuffer connected to Redis: {self.redis_url}")
            return True

        except ImportError:
            logger.warning("redis package not installed, using memory buffer")
            return False
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}, using memory buffer")
            return False

    async def start(self):
        """
        Start the background flush loop (idempotent).

        Safe to call multiple times - only starts once.
        """
        if self._running:
            return  # Already running, do nothing

        # Try to connect to Redis
        await self.connect()

        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info("LLMCallBuffer started (shared across all tasks)")

    async def stop(self):
        """Stop the buffer and flush remaining records."""
        if not self._running:
            return

        self._running = False

        # Cancel flush task
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        # Final flush
        await self._flush_all()

        # Close Redis connection
        if self._redis:
            await self._redis.close()
            self._redis = None

        logger.info("LLMCallBuffer stopped")

    async def record(self, call: LLMCall) -> bool:
        """
        Record an LLM call (fast path).

        This writes to Redis (or memory buffer) and returns immediately.
        The record will be persisted to MongoDB in the next flush cycle.

        Args:
            call: LLMCall instance

        Returns:
            True if recorded successfully
        """
        try:
            call_json = json.dumps(call.to_json_dict())

            if self._redis:
                # Write to Redis list
                await self._redis.lpush(self.BUFFER_KEY, call_json)

                # Update counters atomically
                pipe = self._redis.pipeline()

                # Agent-level counter
                if call.agent_id:
                    pipe.incr(f"{self.COUNTER_PREFIX}:agent:{call.agent_id}:calls")
                    pipe.incrbyfloat(
                        f"{self.COUNTER_PREFIX}:agent:{call.agent_id}:cost",
                        call.cost,
                    )

                # Task-level counter
                if call.task_id:
                    pipe.incr(f"{self.COUNTER_PREFIX}:task:{call.task_id}:calls")
                    pipe.incrbyfloat(
                        f"{self.COUNTER_PREFIX}:task:{call.task_id}:cost",
                        call.cost,
                    )

                # Global counter
                pipe.incr(f"{self.COUNTER_PREFIX}:global:calls")
                pipe.incrbyfloat(f"{self.COUNTER_PREFIX}:global:cost", call.cost)

                await pipe.execute()

            else:
                # Fallback to memory buffer
                with self._memory_lock:
                    self._memory_buffer.append(call.to_dict())

            return True

        except Exception as e:
            logger.error(f"Failed to record LLM call: {e}")
            return False

    async def _flush_loop(self):
        """Background loop that periodically flushes to MongoDB."""
        while self._running:
            try:
                await asyncio.sleep(self.flush_interval)
                count = await self._flush_batch()
                if count > 0:
                    logger.debug(f"LLMCallBuffer flushed {count} records to MongoDB")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"LLMCallBuffer flush error: {e}")

    async def _flush_batch(self) -> int:
        """
        Flush a batch of records from Redis AND memory buffer to MongoDB.

        Also updates aggregated LLM usage fields in Task, Worker, Agent collections.

        Returns:
            Number of records flushed
        """
        if not self.mongo_db:
            return 0

        async with self._lock:
            try:
                docs = []

                # 1. Flush from Redis (if connected)
                if self._redis:
                    # Get batch from Redis (atomically)
                    pipe = self._redis.pipeline()
                    pipe.lrange(self.BUFFER_KEY, -self.flush_batch_size, -1)
                    pipe.ltrim(self.BUFFER_KEY, 0, -(self.flush_batch_size + 1))
                    results = await pipe.execute()

                    items = results[0]
                    for item in items:
                        try:
                            data = json.loads(item)
                            call = LLMCall.from_dict(data)
                            docs.append(call.to_dict())
                        except Exception as e:
                            logger.warning(f"Failed to parse LLM call record: {e}")

                # 2. Also flush from memory buffer (sync calls go here)
                with self._memory_lock:
                    if self._memory_buffer:
                        remaining_slots = self.flush_batch_size - len(docs)
                        if remaining_slots > 0:
                            memory_docs = self._memory_buffer[:remaining_slots]
                            self._memory_buffer = self._memory_buffer[remaining_slots:]
                            docs.extend(memory_docs)

                if not docs:
                    return 0

                # 3. Bulk insert to MongoDB llm_calls collection
                result = self.mongo_db.llm_calls.insert_many(docs)

                # 4. Update aggregated fields in Task/Worker/Agent
                self._update_aggregates(docs)

                return len(result.inserted_ids)

            except Exception as e:
                logger.error(f"Failed to flush LLM calls to MongoDB: {e}")
                return 0

    def _update_aggregates(self, docs: list) -> None:
        """
        Update aggregated LLM usage fields in Task, Worker, Agent collections.

        Groups docs by ID and uses $inc for atomic updates.
        """
        from collections import defaultdict
        from bson import ObjectId

        # Group by task_id
        task_stats = defaultdict(lambda: {"calls": 0, "cost": 0.0, "input": 0, "output": 0})
        worker_stats = defaultdict(lambda: {"calls": 0, "cost": 0.0, "input": 0, "output": 0})
        agent_stats = defaultdict(lambda: {"calls": 0, "cost": 0.0, "input": 0, "output": 0})

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
                self.mongo_db.tasks.update_one(
                    {"_id": task_id if isinstance(task_id, ObjectId) else ObjectId(task_id)},
                    {"$inc": {
                        "llm_calls": stats["calls"],
                        "llm_cost": stats["cost"],
                        "llm_input_tokens": stats["input"],
                        "llm_output_tokens": stats["output"],
                    }},
                )
            except Exception as e:
                logger.warning(f"Failed to update task aggregates: {e}")

        # Update Worker collection
        for worker_id, stats in worker_stats.items():
            try:
                self.mongo_db.workers.update_one(
                    {"_id": worker_id if isinstance(worker_id, ObjectId) else ObjectId(worker_id)},
                    {"$inc": {
                        "llm_calls": stats["calls"],
                        "llm_cost": stats["cost"],
                        "llm_input_tokens": stats["input"],
                        "llm_output_tokens": stats["output"],
                    }},
                )
            except Exception as e:
                logger.warning(f"Failed to update worker aggregates: {e}")

        # Update Agent collection
        for agent_id, stats in agent_stats.items():
            try:
                self.mongo_db.agents.update_one(
                    {"_id": agent_id if isinstance(agent_id, ObjectId) else ObjectId(agent_id)},
                    {"$inc": {
                        "llm_calls": stats["calls"],
                        "llm_cost": stats["cost"],
                        "llm_input_tokens": stats["input"],
                        "llm_output_tokens": stats["output"],
                    }},
                )
            except Exception as e:
                logger.warning(f"Failed to update agent aggregates: {e}")

    async def _flush_all(self):
        """Flush all remaining records to MongoDB."""
        total = 0
        while True:
            count = await self._flush_batch()
            if count == 0:
                break
            total += count
        if total > 0:
            logger.info(f"LLMCallBuffer final flush: {total} records")

    # =========================================================================
    # Read methods (for real-time stats)
    # =========================================================================

    async def get_agent_stats(self, agent_id: str) -> Dict[str, Any]:
        """Get real-time stats for an agent from Redis."""
        if not self._redis:
            return {"calls": 0, "cost": 0.0, "source": "unavailable"}

        try:
            calls = await self._redis.get(
                f"{self.COUNTER_PREFIX}:agent:{agent_id}:calls"
            )
            cost = await self._redis.get(
                f"{self.COUNTER_PREFIX}:agent:{agent_id}:cost"
            )
            return {
                "calls": int(calls or 0),
                "cost": float(cost or 0.0),
                "source": "redis",
            }
        except Exception as e:
            logger.warning(f"Failed to get agent stats: {e}")
            return {"calls": 0, "cost": 0.0, "source": "error"}

    async def get_task_stats(self, task_id: str) -> Dict[str, Any]:
        """Get real-time stats for a task from Redis."""
        if not self._redis:
            return {"calls": 0, "cost": 0.0, "source": "unavailable"}

        try:
            calls = await self._redis.get(
                f"{self.COUNTER_PREFIX}:task:{task_id}:calls"
            )
            cost = await self._redis.get(
                f"{self.COUNTER_PREFIX}:task:{task_id}:cost"
            )
            return {
                "calls": int(calls or 0),
                "cost": float(cost or 0.0),
                "source": "redis",
            }
        except Exception as e:
            logger.warning(f"Failed to get task stats: {e}")
            return {"calls": 0, "cost": 0.0, "source": "error"}

    async def get_global_stats(self) -> Dict[str, Any]:
        """Get real-time global stats from Redis."""
        if not self._redis:
            return {"calls": 0, "cost": 0.0, "source": "unavailable"}

        try:
            calls = await self._redis.get(f"{self.COUNTER_PREFIX}:global:calls")
            cost = await self._redis.get(f"{self.COUNTER_PREFIX}:global:cost")
            return {
                "calls": int(calls or 0),
                "cost": float(cost or 0.0),
                "source": "redis",
            }
        except Exception as e:
            logger.warning(f"Failed to get global stats: {e}")
            return {"calls": 0, "cost": 0.0, "source": "error"}

    # =========================================================================
    # Cleanup methods (call when Task/Worker/Agent completes)
    # =========================================================================

    async def cleanup_task_counters(self, task_id: str) -> bool:
        """
        Cleanup Redis counters for a completed Task.

        Call this when a Task finishes (success or failure).

        Args:
            task_id: Task ID to cleanup

        Returns:
            True if cleanup succeeded
        """
        if not self._redis:
            return True  # Nothing to clean

        try:
            keys = [
                f"{self.COUNTER_PREFIX}:task:{task_id}:calls",
                f"{self.COUNTER_PREFIX}:task:{task_id}:cost",
            ]
            await self._redis.delete(*keys)
            logger.debug(f"Cleaned up Redis counters for task {task_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to cleanup task counters: {e}")
            return False

    async def cleanup_worker_counters(self, worker_id: str) -> bool:
        """
        Cleanup Redis counters for a completed Worker.

        Call this when a Worker finishes (success or failure).

        Args:
            worker_id: Worker ID to cleanup

        Returns:
            True if cleanup succeeded
        """
        if not self._redis:
            return True

        try:
            keys = [
                f"{self.COUNTER_PREFIX}:worker:{worker_id}:calls",
                f"{self.COUNTER_PREFIX}:worker:{worker_id}:cost",
            ]
            await self._redis.delete(*keys)
            logger.debug(f"Cleaned up Redis counters for worker {worker_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to cleanup worker counters: {e}")
            return False

    async def cleanup_agent_counters(self, agent_id: str) -> bool:
        """
        Cleanup Redis counters for a completed Agent.

        Call this when an Agent finishes (success or failure).

        Args:
            agent_id: Agent ID to cleanup

        Returns:
            True if cleanup succeeded
        """
        if not self._redis:
            return True

        try:
            keys = [
                f"{self.COUNTER_PREFIX}:agent:{agent_id}:calls",
                f"{self.COUNTER_PREFIX}:agent:{agent_id}:cost",
            ]
            await self._redis.delete(*keys)
            logger.debug(f"Cleaned up Redis counters for agent {agent_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to cleanup agent counters: {e}")
            return False

    # =========================================================================
    # Sync cleanup methods (for use from sync context like WorkerContext)
    # =========================================================================

    def cleanup_worker_counters_sync(self, worker_id: str) -> bool:
        """
        Sync version of cleanup_worker_counters.

        Uses a new event loop to run the async cleanup.
        Safe to call from sync context.
        """
        import asyncio

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.cleanup_worker_counters(worker_id))
            finally:
                loop.close()
        except Exception as e:
            logger.warning(f"Failed to cleanup worker counters (sync): {e}")
            return False

    def cleanup_task_counters_sync(self, task_id: str) -> bool:
        """
        Sync version of cleanup_task_counters.

        Uses a new event loop to run the async cleanup.
        Safe to call from sync context.
        """
        import asyncio

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.cleanup_task_counters(task_id))
            finally:
                loop.close()
        except Exception as e:
            logger.warning(f"Failed to cleanup task counters (sync): {e}")
            return False


# =============================================================================
# Global buffer instance
# =============================================================================

_buffer: Optional[LLMCallBuffer] = None


def get_llm_call_buffer() -> Optional[LLMCallBuffer]:
    """Get the global LLM call buffer instance."""
    return _buffer


async def init_llm_call_buffer(
    redis_url: str = None,
    mongo_db=None,
) -> LLMCallBuffer:
    """
    Initialize and start the global LLM call buffer.

    Args:
        redis_url: Redis connection URL
        mongo_db: MongoDB database instance

    Returns:
        LLMCallBuffer instance
    """
    global _buffer

    if _buffer is not None:
        return _buffer

    _buffer = LLMCallBuffer(redis_url=redis_url, mongo_db=mongo_db)
    await _buffer.start()

    return _buffer


async def shutdown_llm_call_buffer():
    """Shutdown the global LLM call buffer."""
    global _buffer

    if _buffer is not None:
        await _buffer.stop()
        _buffer = None


def init_llm_call_buffer_sync(
    redis_url: str = None,
    mongo_db=None,
) -> LLMCallBuffer:
    """
    Initialize the global LLM call buffer (sync version, no flush loop).

    This creates the buffer but doesn't start the async flush loop.
    The buffer will accumulate calls in memory until an async context
    calls await buffer.start() or the async init_llm_call_buffer().

    Args:
        redis_url: Redis connection URL
        mongo_db: MongoDB database instance

    Returns:
        LLMCallBuffer instance
    """
    global _buffer

    if _buffer is not None:
        return _buffer

    _buffer = LLMCallBuffer(redis_url=redis_url, mongo_db=mongo_db)
    logger.info("LLMCallBuffer initialized (sync mode, memory only)")

    return _buffer
