"""
Redis Store for Evaluation Server.

Handles real-time counters and pub/sub for live updates.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from loguru import logger

try:
    import redis.asyncio as redis
except ImportError:
    redis = None

from ..config import get_config


class RedisStore:
    """Redis store for real-time data and pub/sub."""

    def __init__(self, url: Optional[str] = None):
        """
        Initialize Redis store.

        Args:
            url: Redis URL (uses config if not provided)
        """
        if redis is None:
            raise ImportError("redis package not installed. Install with: pip install redis")

        config = get_config()
        self.url = url or config.redis_url
        self._client: Optional[redis.Redis] = None
        self._pubsub: Optional[redis.client.PubSub] = None

    async def connect(self) -> None:
        """Connect to Redis."""
        if self._client is not None:
            return

        self._client = redis.from_url(self.url, decode_responses=True)
        await self._client.ping()
        logger.info(f"Connected to Redis: {self.url}")

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._pubsub:
            await self._pubsub.close()
            self._pubsub = None
        if self._client:
            await self._client.close()
            self._client = None
            logger.info("Disconnected from Redis")

    # ========== Real-time Counters ==========

    async def incr_counter(self, key: str, amount: float = 1) -> float:
        """Increment a counter."""
        return await self._client.incrbyfloat(key, amount)

    async def get_counter(self, key: str) -> float:
        """Get counter value."""
        value = await self._client.get(key)
        return float(value) if value else 0.0

    async def set_counter(self, key: str, value: float) -> None:
        """Set counter value."""
        await self._client.set(key, value)

    # ========== Instance Tracking ==========

    async def set_instance_status(
        self,
        instance_id: str,
        status: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Set instance status."""
        key = f"instance:{instance_id}:status"
        await self._client.set(key, status)
        if data:
            data_key = f"instance:{instance_id}:data"
            await self._client.set(data_key, json.dumps(data))

    async def get_instance_status(self, instance_id: str) -> Optional[str]:
        """Get instance status."""
        key = f"instance:{instance_id}:status"
        return await self._client.get(key)

    async def set_instance_heartbeat(self, instance_id: str) -> None:
        """Update instance heartbeat timestamp."""
        key = f"instance:{instance_id}:heartbeat"
        await self._client.set(key, datetime.utcnow().isoformat())

    async def get_active_instances(self) -> List[str]:
        """Get list of active instance IDs."""
        pattern = "instance:*:status"
        keys = await self._client.keys(pattern)
        instances = []
        for key in keys:
            instance_id = key.split(":")[1]
            status = await self._client.get(key)
            if status == "running":
                instances.append(instance_id)
        return instances

    # ========== Task Counters ==========

    async def incr_task_cost(self, task_id: str, cost: float) -> float:
        """Increment task total cost."""
        key = f"task:{task_id}:cost"
        return await self._client.incrbyfloat(key, cost)

    async def get_task_cost(self, task_id: str) -> float:
        """Get task total cost."""
        key = f"task:{task_id}:cost"
        value = await self._client.get(key)
        return float(value) if value else 0.0

    async def incr_task_llm_calls(self, task_id: str) -> int:
        """Increment task LLM call count."""
        key = f"task:{task_id}:llm_calls"
        return await self._client.incr(key)

    async def incr_task_tool_calls(self, task_id: str) -> int:
        """Increment task tool call count."""
        key = f"task:{task_id}:tool_calls"
        return await self._client.incr(key)

    async def get_task_stats(self, task_id: str) -> Dict[str, Any]:
        """Get all task stats."""
        keys = [
            f"task:{task_id}:cost",
            f"task:{task_id}:llm_calls",
            f"task:{task_id}:tool_calls",
        ]
        values = await self._client.mget(keys)
        return {
            "cost": float(values[0]) if values[0] else 0.0,
            "llm_calls": int(values[1]) if values[1] else 0,
            "tool_calls": int(values[2]) if values[2] else 0,
        }

    # ========== Cluster Counters ==========

    async def incr_cluster_cost(self, cost: float) -> float:
        """Increment cluster total cost."""
        return await self._client.incrbyfloat("cluster:total_cost", cost)

    async def get_cluster_cost(self) -> float:
        """Get cluster total cost."""
        value = await self._client.get("cluster:total_cost")
        return float(value) if value else 0.0

    async def incr_cluster_counter(self, counter: str, amount: int = 1) -> int:
        """Increment a cluster-wide counter."""
        key = f"cluster:{counter}"
        return await self._client.incrby(key, amount)

    async def get_cluster_stats(self) -> Dict[str, Any]:
        """Get cluster-wide stats."""
        keys = [
            "cluster:total_cost",
            "cluster:total_llm_calls",
            "cluster:total_tool_calls",
            "cluster:total_tasks",
            "cluster:active_agents",
        ]
        values = await self._client.mget(keys)
        return {
            "total_cost": float(values[0]) if values[0] else 0.0,
            "total_llm_calls": int(values[1]) if values[1] else 0,
            "total_tool_calls": int(values[2]) if values[2] else 0,
            "total_tasks": int(values[3]) if values[3] else 0,
            "active_agents": int(values[4]) if values[4] else 0,
        }

    # ========== Pub/Sub ==========

    async def publish_event(self, channel: str, data: Dict[str, Any]) -> None:
        """Publish an event to a channel."""
        await self._client.publish(channel, json.dumps(data))

    async def publish_log(self, agent_id: str, log_data: Dict[str, Any]) -> None:
        """Publish a log entry for an agent."""
        # Publish to agent-specific channel
        await self._client.publish(f"logs:agent:{agent_id}", json.dumps(log_data))

        # Also publish to task channel if task_id is present
        if log_data.get("task_id"):
            await self._client.publish(
                f"logs:task:{log_data['task_id']}",
                json.dumps(log_data),
            )

    async def subscribe(self, *channels: str):
        """Subscribe to channels."""
        if self._pubsub is None:
            self._pubsub = self._client.pubsub()
        await self._pubsub.subscribe(*channels)
        return self._pubsub

    async def psubscribe(self, *patterns: str):
        """Subscribe to channel patterns."""
        if self._pubsub is None:
            self._pubsub = self._client.pubsub()
        await self._pubsub.psubscribe(*patterns)
        return self._pubsub

    # ========== Rate Limiting ==========

    async def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> bool:
        """
        Check if rate limit is exceeded.

        Returns True if within limit, False if exceeded.
        """
        current = await self._client.incr(key)
        if current == 1:
            await self._client.expire(key, window_seconds)
        return current <= max_requests

    # ========== Caching ==========

    async def cache_set(
        self,
        key: str,
        value: Any,
        ttl_seconds: int = 300,
    ) -> None:
        """Set a cached value."""
        cache_key = f"cache:{key}"
        await self._client.setex(cache_key, ttl_seconds, json.dumps(value))

    async def cache_get(self, key: str) -> Optional[Any]:
        """Get a cached value."""
        cache_key = f"cache:{key}"
        value = await self._client.get(cache_key)
        if value:
            return json.loads(value)
        return None

    async def cache_delete(self, key: str) -> None:
        """Delete a cached value."""
        cache_key = f"cache:{key}"
        await self._client.delete(cache_key)
