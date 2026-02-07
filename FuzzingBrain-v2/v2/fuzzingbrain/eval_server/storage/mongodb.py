"""
MongoDB Storage for Evaluation Server.

Handles persistent storage of evaluation data.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from bson import ObjectId
from loguru import logger

try:
    from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

    MOTOR_AVAILABLE = True
except ImportError:
    MOTOR_AVAILABLE = False
    AsyncIOMotorClient = None
    AsyncIOMotorDatabase = None

from ..config import get_config


class MongoStorage:
    """MongoDB storage layer for evaluation data."""

    def __init__(self, uri: Optional[str] = None, db_name: Optional[str] = None):
        """
        Initialize MongoDB storage.

        Args:
            uri: MongoDB URI (uses config if not provided)
            db_name: Database name (uses config if not provided)
        """
        config = get_config()
        self.uri = uri or config.mongodb_uri
        self.db_name = db_name or config.mongodb_db
        self._client: Optional[AsyncIOMotorClient] = None
        self._db: Optional[AsyncIOMotorDatabase] = None

    async def connect(self) -> None:
        """Connect to MongoDB."""
        if not MOTOR_AVAILABLE:
            raise ImportError(
                "motor package not installed. Install with: pip install motor"
            )

        if self._client is not None:
            return

        self._client = AsyncIOMotorClient(self.uri)
        self._db = self._client[self.db_name]

        # Create indexes
        await self._create_indexes()

        logger.info(f"Connected to MongoDB: {self.db_name}")

    async def disconnect(self) -> None:
        """Disconnect from MongoDB."""
        if self._client:
            self._client.close()
            self._client = None
            self._db = None
            logger.info("Disconnected from MongoDB")

    async def _create_indexes(self) -> None:
        """Create necessary indexes."""
        if self._db is None:
            return

        # Instances collection
        await self._db.instances.create_index("instance_id", unique=True)
        await self._db.instances.create_index("last_heartbeat")

        # Tasks collection
        await self._db.tasks.create_index("task_id", unique=True)
        await self._db.tasks.create_index("instance_id")
        await self._db.tasks.create_index("status")
        await self._db.tasks.create_index("created_at")

        # Workers collection
        await self._db.workers.create_index(
            [("task_id", 1), ("worker_id", 1)], unique=True
        )
        await self._db.workers.create_index("status")

        # Agents collection
        await self._db.agents.create_index("agent_id", unique=True)
        await self._db.agents.create_index([("task_id", 1), ("worker_id", 1)])
        await self._db.agents.create_index("status")

        # LLM calls collection
        await self._db.llm_calls.create_index("call_id", unique=True)
        await self._db.llm_calls.create_index("timestamp")
        await self._db.llm_calls.create_index([("task_id", 1), ("timestamp", -1)])
        await self._db.llm_calls.create_index([("agent_id", 1), ("timestamp", -1)])
        await self._db.llm_calls.create_index("model")

        # Tool calls collection
        await self._db.tool_calls.create_index("call_id", unique=True)
        await self._db.tool_calls.create_index("timestamp")
        await self._db.tool_calls.create_index([("agent_id", 1), ("timestamp", -1)])
        await self._db.tool_calls.create_index("tool_name")

        # Agent logs collection
        await self._db.agent_logs.create_index("log_id", unique=True)
        await self._db.agent_logs.create_index([("agent_id", 1), ("timestamp", 1)])
        await self._db.agent_logs.create_index([("task_id", 1), ("timestamp", -1)])
        await self._db.agent_logs.create_index(
            [("content", "text")],
            default_language="english",
        )

        # Events collection
        await self._db.events.create_index("event_id", unique=True)
        await self._db.events.create_index("timestamp")
        await self._db.events.create_index([("task_id", 1), ("timestamp", -1)])
        await self._db.events.create_index("event_type")

        # Aggregations collection (for pre-computed summaries)
        await self._db.aggregations.create_index(
            [("type", 1), ("key", 1), ("period", 1)],
            unique=True,
        )

        logger.debug("MongoDB indexes created")

    # ========== Instance Operations ==========

    async def upsert_instance(self, data: Dict[str, Any]) -> None:
        """Insert or update instance."""
        await self._db.instances.update_one(
            {"instance_id": data["instance_id"]},
            {"$set": data},
            upsert=True,
        )

    async def get_instance(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Get instance by ID."""
        return await self._db.instances.find_one({"instance_id": instance_id})

    async def get_all_instances(
        self, include_dead: bool = False
    ) -> List[Dict[str, Any]]:
        """Get all instances."""
        config = get_config()
        query = {}
        if not include_dead:
            cutoff = datetime.utcnow() - timedelta(
                seconds=config.heartbeat_timeout_seconds
            )
            query["last_heartbeat"] = {"$gte": cutoff}
        cursor = self._db.instances.find(query)
        return await cursor.to_list(length=1000)

    async def update_heartbeat(self, instance_id: str, data: Dict[str, Any]) -> None:
        """Update instance heartbeat."""
        await self._db.instances.update_one(
            {"instance_id": instance_id},
            {"$set": {"last_heartbeat": datetime.utcnow(), **data}},
        )

    # ========== Task Operations ==========

    async def upsert_task(self, data: Dict[str, Any]) -> None:
        """Insert or update task."""
        task_id = data.get("task_id") or data.get("_id")
        await self._db.tasks.update_one(
            {"_id": ObjectId(task_id) if task_id else ObjectId()},
            {"$set": data},
            upsert=True,
        )

    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task by ID."""
        return await self._db.tasks.find_one({"_id": ObjectId(task_id)})

    async def get_tasks(
        self,
        instance_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get tasks with filters."""
        query = {}
        if instance_id:
            query["instance_id"] = instance_id
        if status:
            query["status"] = status
        cursor = self._db.tasks.find(query).sort("created_at", -1).limit(limit)
        return await cursor.to_list(length=limit)

    # ========== Worker Operations ==========

    async def upsert_worker(self, data: Dict[str, Any]) -> None:
        """Insert or update worker."""
        worker_id = data.get("worker_id") or data.get("_id")
        await self._db.workers.update_one(
            {"_id": ObjectId(worker_id) if worker_id else ObjectId()},
            {"$set": data},
            upsert=True,
        )

    async def get_worker(self, worker_id: str) -> Optional[Dict[str, Any]]:
        """Get worker by ID."""
        return await self._db.workers.find_one({"_id": ObjectId(worker_id)})

    async def get_workers_by_task(self, task_id: str) -> List[Dict[str, Any]]:
        """Get all workers for a task."""
        cursor = self._db.workers.find({"task_id": ObjectId(task_id)}).sort(
            "started_at", -1
        )
        return await cursor.to_list(length=1000)

    async def update_worker_status(
        self,
        worker_id: str,
        status: str,
        cpu_percent: Optional[float] = None,
        memory_mb: Optional[float] = None,
    ) -> None:
        """Update worker status and resource usage."""
        update_data = {
            "status": status,
            "last_heartbeat": datetime.utcnow(),
        }
        if cpu_percent is not None:
            update_data["cpu_percent"] = cpu_percent
        if memory_mb is not None:
            update_data["memory_mb"] = memory_mb
        await self._db.workers.update_one(
            {"_id": ObjectId(worker_id)},
            {"$set": update_data},
        )

    async def end_worker(self, worker_id: str, status: str = "completed") -> None:
        """Mark worker as ended."""
        await self._db.workers.update_one(
            {"_id": ObjectId(worker_id)},
            {"$set": {"status": status, "ended_at": datetime.utcnow()}},
        )

    # ========== Agent Operations ==========

    async def upsert_agent(self, data: Dict[str, Any]) -> None:
        """Insert or update agent."""
        agent_id = data.get("agent_id") or data.get("_id")
        await self._db.agents.update_one(
            {"_id": ObjectId(agent_id) if agent_id else ObjectId()},
            {"$set": data},
            upsert=True,
        )

    async def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get agent by ID."""
        return await self._db.agents.find_one({"_id": ObjectId(agent_id)})

    async def get_agents_by_task(self, task_id: str) -> List[Dict[str, Any]]:
        """Get all agents for a task."""
        cursor = self._db.agents.find({"task_id": ObjectId(task_id)}).sort(
            "started_at", -1
        )
        return await cursor.to_list(length=1000)

    async def get_agents_by_worker(self, worker_id: str) -> List[Dict[str, Any]]:
        """Get all agents for a worker."""
        cursor = self._db.agents.find({"worker_id": ObjectId(worker_id)}).sort(
            "started_at", -1
        )
        return await cursor.to_list(length=1000)

    async def get_agent_max_iterations(self, task_id: str) -> Dict[str, int]:
        """Get max iteration for each agent from LLM calls."""
        pipeline = [
            {"$match": {"task_id": ObjectId(task_id)}},
            {"$group": {"_id": "$agent_id", "max_iter": {"$max": "$iteration"}}},
        ]
        result = await self._db.llm_calls.aggregate(pipeline).to_list(length=1000)
        return {str(r["_id"]): r["max_iter"] or 0 for r in result if r["_id"]}

    async def update_agent_status(
        self,
        agent_id: str,
        status: str,
        iteration: Optional[int] = None,
    ) -> None:
        """Update agent status."""
        update_data = {
            "status": status,
            "last_heartbeat": datetime.utcnow(),
        }
        if iteration is not None:
            update_data["iteration"] = iteration
        await self._db.agents.update_one(
            {"_id": ObjectId(agent_id)},
            {"$set": update_data},
        )

    async def end_agent(self, agent_id: str, status: str = "completed") -> None:
        """Mark agent as ended."""
        await self._db.agents.update_one(
            {"_id": ObjectId(agent_id)},
            {"$set": {"status": status, "ended_at": datetime.utcnow()}},
        )

    # ========== LLM Call Operations ==========

    async def insert_llm_calls(self, calls: List[Dict[str, Any]]) -> None:
        """Insert multiple LLM calls."""
        if not calls:
            return
        await self._db.llm_calls.insert_many(calls)

    async def get_llm_calls(
        self,
        task_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Get LLM calls with filters."""
        query = {}
        if task_id:
            query["task_id"] = ObjectId(task_id)
        if agent_id:
            query["agent_id"] = ObjectId(agent_id)
        if model:
            query["model"] = model
        if since:
            query["timestamp"] = {"$gte": since}
        cursor = self._db.llm_calls.find(query).sort("timestamp", -1).limit(limit)
        return await cursor.to_list(length=limit)

    # ========== Tool Call Operations ==========

    async def insert_tool_calls(self, calls: List[Dict[str, Any]]) -> None:
        """Insert multiple tool calls."""
        if not calls:
            return
        await self._db.tool_calls.insert_many(calls)

    async def get_tool_calls(
        self,
        agent_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Get tool calls with filters."""
        query = {}
        if agent_id:
            query["agent_id"] = ObjectId(agent_id)
        if tool_name:
            query["tool_name"] = tool_name
        if since:
            query["timestamp"] = {"$gte": since}
        cursor = self._db.tool_calls.find(query).sort("timestamp", -1).limit(limit)
        return await cursor.to_list(length=limit)

    # ========== Agent Log Operations ==========

    async def insert_logs(self, logs: List[Dict[str, Any]]) -> None:
        """Insert multiple agent logs."""
        if not logs:
            return
        await self._db.agent_logs.insert_many(logs)

    async def get_agent_logs(
        self,
        agent_id: str,
        since: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Get logs for an agent."""
        query = {"agent_id": ObjectId(agent_id)}
        if since:
            query["timestamp"] = {"$gte": since}
        cursor = self._db.agent_logs.find(query).sort("timestamp", 1).limit(limit)
        return await cursor.to_list(length=limit)

    async def get_task_logs(
        self,
        task_id: str,
        since: Optional[datetime] = None,
        limit: int = 5000,
    ) -> List[Dict[str, Any]]:
        """Get all logs for a task."""
        query = {"task_id": ObjectId(task_id)}
        if since:
            query["timestamp"] = {"$gte": since}
        cursor = self._db.agent_logs.find(query).sort("timestamp", -1).limit(limit)
        return await cursor.to_list(length=limit)

    async def search_logs(
        self,
        query_text: str,
        task_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Search logs by content."""
        query = {"$text": {"$search": query_text}}
        if task_id:
            query["task_id"] = ObjectId(task_id)
        cursor = self._db.agent_logs.find(query).limit(limit)
        return await cursor.to_list(length=limit)

    # ========== Event Operations ==========

    async def insert_events(self, events: List[Dict[str, Any]]) -> None:
        """Insert multiple events."""
        if not events:
            return
        await self._db.events.insert_many(events)

    async def get_events(
        self,
        task_id: Optional[str] = None,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Get events with filters."""
        query = {}
        if task_id:
            query["task_id"] = ObjectId(task_id)
        if event_type:
            query["event_type"] = event_type
        if since:
            query["timestamp"] = {"$gte": since}
        cursor = self._db.events.find(query).sort("timestamp", -1).limit(limit)
        return await cursor.to_list(length=limit)

    # ========== Aggregation Operations ==========

    async def get_cost_summary(
        self,
        task_id: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Get aggregated cost summary."""
        match_stage = {}
        if task_id:
            match_stage["task_id"] = ObjectId(task_id)
        if since:
            match_stage["timestamp"] = {"$gte": since}

        pipeline = [
            {"$match": match_stage} if match_stage else {"$match": {}},
            {
                "$group": {
                    "_id": None,
                    "total_cost": {"$sum": "$cost_total"},
                    "total_calls": {"$sum": 1},
                    "total_input_tokens": {"$sum": "$input_tokens"},
                    "total_output_tokens": {"$sum": "$output_tokens"},
                }
            },
        ]

        result = await self._db.llm_calls.aggregate(pipeline).to_list(length=1)
        if result:
            return result[0]
        return {
            "total_cost": 0,
            "total_calls": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
        }

    async def get_cost_by_model(
        self,
        task_id: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Get cost breakdown by model."""
        match_stage = {}
        if task_id:
            match_stage["task_id"] = ObjectId(task_id)
        if since:
            match_stage["timestamp"] = {"$gte": since}

        pipeline = [
            {"$match": match_stage} if match_stage else {"$match": {}},
            {
                "$group": {
                    "_id": "$model",
                    "total_cost": {"$sum": "$cost_total"},
                    "total_calls": {"$sum": 1},
                    "total_tokens": {"$sum": "$total_tokens"},
                }
            },
            {"$sort": {"total_cost": -1}},
        ]

        return await self._db.llm_calls.aggregate(pipeline).to_list(length=100)

    async def get_tool_summary(
        self,
        task_id: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Get tool usage summary."""
        match_stage = {}
        if task_id:
            match_stage["task_id"] = ObjectId(task_id)
        if since:
            match_stage["timestamp"] = {"$gte": since}

        pipeline = [
            {"$match": match_stage} if match_stage else {"$match": {}},
            {
                "$group": {
                    "_id": "$tool_name",
                    "total_calls": {"$sum": 1},
                    "success_count": {
                        "$sum": {"$cond": [{"$eq": ["$success", True]}, 1, 0]}
                    },
                    "failure_count": {
                        "$sum": {"$cond": [{"$eq": ["$success", False]}, 1, 0]}
                    },
                    "avg_latency_ms": {"$avg": "$latency_ms"},
                }
            },
            {"$sort": {"total_calls": -1}},
        ]

        return await self._db.tool_calls.aggregate(pipeline).to_list(length=100)

    # ========== SP Workflow Statistics ==========

    async def get_sp_workflow_stats(self, task_id: str) -> Dict[str, Any]:
        """
        Get SP workflow statistics from main fuzzingbrain database.

        Returns counts for each SP status based on actual SP data.
        - is_checked: whether verification was done
        - is_important: whether it's a real bug (determined during verification)
        - is_real: whether POV was generated
        """
        # Connect to main fuzzingbrain database
        main_db = self._client["fuzzingbrain"]
        sp_collection = main_db.suspicious_points

        query = {"task_id": ObjectId(task_id)}

        # Count various states
        created = await sp_collection.count_documents(query)
        verified = await sp_collection.count_documents({**query, "is_checked": True})
        # is_important=True means it's a real bug (verified as important)
        marked_real = await sp_collection.count_documents(
            {**query, "is_important": True}
        )
        # verified but not important = false positive
        marked_fp = await sp_collection.count_documents(
            {**query, "is_checked": True, "is_important": False}
        )

        return {
            "created": created,
            "verified": verified,
            "marked_real": marked_real,
            "marked_fp": marked_fp,
        }

    async def get_direction_workflow_stats(self, task_id: str) -> Dict[str, Any]:
        """
        Get Direction workflow statistics from main fuzzingbrain database.
        """
        # Connect to main fuzzingbrain database
        main_db = self._client["fuzzingbrain"]
        directions_collection = main_db.directions

        query = {"task_id": ObjectId(task_id)}

        # Count various states
        created = await directions_collection.count_documents(query)
        completed = await directions_collection.count_documents(
            {**query, "status": "completed"}
        )

        return {
            "created": created,
            "completed": completed,
        }

    async def get_pov_workflow_stats(self, task_id: str) -> Dict[str, Any]:
        """
        Get POV workflow statistics from main fuzzingbrain database.
        """
        # Connect to main fuzzingbrain database
        main_db = self._client["fuzzingbrain"]
        pov_collection = main_db.povs

        query = {"task_id": ObjectId(task_id)}

        # Count various states (is_successful is the actual field name)
        total = await pov_collection.count_documents(query)
        crashed = await pov_collection.count_documents({**query, "is_successful": True})
        not_crashed = await pov_collection.count_documents(
            {**query, "is_successful": False}
        )

        return {
            "attempts": total,
            "created": total,
            "crashed": crashed,
        }

    # ========== Cleanup Operations ==========

    async def cleanup_old_data(self, days: int = 7) -> Dict[str, int]:
        """Clean up data older than specified days."""
        cutoff = datetime.utcnow() - timedelta(days=days)

        results = {}

        # Clean up old logs
        result = await self._db.agent_logs.delete_many({"timestamp": {"$lt": cutoff}})
        results["agent_logs"] = result.deleted_count

        # Clean up old LLM calls
        result = await self._db.llm_calls.delete_many({"timestamp": {"$lt": cutoff}})
        results["llm_calls"] = result.deleted_count

        # Clean up old tool calls
        result = await self._db.tool_calls.delete_many({"timestamp": {"$lt": cutoff}})
        results["tool_calls"] = result.deleted_count

        # Clean up old events
        result = await self._db.events.delete_many({"timestamp": {"$lt": cutoff}})
        results["events"] = result.deleted_count

        logger.info(f"Cleaned up old data: {results}")
        return results
