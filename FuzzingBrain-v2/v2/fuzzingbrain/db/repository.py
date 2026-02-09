"""
Database Repository

CRUD operations for all FuzzingBrain models.
"""

from datetime import datetime
from typing import Optional, List, TypeVar, Generic, Type
from pymongo.database import Database
from pymongo.collection import Collection
from bson import ObjectId
from loguru import logger

from ..core.models import (
    Task,
    POV,
    Patch,
    Worker,
    Fuzzer,
    Function,
    CallGraphNode,
    SuspiciousPoint,
    Direction,
    DirectionStatus,
)


T = TypeVar("T")


class BaseRepository(Generic[T]):
    """Base repository with common CRUD operations"""

    def __init__(self, db: Database, collection_name: str, model_class: Type[T]):
        self.db = db
        self.collection: Collection = db[collection_name]
        self.model_class = model_class

    def save(self, entity: T) -> bool:
        """
        Save entity to database (upsert).

        Returns:
            True if saved successfully
        """
        try:
            data = entity.to_dict()
            self.collection.replace_one({"_id": data["_id"]}, data, upsert=True)
            return True
        except Exception as e:
            logger.error(f"Failed to save {self.model_class.__name__}: {e}")
            return False

    def _convert_id(self, entity_id: str):
        """Convert entity_id to ObjectId if it's a valid ObjectId string."""
        try:
            # Check if it's a valid ObjectId string (24 hex characters)
            if len(entity_id) == 24:
                return ObjectId(entity_id)
        except Exception:
            pass
        return entity_id

    def find_by_id(self, entity_id: str) -> Optional[T]:
        """Find entity by ID"""
        try:
            # Try with ObjectId first, then fallback to string
            _id = self._convert_id(entity_id)
            data = self.collection.find_one({"_id": _id})
            if data:
                return self.model_class.from_dict(data)
            return None
        except Exception as e:
            logger.error(f"Failed to find {self.model_class.__name__} by id: {e}")
            return None

    def find_all(self, query: dict = None, limit: int = 0, skip: int = 0) -> List[T]:
        """Find all entities matching query"""
        try:
            query = query or {}
            cursor = self.collection.find(query).skip(skip)
            if limit > 0:
                cursor = cursor.limit(limit)
            return [self.model_class.from_dict(doc) for doc in cursor]
        except Exception as e:
            logger.error(f"Failed to find {self.model_class.__name__}s: {e}")
            return []

    def find_one(self, query: dict) -> Optional[T]:
        """Find single entity matching query"""
        try:
            data = self.collection.find_one(query)
            if data:
                return self.model_class.from_dict(data)
            return None
        except Exception as e:
            logger.error(f"Failed to find {self.model_class.__name__}: {e}")
            return None

    def update(self, entity_id: str, updates: dict) -> bool:
        """Update entity fields"""
        try:
            updates["updated_at"] = datetime.now()
            _id = self._convert_id(entity_id)
            result = self.collection.update_one({"_id": _id}, {"$set": updates})
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to update {self.model_class.__name__}: {e}")
            return False

    def delete(self, entity_id: str) -> bool:
        """Delete entity by ID"""
        try:
            _id = self._convert_id(entity_id)
            result = self.collection.delete_one({"_id": _id})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Failed to delete {self.model_class.__name__}: {e}")
            return False

    def count(self, query: dict = None) -> int:
        """Count entities matching query"""
        try:
            query = query or {}
            return self.collection.count_documents(query)
        except Exception as e:
            logger.error(f"Failed to count {self.model_class.__name__}s: {e}")
            return 0

    def exists(self, entity_id: str) -> bool:
        """Check if entity exists"""
        _id = self._convert_id(entity_id)
        return self.collection.count_documents({"_id": _id}, limit=1) > 0


class TaskRepository(BaseRepository[Task]):
    """Repository for Task model"""

    # Fields managed exclusively by WorkerLLMBuffer via $inc.
    # Must NOT be included in save() to avoid overwriting buffer increments.
    _LLM_FIELDS = ("llm_calls", "llm_cost", "llm_input_tokens", "llm_output_tokens")

    def __init__(self, db: Database):
        super().__init__(db, "tasks", Task)

    def save(self, task: Task) -> bool:
        """Save task to database (upsert).

        Uses $set instead of replace_one to avoid overwriting llm_* fields
        that are managed by WorkerLLMBuffer via atomic $inc.
        """
        try:
            data = task.to_dict()
            doc_id = data.pop("_id")
            for key in self._LLM_FIELDS:
                data.pop(key, None)
            self.collection.update_one({"_id": doc_id}, {"$set": data}, upsert=True)
            return True
        except Exception as e:
            logger.error(f"Failed to save Task: {e}")
            return False

    def find_by_status(self, status: str) -> List[Task]:
        """Find tasks by status"""
        return self.find_all({"status": status})

    def find_pending(self) -> List[Task]:
        """Find all pending tasks"""
        return self.find_by_status("pending")

    def find_running(self) -> List[Task]:
        """Find all running tasks"""
        return self.find_by_status("running")

    def find_by_project(self, project_name: str) -> List[Task]:
        """Find tasks by project name"""
        return self.find_all({"project_name": project_name})

    def update_status(self, task_id: str, status: str, error_msg: str = None) -> bool:
        """Update task status"""
        updates = {"status": status}
        if error_msg:
            updates["error_msg"] = error_msg
        return self.update(task_id, updates)

    def add_pov(self, task_id: str, pov_id: str) -> bool:
        """Add POV ID to task"""
        try:
            result = self.collection.update_one(
                {"_id": ObjectId(task_id)},
                {"$push": {"pov_ids": pov_id}, "$set": {"updated_at": datetime.now()}},
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to add POV to task: {e}")
            return False

    def add_patch(self, task_id: str, patch_id: str) -> bool:
        """Add Patch ID to task"""
        try:
            result = self.collection.update_one(
                {"_id": ObjectId(task_id)},
                {
                    "$push": {"patch_ids": patch_id},
                    "$set": {"updated_at": datetime.now()},
                },
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to add patch to task: {e}")
            return False


class POVRepository(BaseRepository[POV]):
    """Repository for POV model"""

    def __init__(self, db: Database):
        super().__init__(db, "povs", POV)

    def find_by_task(self, task_id: str) -> List[POV]:
        """Find all POVs for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_active_by_task(self, task_id: str) -> List[POV]:
        """Find active POVs for a task"""
        return self.find_all({"task_id": ObjectId(task_id), "is_active": True})

    def find_successful_by_task(self, task_id: str) -> List[POV]:
        """Find successful POVs for a task"""
        return self.find_all(
            {"task_id": ObjectId(task_id), "is_active": True, "is_successful": True}
        )

    def find_by_harness(self, task_id: str, harness_name: str) -> List[POV]:
        """Find POVs for a specific harness"""
        return self.find_all(
            {"task_id": ObjectId(task_id), "harness_name": harness_name}
        )

    def deactivate(self, pov_id: str) -> bool:
        """Mark POV as inactive"""
        return self.update(pov_id, {"is_active": False})

    def mark_successful(self, pov_id: str) -> bool:
        """Mark POV as successful"""
        return self.update(pov_id, {"is_successful": True})


class PatchRepository(BaseRepository[Patch]):
    """Repository for Patch model"""

    def __init__(self, db: Database):
        super().__init__(db, "patches", Patch)

    def find_by_task(self, task_id: str) -> List[Patch]:
        """Find all patches for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_active_by_task(self, task_id: str) -> List[Patch]:
        """Find active patches for a task"""
        return self.find_all({"task_id": ObjectId(task_id), "is_active": True})

    def find_by_pov(self, pov_id: str) -> List[Patch]:
        """Find patches for a specific POV"""
        return self.find_all({"pov_id": pov_id})

    def find_valid_by_task(self, task_id: str) -> List[Patch]:
        """Find valid patches (passes all checks)"""
        return self.find_all(
            {
                "task_id": ObjectId(task_id),
                "is_active": True,
                "apply_check": True,
                "compilation_check": True,
                "pov_check": True,
                "test_check": True,
            }
        )

    def update_checks(
        self,
        patch_id: str,
        apply: bool = None,
        compile: bool = None,
        pov: bool = None,
        test: bool = None,
    ) -> bool:
        """Update patch verification checks"""
        updates = {}
        if apply is not None:
            updates["apply_check"] = apply
        if compile is not None:
            updates["compilation_check"] = compile
        if pov is not None:
            updates["pov_check"] = pov
        if test is not None:
            updates["test_check"] = test
        if updates:
            return self.update(patch_id, updates)
        return False


class SuspiciousPointRepository(BaseRepository[SuspiciousPoint]):
    """Repository for SuspiciousPoint model"""

    def __init__(self, db: Database):
        super().__init__(db, "suspicious_points", SuspiciousPoint)
        # Create indexes for faster queries
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Create indexes for common query patterns."""
        try:
            self.collection.create_index("task_id")
            self.collection.create_index("status")
            self.collection.create_index("function_name")
            self.collection.create_index("score")
            self.collection.create_index([("task_id", 1), ("status", 1)])
            self.collection.create_index([("task_id", 1), ("function_name", 1)])
            self.collection.create_index([("task_id", 1), ("score", -1)])
            self.collection.create_index([("task_id", 1), ("is_checked", 1)])
            # Compound index for claim_for_verify priority sorting
            self.collection.create_index(
                [
                    ("task_id", 1),
                    ("status", 1),
                    ("is_important", -1),
                    ("score", -1),
                    ("created_at", 1),
                ]
            )
        except Exception as e:
            logger.debug(f"Index creation for suspicious_points: {e}")

    def find_by_task(self, task_id: str) -> List[SuspiciousPoint]:
        """Find all suspicious points for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_by_function(
        self, task_id: str, function_name: str
    ) -> List[SuspiciousPoint]:
        """Find suspicious points for a specific function"""
        return self.find_all(
            {"task_id": ObjectId(task_id), "function_name": function_name}
        )

    def find_unchecked(self, task_id: str) -> List[SuspiciousPoint]:
        """Find unchecked suspicious points for a task"""
        return self.find_all({"task_id": ObjectId(task_id), "is_checked": False})

    def find_real(self, task_id: str) -> List[SuspiciousPoint]:
        """Find verified real vulnerabilities for a task"""
        return self.find_all(
            {"task_id": ObjectId(task_id), "is_checked": True, "is_real": True}
        )

    def find_important(self, task_id: str) -> List[SuspiciousPoint]:
        """Find important (high priority) suspicious points"""
        return self.find_all({"task_id": ObjectId(task_id), "is_important": True})

    def find_by_score(
        self, task_id: str, min_score: float = 0.0
    ) -> List[SuspiciousPoint]:
        """Find suspicious points with score >= min_score, sorted by score descending"""
        try:
            cursor = self.collection.find(
                {"task_id": ObjectId(task_id), "score": {"$gte": min_score}}
            ).sort("score", -1)
            return [self.model_class.from_dict(doc) for doc in cursor]
        except Exception as e:
            logger.error(f"Failed to find suspicious points by score: {e}")
            return []

    def mark_checked(self, sp_id: str, is_real: bool, notes: str = None) -> bool:
        """Mark a suspicious point as checked"""
        updates = {"is_checked": True, "is_real": is_real, "checked_at": datetime.now()}
        if notes:
            updates["verification_notes"] = notes
        return self.update(sp_id, updates)

    def mark_important(self, sp_id: str) -> bool:
        """Mark a suspicious point as important (high priority)"""
        return self.update(sp_id, {"is_important": True})

    def update_score(self, sp_id: str, score: float) -> bool:
        """Update the score of a suspicious point"""
        return self.update(sp_id, {"score": score})

    def add_source(self, sp_id: str, harness_name: str, sanitizer: str) -> bool:
        """
        Add a new source to an existing SP.

        Args:
            sp_id: Suspicious point ID
            harness_name: Harness name to add
            sanitizer: Sanitizer to add

        Returns:
            True if source was added, False if already exists or error
        """
        try:
            new_source = {"harness_name": harness_name, "sanitizer": sanitizer}
            # Use $addToSet to avoid duplicates
            result = self.collection.update_one(
                {"_id": ObjectId(sp_id)}, {"$addToSet": {"sources": new_source}}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to add source to SP {sp_id}: {e}")
            return False

    def add_merged_duplicate(
        self,
        sp_id: str,
        description: str,
        vuln_type: str,
        harness_name: str,
        sanitizer: str,
        score: float = 0.0,
    ) -> bool:
        """
        Record a merged duplicate for human review.

        When an SP is identified as a duplicate and merged, this records
        the original description and metadata for later review.

        Args:
            sp_id: Suspicious point ID that the duplicate was merged into
            description: Description of the duplicate SP
            vuln_type: Vulnerability type of the duplicate
            harness_name: Harness that discovered the duplicate
            sanitizer: Sanitizer used
            score: Score of the duplicate

        Returns:
            True if recorded successfully
        """
        try:
            merged_record = {
                "description": description,
                "vuln_type": vuln_type,
                "harness_name": harness_name,
                "sanitizer": sanitizer,
                "score": score,
                "merged_at": datetime.now().isoformat(),
            }
            result = self.collection.update_one(
                {"_id": ObjectId(sp_id)},
                {"$push": {"merged_duplicates": merged_record}},
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to add merged duplicate to SP {sp_id}: {e}")
            return False

    def find_with_merged_duplicates(self, task_id: str) -> List[SuspiciousPoint]:
        """
        Find all SPs that have merged duplicates (for human review).

        Returns:
            List of SPs with at least one merged duplicate
        """
        return self.find_all(
            {
                "task_id": ObjectId(task_id),
                "merged_duplicates": {"$exists": True, "$ne": []},
            }
        )

    def count_by_status(
        self,
        task_id: str,
        status: str = None,
        harness_name: str = None,
        sanitizer: str = None,
    ) -> int | dict:
        """
        Get count of suspicious points by status.

        If status is provided, returns int count for that specific status.
        If status is None, returns dict with all status counts.

        Args:
            task_id: Task ID
            status: Optional status to filter by (pending_verify, verifying, pending_pov, etc.)
            harness_name: Optional fuzzer/harness name filter
            sanitizer: Optional sanitizer filter

        Returns:
            int if status specified, dict of counts otherwise
        """
        try:
            # If specific status requested, return count for that status
            if status is not None:
                query = {"task_id": ObjectId(task_id), "status": status}
                # Filter by sources array (not top-level fields)
                if harness_name and sanitizer:
                    query["sources"] = {
                        "$elemMatch": {
                            "harness_name": harness_name,
                            "sanitizer": sanitizer,
                        }
                    }
                return self.collection.count_documents(query)

            # Otherwise return all counts (original behavior)
            total = self.collection.count_documents({"task_id": ObjectId(task_id)})
            checked = self.collection.count_documents(
                {"task_id": ObjectId(task_id), "is_checked": True}
            )
            real = self.collection.count_documents(
                {"task_id": ObjectId(task_id), "is_checked": True, "is_real": True}
            )
            important = self.collection.count_documents(
                {"task_id": ObjectId(task_id), "is_important": True}
            )
            return {
                "total": total,
                "checked": checked,
                "unchecked": total - checked,
                "real": real,
                "false_positive": checked - real,
                "important": important,
            }
        except Exception as e:
            logger.error(f"Failed to count suspicious points: {e}")
            if status is not None:
                return 0
            return {
                "total": 0,
                "checked": 0,
                "unchecked": 0,
                "real": 0,
                "false_positive": 0,
                "important": 0,
            }

    # =========================================================================
    # Pipeline Methods (Claim-based task distribution)
    # =========================================================================

    def claim_for_verify(
        self,
        task_id: str,
        processor_id: str,
        harness_name: str = None,
        sanitizer: str = None,
    ) -> Optional[SuspiciousPoint]:
        """
        Atomically claim a suspicious point for verification.

        Uses find_one_and_update with atomic operation to prevent race conditions.
        Returns the claimed SP, or None if no SP available.

        Args:
            task_id: Task ID to filter
            processor_id: ID of the agent claiming the task
            harness_name: Filter by harness name (if provided)
            sanitizer: Filter by sanitizer (if provided)

        Returns:
            Claimed SuspiciousPoint, or None if none available
        """
        try:
            from pymongo import ReturnDocument
            from ..core.models import SPStatus

            # Build filter query
            query = {
                "task_id": ObjectId(task_id),
                "status": SPStatus.PENDING_VERIFY.value,
            }
            # Filter by sources array for worker isolation
            if harness_name and sanitizer:
                query["sources"] = {
                    "$elemMatch": {"harness_name": harness_name, "sanitizer": sanitizer}
                }

            # Atomic claim: find pending_verify and update to verifying
            result = self.collection.find_one_and_update(
                query,
                {
                    "$set": {
                        "status": SPStatus.VERIFYING.value,
                        "processor_id": processor_id,
                    }
                },
                # Priority: is_important DESC, score DESC, created_at ASC
                sort=[("is_important", -1), ("score", -1), ("created_at", 1)],
                return_document=ReturnDocument.AFTER,
            )

            if result:
                logger.debug(
                    f"Claimed SP {result['_id']} for verification by {processor_id}"
                )
                return self.model_class.from_dict(result)
            return None

        except Exception as e:
            logger.error(f"Failed to claim SP for verification: {e}")
            return None

    def claim_for_pov(
        self,
        task_id: str,
        processor_id: str,
        min_score: float = 0.5,
        harness_name: str = None,
        sanitizer: str = None,
    ) -> Optional[SuspiciousPoint]:
        """
        Claim a suspicious point for POV generation (parallel mode).

        Multiple workers can attempt the same SP simultaneously.
        First to succeed wins and sets pov_success_by.

        Args:
            task_id: Task ID to filter
            processor_id: ID of the agent claiming the task
            min_score: Minimum score threshold for POV generation
            harness_name: Filter by harness name (if provided)
            sanitizer: Filter by sanitizer (if provided)

        Returns:
            Claimed SuspiciousPoint, or None if none available
        """
        try:
            from pymongo import ReturnDocument
            from ..core.models import SPStatus

            # Build filter query
            query = {
                "task_id": ObjectId(task_id),
                "status": {
                    "$in": [SPStatus.PENDING_POV.value, SPStatus.GENERATING_POV.value]
                },
                "score": {"$gte": min_score},
                "pov_success_by": None,  # Not already succeeded
            }
            # Filter by sources array for worker isolation
            if harness_name and sanitizer:
                query["sources"] = {
                    "$elemMatch": {"harness_name": harness_name, "sanitizer": sanitizer}
                }
                # Exclude SPs that this worker has already attempted
                query["pov_attempted_by"] = {
                    "$not": {
                        "$elemMatch": {
                            "harness_name": harness_name,
                            "sanitizer": sanitizer,
                        }
                    }
                }

            # Parallel claim: add self to attempted list, set status to generating
            attempt_record = {"harness_name": harness_name, "sanitizer": sanitizer}
            result = self.collection.find_one_and_update(
                query,
                {
                    "$set": {
                        "status": SPStatus.GENERATING_POV.value,
                    },
                    "$addToSet": {"pov_attempted_by": attempt_record},
                },
                # Priority: is_important DESC, score DESC
                sort=[("is_important", -1), ("score", -1)],
                return_document=ReturnDocument.AFTER,
            )

            if result:
                logger.debug(
                    f"Claimed SP {result['_id']} for POV generation by {harness_name}/{sanitizer}"
                )
                return self.model_class.from_dict(result)
            return None

        except Exception as e:
            logger.error(f"Failed to claim SP for POV generation: {e}")
            return None

    def complete_verify(
        self,
        sp_id: str,
        is_real: bool,
        score: float,
        notes: str = None,
        is_important: bool = False,
        proceed_to_pov: bool = False,
    ) -> bool:
        """
        Complete verification of a suspicious point.

        Args:
            sp_id: Suspicious point ID
            is_real: Whether it's a real vulnerability
            score: Updated score
            notes: Verification notes
            is_important: Whether to mark as important
            proceed_to_pov: Whether to proceed to POV generation stage

        Returns:
            True if successful
        """
        try:
            from ..core.models import SPStatus

            # Determine next status
            if proceed_to_pov:
                next_status = SPStatus.PENDING_POV.value
            else:
                next_status = SPStatus.VERIFIED.value

            updates = {
                "status": next_status,
                "processor_id": None,  # Release the lock
                "is_checked": True,
                "is_real": is_real,
                "score": score,
                "is_important": is_important,
                "checked_at": datetime.now(),
            }
            if notes:
                updates["verification_notes"] = notes

            return self.update(sp_id, updates)

        except Exception as e:
            logger.error(f"Failed to complete verification: {e}")
            return False

    def complete_pov(
        self,
        sp_id: str,
        pov_id: str = None,
        success: bool = True,
        harness_name: str = None,
        sanitizer: str = None,
    ) -> bool:
        """
        Complete POV generation for a suspicious point (parallel mode).

        On success: marks SP as pov_generated, records pov_success_by
        On failure: worker already in pov_attempted_by, check if others still trying

        Args:
            sp_id: Suspicious point ID
            pov_id: Generated POV ID (if successful)
            success: Whether POV generation succeeded
            harness_name: Worker's harness name
            sanitizer: Worker's sanitizer

        Returns:
            True if successful
        """
        try:
            from ..core.models import SPStatus

            if success:
                # Success - record who succeeded
                success_record = {"harness_name": harness_name, "sanitizer": sanitizer}
                result = self.collection.update_one(
                    {
                        "_id": ObjectId(sp_id),
                        "pov_success_by": None,  # Only if not already succeeded
                    },
                    {
                        "$set": {
                            "status": SPStatus.POV_GENERATED.value,
                            "processor_id": None,
                            "pov_id": pov_id,
                            "pov_success_by": success_record,
                            "pov_generated_at": datetime.now(),
                            "is_real": True,
                        },
                    },
                )
                if result.modified_count > 0:
                    logger.info(
                        f"SP {sp_id}: POV succeeded by {harness_name}/{sanitizer}"
                    )
                    return True
                else:
                    # Someone else already succeeded
                    logger.info(
                        f"SP {sp_id}: POV succeeded by {harness_name}/{sanitizer} but another worker already won"
                    )
                    return False
            else:
                # Failed - check if all contributors have tried
                # For now, just log the failure (worker already in pov_attempted_by from claim)
                logger.info(f"SP {sp_id}: POV failed by {harness_name}/{sanitizer}")

                # Check if we need to mark as failed (all contributors tried)
                sp = self.find_by_id(sp_id)
                if sp:
                    sources_set = {
                        (s["harness_name"], s["sanitizer"]) for s in sp.sources
                    }
                    attempted_set = {
                        (a["harness_name"], a["sanitizer"]) for a in sp.pov_attempted_by
                    }
                    if sources_set == attempted_set and sp.pov_success_by is None:
                        # All contributors tried and failed
                        self.update(sp_id, {"status": SPStatus.FAILED.value})
                        logger.info(
                            f"SP {sp_id}: All contributors failed, marking as FAILED"
                        )
                return True

        except Exception as e:
            logger.error(f"Failed to complete POV generation: {e}")
            return False

    def release_claim(
        self,
        sp_id: str,
        revert_status: str = None,
        harness_name: str = None,
        sanitizer: str = None,
    ) -> bool:
        """
        Release a claimed SP (e.g., on agent failure).

        Args:
            sp_id: Suspicious point ID
            revert_status: Status to revert to (if None, keeps current status)
            harness_name: If provided with sanitizer, also remove from pov_attempted_by
                         so the same worker can retry on crash recovery
            sanitizer: If provided with harness_name, also remove from pov_attempted_by

        Returns:
            True if successful
        """
        try:
            update_ops = {"$set": {"processor_id": None, "updated_at": datetime.now()}}
            if revert_status:
                update_ops["$set"]["status"] = revert_status
            # Clean up pov_attempted_by so same worker can retry after crash
            if harness_name and sanitizer:
                update_ops["$pull"] = {
                    "pov_attempted_by": {
                        "harness_name": harness_name,
                        "sanitizer": sanitizer,
                    }
                }

            _id = self._convert_id(sp_id)
            result = self.collection.update_one({"_id": _id}, update_ops)
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to release claim: {e}")
            return False

    def count_by_pipeline_status(self, task_id: str) -> dict:
        """Get count of suspicious points by pipeline status"""
        try:
            from ..core.models import SPStatus

            counts = {
                "pending_verify": 0,
                "verifying": 0,
                "verified": 0,
                "pending_pov": 0,
                "generating_pov": 0,
                "pov_generated": 0,
                "failed": 0,
            }

            for status in SPStatus:
                counts[status.value] = self.collection.count_documents(
                    {
                        "task_id": ObjectId(task_id),
                        "status": status.value,
                    }
                )

            counts["total"] = sum(counts.values())
            return counts

        except Exception as e:
            logger.error(f"Failed to count by pipeline status: {e}")
            return {"total": 0}

    def is_pipeline_complete(
        self,
        task_id: str,
        harness_name: str = None,
        sanitizer: str = None,
    ) -> bool:
        """
        Check if all SPs have finished processing for this worker.

        For verify stage: checks pending_verify and verifying
        For POV stage (parallel mode): checks if there are SPs that:
            - This worker is a contributor (in sources)
            - Not yet succeeded (pov_success_by is None)
            - This worker hasn't attempted yet

        Args:
            task_id: Task ID to filter
            harness_name: Filter by harness name (if provided)
            sanitizer: Filter by sanitizer (if provided)

        Returns:
            True if no more work for this worker
        """
        try:
            from ..core.models import SPStatus

            if harness_name and sanitizer:
                # Check verify stage SPs
                verify_query = {
                    "task_id": ObjectId(task_id),
                    "status": {
                        "$in": [SPStatus.PENDING_VERIFY.value, SPStatus.VERIFYING.value]
                    },
                    "sources": {
                        "$elemMatch": {
                            "harness_name": harness_name,
                            "sanitizer": sanitizer,
                        }
                    },
                }
                verify_pending = self.collection.count_documents(verify_query)

                # Check POV stage SPs (parallel mode)
                # SP is available if: contributor + not succeeded + not attempted by me
                pov_query = {
                    "task_id": ObjectId(task_id),
                    "status": {
                        "$in": [
                            SPStatus.PENDING_POV.value,
                            SPStatus.GENERATING_POV.value,
                        ]
                    },
                    "sources": {
                        "$elemMatch": {
                            "harness_name": harness_name,
                            "sanitizer": sanitizer,
                        }
                    },
                    "pov_success_by": None,  # Not already succeeded
                    "pov_attempted_by": {
                        "$not": {
                            "$elemMatch": {
                                "harness_name": harness_name,
                                "sanitizer": sanitizer,
                            }
                        }
                    },
                }
                pov_pending = self.collection.count_documents(pov_query)

                return verify_pending == 0 and pov_pending == 0
            else:
                # No worker filter - check all pending/in-progress
                query = {
                    "task_id": ObjectId(task_id),
                    "status": {
                        "$in": [
                            SPStatus.PENDING_VERIFY.value,
                            SPStatus.VERIFYING.value,
                            SPStatus.PENDING_POV.value,
                            SPStatus.GENERATING_POV.value,
                        ]
                    },
                }
                in_progress = self.collection.count_documents(query)
                return in_progress == 0

        except Exception as e:
            logger.error(f"Failed to check pipeline completion: {e}")
            return False


class DirectionRepository(BaseRepository[Direction]):
    """Repository for Direction model (Full-scan analysis directions)"""

    def __init__(self, db: Database):
        super().__init__(db, "directions", Direction)
        # Create indexes for faster queries
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Create indexes for common query patterns."""
        try:
            self.collection.create_index("task_id")
            self.collection.create_index("status")
            self.collection.create_index("fuzzer")
            self.collection.create_index([("task_id", 1), ("fuzzer", 1)])
            self.collection.create_index([("task_id", 1), ("status", 1)])
            self.collection.create_index([("task_id", 1), ("fuzzer", 1), ("status", 1)])
        except Exception as e:
            logger.debug(f"Index creation for directions: {e}")

    def find_by_task(self, task_id: str) -> List[Direction]:
        """Find all directions for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_by_fuzzer(self, task_id: str, fuzzer: str) -> List[Direction]:
        """Find all directions for a specific fuzzer"""
        return self.find_all({"task_id": ObjectId(task_id), "fuzzer": fuzzer})

    def find_pending(self, task_id: str, fuzzer: str = None) -> List[Direction]:
        """Find pending directions"""
        query = {"task_id": ObjectId(task_id), "status": DirectionStatus.PENDING.value}
        if fuzzer:
            query["fuzzer"] = fuzzer
        return self.find_all(query)

    def find_by_priority(self, task_id: str, fuzzer: str = None) -> List[Direction]:
        """Find directions sorted by priority (high risk first)"""
        try:
            query = {"task_id": ObjectId(task_id)}
            if fuzzer:
                query["fuzzer"] = fuzzer
            # Sort by risk level (high > medium > low) and then by created_at
            cursor = self.collection.find(query).sort(
                [
                    (
                        "risk_level",
                        1,
                    ),  # 'high' < 'low' < 'medium' alphabetically, need custom sort
                    ("created_at", 1),
                ]
            )
            directions = [self.model_class.from_dict(doc) for doc in cursor]
            # Custom sort by priority score (descending)
            return sorted(
                directions, key=lambda d: d.get_priority_score(), reverse=True
            )
        except Exception as e:
            logger.error(f"Failed to find directions by priority: {e}")
            return []

    def claim(
        self, task_id: str, fuzzer: str, processor_id: str
    ) -> Optional[Direction]:
        """
        Atomically claim a direction for analysis.

        Args:
            task_id: Task ID
            fuzzer: Fuzzer name
            processor_id: ID of the agent claiming

        Returns:
            Claimed Direction, or None if none available
        """
        try:
            from pymongo import ReturnDocument

            # Find pending directions, prioritize high risk
            # Custom sort needed because risk_level is string
            pending = self.find_pending(task_id, fuzzer)
            if not pending:
                return None

            # Sort by priority
            pending.sort(key=lambda d: d.get_priority_score(), reverse=True)
            target = pending[0]

            # Atomic claim
            result = self.collection.find_one_and_update(
                {
                    "_id": ObjectId(target.direction_id),
                    "status": DirectionStatus.PENDING.value,
                },
                {
                    "$set": {
                        "status": DirectionStatus.IN_PROGRESS.value,
                        "processor_id": processor_id,
                        "started_at": datetime.now(),
                    }
                },
                return_document=ReturnDocument.AFTER,
            )

            if result:
                logger.debug(f"Claimed direction {result['_id']} by {processor_id}")
                return self.model_class.from_dict(result)
            return None

        except Exception as e:
            logger.error(f"Failed to claim direction: {e}")
            return None

    def complete(
        self,
        direction_id: str,
        sp_count: int = 0,
        functions_analyzed: int = 0,
    ) -> bool:
        """
        Mark direction as completed.

        Args:
            direction_id: Direction ID
            sp_count: Number of SPs found
            functions_analyzed: Number of functions analyzed

        Returns:
            True if successful
        """
        return self.update(
            direction_id,
            {
                "status": DirectionStatus.COMPLETED.value,
                "processor_id": None,
                "sp_count": sp_count,
                "functions_analyzed": functions_analyzed,
                "completed_at": datetime.now(),
            },
        )

    def skip(self, direction_id: str, reason: str = "") -> bool:
        """Mark direction as skipped"""
        updates = {
            "status": DirectionStatus.SKIPPED.value,
            "processor_id": None,
            "completed_at": datetime.now(),
        }
        if reason:
            updates["risk_reason"] = f"Skipped: {reason}"
        return self.update(direction_id, updates)

    def release_claim(self, direction_id: str) -> bool:
        """Release a claimed direction (e.g., on agent failure)"""
        return self.update(
            direction_id,
            {
                "status": DirectionStatus.PENDING.value,
                "processor_id": None,
                "started_at": None,
            },
        )

    def count_by_status(self, task_id: str, fuzzer: str = None) -> dict:
        """Get count of directions by status"""
        try:
            query = {"task_id": ObjectId(task_id)}
            if fuzzer:
                query["fuzzer"] = fuzzer

            counts = {
                "pending": 0,
                "in_progress": 0,
                "completed": 0,
                "skipped": 0,
            }

            for status in DirectionStatus:
                q = {**query, "status": status.value}
                counts[status.value] = self.collection.count_documents(q)

            counts["total"] = sum(counts.values())
            return counts

        except Exception as e:
            logger.error(f"Failed to count directions by status: {e}")
            return {"total": 0}

    def is_all_complete(self, task_id: str, fuzzer: str = None) -> bool:
        """Check if all directions are completed or skipped"""
        try:
            query = {"task_id": ObjectId(task_id)}
            if fuzzer:
                query["fuzzer"] = fuzzer
            query["status"] = {
                "$in": [
                    DirectionStatus.PENDING.value,
                    DirectionStatus.IN_PROGRESS.value,
                ]
            }
            pending = self.collection.count_documents(query)
            return pending == 0
        except Exception as e:
            logger.error(f"Failed to check direction completion: {e}")
            return False

    def get_stats(self, task_id: str, fuzzer: str = None) -> dict:
        """Get statistics for directions"""
        try:
            query = {"task_id": ObjectId(task_id)}
            if fuzzer:
                query["fuzzer"] = fuzzer

            pipeline = [
                {"$match": query},
                {
                    "$group": {
                        "_id": None,
                        "total_directions": {"$sum": 1},
                        "total_sp_count": {"$sum": "$sp_count"},
                        "total_functions_analyzed": {"$sum": "$functions_analyzed"},
                        "completed": {
                            "$sum": {"$cond": [{"$eq": ["$status", "completed"]}, 1, 0]}
                        },
                        "high_risk": {
                            "$sum": {"$cond": [{"$eq": ["$risk_level", "high"]}, 1, 0]}
                        },
                        "medium_risk": {
                            "$sum": {
                                "$cond": [{"$eq": ["$risk_level", "medium"]}, 1, 0]
                            }
                        },
                        "low_risk": {
                            "$sum": {"$cond": [{"$eq": ["$risk_level", "low"]}, 1, 0]}
                        },
                    }
                },
            ]

            result = list(self.collection.aggregate(pipeline))
            if result:
                stats = result[0]
                del stats["_id"]
                return stats
            return {
                "total_directions": 0,
                "total_sp_count": 0,
                "total_functions_analyzed": 0,
                "completed": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
            }

        except Exception as e:
            logger.error(f"Failed to get direction stats: {e}")
            return {}

    def delete_by_task(self, task_id: str) -> int:
        """Delete all directions for a task"""
        try:
            result = self.collection.delete_many({"task_id": ObjectId(task_id)})
            return result.deleted_count
        except Exception as e:
            logger.error(f"Failed to delete directions for task: {e}")
            return 0


class WorkerRepository(BaseRepository[Worker]):
    """
    Repository for Worker model.

    Workers use MongoDB ObjectId as primary key.
    Queries by task_id also use ObjectId.
    """

    def __init__(self, db: Database):
        super().__init__(db, "workers", Worker)

    def find_by_id(self, worker_id: str) -> Optional[Worker]:
        """Find worker by ObjectId string."""
        try:
            data = self.collection.find_one({"_id": ObjectId(worker_id)})
            if data:
                return Worker.from_dict(data)
            return None
        except Exception as e:
            logger.error(f"Failed to find Worker by id: {e}")
            return None

    def find_by_task(self, task_id: str) -> List[Worker]:
        """Find all workers for a task (by ObjectId)."""
        try:
            # task_id is stored as ObjectId in workers collection
            cursor = self.collection.find({"task_id": ObjectId(task_id)})
            return [Worker.from_dict(doc) for doc in cursor]
        except Exception as e:
            logger.error(f"Failed to find workers by task: {e}")
            return []

    def find_running_by_task(self, task_id: str) -> List[Worker]:
        """Find running workers for a task."""
        try:
            cursor = self.collection.find(
                {"task_id": ObjectId(task_id), "status": "running"}
            )
            return [Worker.from_dict(doc) for doc in cursor]
        except Exception as e:
            logger.error(f"Failed to find running workers: {e}")
            return []

    def find_by_status(self, status: str) -> List[Worker]:
        """Find workers by status"""
        return self.find_all({"status": status})

    def find_by_fuzzer(
        self, task_id: str, fuzzer: str, sanitizer: str
    ) -> Optional[Worker]:
        """Find worker by task, fuzzer, and sanitizer."""
        try:
            data = self.collection.find_one(
                {
                    "task_id": ObjectId(task_id),
                    "fuzzer": fuzzer,
                    "sanitizer": sanitizer,
                }
            )
            if data:
                return Worker.from_dict(data)
            return None
        except Exception as e:
            logger.error(f"Failed to find worker by fuzzer: {e}")
            return None

    # Fields managed exclusively by WorkerLLMBuffer via $inc.
    # Must NOT be included in save() to avoid overwriting buffer increments.
    _LLM_FIELDS = ("llm_calls", "llm_cost", "llm_input_tokens", "llm_output_tokens")

    def save(self, worker: Worker) -> bool:
        """Save worker to database (upsert by ObjectId).

        Uses $set instead of replace_one to avoid overwriting llm_* fields
        that are managed by WorkerLLMBuffer via atomic $inc.
        """
        try:
            data = worker.to_dict()
            # Ensure _id is ObjectId
            if isinstance(data.get("_id"), str):
                data["_id"] = ObjectId(data["_id"])
            doc_id = data.pop("_id")
            for key in self._LLM_FIELDS:
                data.pop(key, None)
            self.collection.update_one({"_id": doc_id}, {"$set": data}, upsert=True)
            return True
        except Exception as e:
            logger.error(f"Failed to save Worker: {e}")
            return False

    def update(self, worker_id: str, updates: dict) -> bool:
        """Update worker fields by ObjectId."""
        try:
            updates["updated_at"] = datetime.now()
            result = self.collection.update_one(
                {"_id": ObjectId(worker_id)}, {"$set": updates}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to update Worker: {e}")
            return False

    def update_status(self, worker_id: str, status: str, error_msg: str = None) -> bool:
        """Update worker status"""
        updates = {"status": status}
        if error_msg:
            updates["error_msg"] = error_msg
        return self.update(worker_id, updates)

    def update_results(self, worker_id: str, povs: int = 0, patches: int = 0) -> bool:
        """Update worker results"""
        return self.update(
            worker_id, {"pov_generated": povs, "patch_generated": patches}
        )

    def update_strategy(self, worker_id: str, strategy: str) -> bool:
        """Update current strategy and add to history"""
        try:
            result = self.collection.update_one(
                {"_id": ObjectId(worker_id)},
                {
                    "$set": {
                        "current_strategy": strategy,
                        "updated_at": datetime.now(),
                    },
                    "$push": {"strategy_history": strategy},
                },
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to update worker strategy: {e}")
            return False


class FuzzerRepository(BaseRepository[Fuzzer]):
    """Repository for Fuzzer model"""

    def __init__(self, db: Database):
        super().__init__(db, "fuzzers", Fuzzer)

    def find_by_task(self, task_id: str) -> List[Fuzzer]:
        """Find all fuzzers for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_successful_by_task(self, task_id: str) -> List[Fuzzer]:
        """Find successfully built fuzzers"""
        return self.find_all({"task_id": ObjectId(task_id), "status": "success"})

    def find_by_name(self, task_id: str, fuzzer_name: str) -> Optional[Fuzzer]:
        """Find fuzzer by task and name"""
        return self.find_one({"task_id": ObjectId(task_id), "fuzzer_name": fuzzer_name})

    def update_status(
        self,
        fuzzer_id: str,
        status: str,
        error_msg: str = None,
        binary_path: str = None,
    ) -> bool:
        """Update fuzzer build status"""
        updates = {"status": status}
        if error_msg:
            updates["error_msg"] = error_msg
        if binary_path:
            updates["binary_path"] = binary_path
        return self.update(fuzzer_id, updates)


class FunctionRepository(BaseRepository[Function]):
    """Repository for Function model (static analysis metadata)"""

    def __init__(self, db: Database):
        super().__init__(db, "functions", Function)
        # Create indexes for faster queries
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Create indexes for common query patterns."""
        try:
            self.collection.create_index("task_id")
            self.collection.create_index("name")
            self.collection.create_index([("task_id", 1), ("name", 1)])
            self.collection.create_index([("task_id", 1), ("file_path", 1)])
            # SP Find v2: Index for analysis tracking
            self.collection.create_index(
                [("task_id", 1), ("analyzed_by_directions", 1)]
            )
            self.collection.create_index([("task_id", 1), ("reached_by_fuzzers", 1)])
        except Exception as e:
            logger.debug(f"Index creation for functions: {e}")

    def find_by_task(self, task_id: str) -> List[Function]:
        """Find all functions for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_by_name(self, task_id: str, name: str) -> Optional[Function]:
        """Find function by task and name"""
        # First try by constructed ID
        function_id = f"{task_id}_{name}"
        result = self.find_by_id(function_id)
        if result:
            return result
        # Fallback: query by task_id + name fields (for legacy data)
        return self.find_one({"task_id": ObjectId(task_id), "name": name})

    def find_by_file(self, task_id: str, file_path: str) -> List[Function]:
        """Find all functions in a specific file"""
        return self.find_all({"task_id": ObjectId(task_id), "file_path": file_path})

    def save_many(self, functions: List[Function]) -> int:
        """
        Bulk save functions.

        Returns:
            Number of functions saved successfully
        """
        if not functions:
            return 0
        try:
            docs = [f.to_dict() for f in functions]
            # Use bulk write with upsert
            from pymongo import UpdateOne

            operations = [
                UpdateOne({"_id": doc["_id"]}, {"$set": doc}, upsert=True)
                for doc in docs
            ]
            result = self.collection.bulk_write(operations)
            return result.upserted_count + result.modified_count
        except Exception as e:
            logger.error(f"Failed to bulk save functions: {e}")
            return 0

    def delete_by_task(self, task_id: str) -> int:
        """Delete all functions for a task"""
        try:
            result = self.collection.delete_many({"task_id": ObjectId(task_id)})
            return result.deleted_count
        except Exception as e:
            logger.error(f"Failed to delete functions for task: {e}")
            return 0

    # =========================================================================
    # SP Find v2: Analysis Tracking Methods
    # =========================================================================

    def mark_analyzed_by_direction(self, function_id: str, direction_id: str) -> bool:
        """
        Mark a function as analyzed by a specific direction.

        Uses $addToSet to prevent duplicates.

        Args:
            function_id: Function ID
            direction_id: Direction ID that analyzed this function

        Returns:
            True if successful
        """
        try:
            result = self.collection.update_one(
                {"_id": function_id},
                {"$addToSet": {"analyzed_by_directions": ObjectId(direction_id)}},
            )
            return result.modified_count > 0 or result.matched_count > 0
        except Exception as e:
            logger.error(f"Failed to mark function as analyzed: {e}")
            return False

    def mark_many_analyzed(self, function_ids: List[str], direction_id: str) -> int:
        """
        Mark multiple functions as analyzed by a direction.

        Args:
            function_ids: List of function IDs
            direction_id: Direction ID

        Returns:
            Number of functions updated
        """
        if not function_ids:
            return 0
        try:
            result = self.collection.update_many(
                {"_id": {"$in": function_ids}},
                {"$addToSet": {"analyzed_by_directions": ObjectId(direction_id)}},
            )
            return result.modified_count
        except Exception as e:
            logger.error(f"Failed to mark functions as analyzed: {e}")
            return 0

    def get_functions_for_analysis(
        self,
        task_id: str,
        fuzzer_name: str,
        direction_id: str,
        function_names: List[str] = None,
        prioritize_unanalyzed: bool = True,
        limit: int = 0,
    ) -> List[Function]:
        """
        Get functions for SP Find analysis with priority ordering.

        Priority order (when prioritize_unanalyzed=True):
        1. Functions not analyzed by ANY direction
        2. Functions not analyzed by THIS direction
        3. Functions already analyzed by this direction (if exhausted)

        Args:
            task_id: Task ID
            fuzzer_name: Fuzzer name (to filter reachable functions)
            direction_id: Current direction ID
            function_names: Optional list of function names (small pool)
                           If None, uses all reachable functions (big pool)
            prioritize_unanalyzed: Whether to prioritize unanalyzed functions
            limit: Max functions to return (0 = no limit)

        Returns:
            List of Functions ordered by priority
        """
        try:
            # Base query: functions reachable by this fuzzer
            base_query = {
                "task_id": ObjectId(task_id),
                "reached_by_fuzzers": fuzzer_name,
            }

            # If small pool specified, filter by function names
            if function_names:
                base_query["name"] = {"$in": function_names}

            if not prioritize_unanalyzed:
                # Simple query without priority
                cursor = self.collection.find(base_query)
                if limit > 0:
                    cursor = cursor.limit(limit)
                return [self.model_class.from_dict(doc) for doc in cursor]

            # Priority 1: Not analyzed by ANY direction
            query_p1 = {
                **base_query,
                "$or": [
                    {"analyzed_by_directions": {"$exists": False}},
                    {"analyzed_by_directions": {"$size": 0}},
                ],
            }

            # Priority 2: Not analyzed by THIS direction
            query_p2 = {
                **base_query,
                "analyzed_by_directions": {"$nin": [ObjectId(direction_id)]},
            }

            # Priority 3: All functions (including already analyzed)
            query_p3 = base_query

            results = []
            seen_ids = set()

            # Collect from each priority level
            for query in [query_p1, query_p2, query_p3]:
                if limit > 0 and len(results) >= limit:
                    break
                cursor = self.collection.find(query)
                for doc in cursor:
                    if doc["_id"] not in seen_ids:
                        seen_ids.add(doc["_id"])
                        results.append(self.model_class.from_dict(doc))
                        if limit > 0 and len(results) >= limit:
                            break

            return results

        except Exception as e:
            logger.error(f"Failed to get functions for analysis: {e}")
            return []

    def get_unanalyzed_count(
        self,
        task_id: str,
        fuzzer_name: str = None,
        direction_id: str = None,
    ) -> dict:
        """
        Get count of unanalyzed functions.

        Args:
            task_id: Task ID
            fuzzer_name: Optional fuzzer name filter
            direction_id: Optional direction ID to check

        Returns:
            Dict with counts:
            - total: Total functions
            - unanalyzed_by_any: Not analyzed by any direction
            - unanalyzed_by_direction: Not analyzed by specific direction (if provided)
        """
        try:
            base_query = {"task_id": ObjectId(task_id)}
            if fuzzer_name:
                base_query["reached_by_fuzzers"] = fuzzer_name

            total = self.collection.count_documents(base_query)

            # Count not analyzed by any direction
            query_unanalyzed = {
                **base_query,
                "$or": [
                    {"analyzed_by_directions": {"$exists": False}},
                    {"analyzed_by_directions": {"$size": 0}},
                ],
            }
            unanalyzed_by_any = self.collection.count_documents(query_unanalyzed)

            result = {
                "total": total,
                "unanalyzed_by_any": unanalyzed_by_any,
                "analyzed_by_any": total - unanalyzed_by_any,
            }

            # If direction specified, count for that direction
            if direction_id:
                query_not_by_dir = {
                    **base_query,
                    "analyzed_by_directions": {"$nin": [ObjectId(direction_id)]},
                }
                unanalyzed_by_dir = self.collection.count_documents(query_not_by_dir)
                result["unanalyzed_by_direction"] = unanalyzed_by_dir
                result["analyzed_by_direction"] = total - unanalyzed_by_dir

            return result

        except Exception as e:
            logger.error(f"Failed to get unanalyzed count: {e}")
            return {"total": 0, "unanalyzed_by_any": 0, "analyzed_by_any": 0}

    def get_analysis_coverage(self, task_id: str, fuzzer_name: str = None) -> dict:
        """
        Get analysis coverage statistics.

        Args:
            task_id: Task ID
            fuzzer_name: Optional fuzzer name filter

        Returns:
            Dict with coverage stats:
            - total_functions: Total function count
            - analyzed_functions: Functions analyzed by at least one direction
            - coverage_percent: Percentage of functions analyzed
            - by_direction: Dict mapping direction_id to count
        """
        try:
            base_query = {"task_id": ObjectId(task_id)}
            if fuzzer_name:
                base_query["reached_by_fuzzers"] = fuzzer_name

            total = self.collection.count_documents(base_query)
            if total == 0:
                return {
                    "total_functions": 0,
                    "analyzed_functions": 0,
                    "coverage_percent": 0.0,
                    "by_direction": {},
                }

            # Count analyzed (has at least one direction)
            query_analyzed = {
                **base_query,
                "analyzed_by_directions": {"$exists": True, "$ne": []},
            }
            analyzed = self.collection.count_documents(query_analyzed)

            # Aggregate by direction
            pipeline = [
                {"$match": base_query},
                {"$unwind": "$analyzed_by_directions"},
                {"$group": {"_id": "$analyzed_by_directions", "count": {"$sum": 1}}},
            ]
            by_direction = {}
            for doc in self.collection.aggregate(pipeline):
                by_direction[doc["_id"]] = doc["count"]

            return {
                "total_functions": total,
                "analyzed_functions": analyzed,
                "coverage_percent": round(analyzed / total * 100, 2)
                if total > 0
                else 0.0,
                "by_direction": by_direction,
            }

        except Exception as e:
            logger.error(f"Failed to get analysis coverage: {e}")
            return {
                "total_functions": 0,
                "analyzed_functions": 0,
                "coverage_percent": 0.0,
                "by_direction": {},
            }


class CallGraphNodeRepository(BaseRepository[CallGraphNode]):
    """Repository for CallGraphNode model (call graph relationships)"""

    def __init__(self, db: Database):
        super().__init__(db, "callgraph_nodes", CallGraphNode)
        # Create indexes for faster queries
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Create indexes for common query patterns."""
        try:
            self.collection.create_index("task_id")
            self.collection.create_index("function_name")
            self.collection.create_index("call_depth")
            self.collection.create_index([("task_id", 1), ("function_name", 1)])
            self.collection.create_index([("task_id", 1), ("fuzzer_id", 1)])
            self.collection.create_index([("task_id", 1), ("call_depth", 1)])
        except Exception as e:
            logger.debug(f"Index creation for callgraph_nodes: {e}")

    def find_by_task(self, task_id: str) -> List[CallGraphNode]:
        """Find all call graph nodes for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_by_fuzzer(self, task_id: str, fuzzer_id: str) -> List[CallGraphNode]:
        """Find all nodes for a specific fuzzer"""
        return self.find_all({"task_id": ObjectId(task_id), "fuzzer_id": fuzzer_id})

    def find_by_function(
        self, task_id: str, fuzzer_id: str, function_name: str
    ) -> Optional[CallGraphNode]:
        """Find node by function name for a specific fuzzer"""
        node_id = f"{task_id}_{fuzzer_id}_{function_name}"
        return self.find_by_id(node_id)

    def find_callers(
        self, task_id: str, fuzzer_id: str, function_name: str
    ) -> List[str]:
        """Get list of callers for a function"""
        node = self.find_by_function(task_id, fuzzer_id, function_name)
        return node.callers if node else []

    def find_callees(
        self, task_id: str, fuzzer_id: str, function_name: str
    ) -> List[str]:
        """Get list of callees for a function"""
        node = self.find_by_function(task_id, fuzzer_id, function_name)
        return node.callees if node else []

    def find_by_depth(
        self, task_id: str, fuzzer_id: str, depth: int
    ) -> List[CallGraphNode]:
        """Find all nodes at a specific call depth"""
        return self.find_all(
            {"task_id": ObjectId(task_id), "fuzzer_id": fuzzer_id, "call_depth": depth}
        )

    def save_many(self, nodes: List[CallGraphNode]) -> int:
        """
        Bulk save call graph nodes.

        Returns:
            Number of nodes saved successfully
        """
        if not nodes:
            return 0
        try:
            docs = [n.to_dict() for n in nodes]
            from pymongo import UpdateOne

            operations = [
                UpdateOne({"_id": doc["_id"]}, {"$set": doc}, upsert=True)
                for doc in docs
            ]
            result = self.collection.bulk_write(operations)
            return result.upserted_count + result.modified_count
        except Exception as e:
            logger.error(f"Failed to bulk save call graph nodes: {e}")
            return 0

    def delete_by_task(self, task_id: str) -> int:
        """Delete all nodes for a task"""
        try:
            result = self.collection.delete_many({"task_id": ObjectId(task_id)})
            return result.deleted_count
        except Exception as e:
            logger.error(f"Failed to delete call graph nodes for task: {e}")
            return 0

    def delete_by_fuzzer(self, task_id: str, fuzzer_id: str) -> int:
        """Delete all nodes for a specific fuzzer"""
        try:
            result = self.collection.delete_many(
                {"task_id": ObjectId(task_id), "fuzzer_id": fuzzer_id}
            )
            return result.deleted_count
        except Exception as e:
            logger.error(f"Failed to delete call graph nodes for fuzzer: {e}")
            return 0


class RepositoryManager:
    """
    Central repository manager.

    Provides access to all repositories with a shared database connection.
    """

    def __init__(self, db: Database):
        self.db = db
        self._tasks: Optional[TaskRepository] = None
        self._povs: Optional[POVRepository] = None
        self._patches: Optional[PatchRepository] = None
        self._suspicious_points: Optional[SuspiciousPointRepository] = None
        self._directions: Optional[DirectionRepository] = None
        self._workers: Optional[WorkerRepository] = None
        self._fuzzers: Optional[FuzzerRepository] = None
        self._functions: Optional[FunctionRepository] = None
        self._callgraph_nodes: Optional[CallGraphNodeRepository] = None

    @property
    def tasks(self) -> TaskRepository:
        """Get TaskRepository"""
        if self._tasks is None:
            self._tasks = TaskRepository(self.db)
        return self._tasks

    @property
    def povs(self) -> POVRepository:
        """Get POVRepository"""
        if self._povs is None:
            self._povs = POVRepository(self.db)
        return self._povs

    @property
    def patches(self) -> PatchRepository:
        """Get PatchRepository"""
        if self._patches is None:
            self._patches = PatchRepository(self.db)
        return self._patches

    @property
    def suspicious_points(self) -> SuspiciousPointRepository:
        """Get SuspiciousPointRepository"""
        if self._suspicious_points is None:
            self._suspicious_points = SuspiciousPointRepository(self.db)
        return self._suspicious_points

    @property
    def directions(self) -> DirectionRepository:
        """Get DirectionRepository"""
        if self._directions is None:
            self._directions = DirectionRepository(self.db)
        return self._directions

    @property
    def workers(self) -> WorkerRepository:
        """Get WorkerRepository"""
        if self._workers is None:
            self._workers = WorkerRepository(self.db)
        return self._workers

    @property
    def fuzzers(self) -> FuzzerRepository:
        """Get FuzzerRepository"""
        if self._fuzzers is None:
            self._fuzzers = FuzzerRepository(self.db)
        return self._fuzzers

    @property
    def functions(self) -> FunctionRepository:
        """Get FunctionRepository"""
        if self._functions is None:
            self._functions = FunctionRepository(self.db)
        return self._functions

    @property
    def callgraph_nodes(self) -> CallGraphNodeRepository:
        """Get CallGraphNodeRepository"""
        if self._callgraph_nodes is None:
            self._callgraph_nodes = CallGraphNodeRepository(self.db)
        return self._callgraph_nodes


# Global repository manager instance
_repo_manager: Optional[RepositoryManager] = None


def get_repos(db: Database = None) -> RepositoryManager:
    """
    Get the global repository manager.

    Args:
        db: Database instance (required on first call)

    Returns:
        RepositoryManager instance
    """
    global _repo_manager
    if _repo_manager is None:
        if db is None:
            raise RuntimeError("Database not initialized. Pass db on first call.")
        _repo_manager = RepositoryManager(db)
    return _repo_manager


def init_repos(db: Database) -> RepositoryManager:
    """Initialize repository manager with database"""
    global _repo_manager
    _repo_manager = RepositoryManager(db)
    return _repo_manager
