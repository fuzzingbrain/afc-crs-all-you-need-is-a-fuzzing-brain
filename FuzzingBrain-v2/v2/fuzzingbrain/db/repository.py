"""
Database Repository

CRUD operations for all FuzzingBrain models.
"""

from datetime import datetime
from typing import Optional, List, TypeVar, Generic, Type
from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.errors import DuplicateKeyError
from loguru import logger

from ..core.models import Task, POV, Patch, Worker, Fuzzer


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
            self.collection.replace_one(
                {"_id": data["_id"]},
                data,
                upsert=True
            )
            return True
        except Exception as e:
            logger.error(f"Failed to save {self.model_class.__name__}: {e}")
            return False

    def find_by_id(self, entity_id: str) -> Optional[T]:
        """Find entity by ID"""
        try:
            data = self.collection.find_one({"_id": entity_id})
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
            result = self.collection.update_one(
                {"_id": entity_id},
                {"$set": updates}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to update {self.model_class.__name__}: {e}")
            return False

    def delete(self, entity_id: str) -> bool:
        """Delete entity by ID"""
        try:
            result = self.collection.delete_one({"_id": entity_id})
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
        return self.collection.count_documents({"_id": entity_id}, limit=1) > 0


class TaskRepository(BaseRepository[Task]):
    """Repository for Task model"""

    def __init__(self, db: Database):
        super().__init__(db, "tasks", Task)

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
                {"_id": task_id},
                {
                    "$push": {"pov_ids": pov_id},
                    "$set": {"updated_at": datetime.now()}
                }
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to add POV to task: {e}")
            return False

    def add_patch(self, task_id: str, patch_id: str) -> bool:
        """Add Patch ID to task"""
        try:
            result = self.collection.update_one(
                {"_id": task_id},
                {
                    "$push": {"patch_ids": patch_id},
                    "$set": {"updated_at": datetime.now()}
                }
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
        return self.find_all({"task_id": task_id})

    def find_active_by_task(self, task_id: str) -> List[POV]:
        """Find active POVs for a task"""
        return self.find_all({"task_id": task_id, "is_active": True})

    def find_successful_by_task(self, task_id: str) -> List[POV]:
        """Find successful POVs for a task"""
        return self.find_all({
            "task_id": task_id,
            "is_active": True,
            "is_successful": True
        })

    def find_by_harness(self, task_id: str, harness_name: str) -> List[POV]:
        """Find POVs for a specific harness"""
        return self.find_all({
            "task_id": task_id,
            "harness_name": harness_name
        })

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
        return self.find_all({"task_id": task_id})

    def find_active_by_task(self, task_id: str) -> List[Patch]:
        """Find active patches for a task"""
        return self.find_all({"task_id": task_id, "is_active": True})

    def find_by_pov(self, pov_id: str) -> List[Patch]:
        """Find patches for a specific POV"""
        return self.find_all({"pov_id": pov_id})

    def find_valid_by_task(self, task_id: str) -> List[Patch]:
        """Find valid patches (passes all checks)"""
        return self.find_all({
            "task_id": task_id,
            "is_active": True,
            "apply_check": True,
            "compilation_check": True,
            "pov_check": True,
            "test_check": True
        })

    def update_checks(self, patch_id: str, apply: bool = None, compile: bool = None,
                      pov: bool = None, test: bool = None) -> bool:
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


class WorkerRepository(BaseRepository[Worker]):
    """Repository for Worker model"""

    def __init__(self, db: Database):
        super().__init__(db, "workers", Worker)

    def find_by_task(self, task_id: str) -> List[Worker]:
        """Find all workers for a task"""
        return self.find_all({"task_id": task_id})

    def find_running_by_task(self, task_id: str) -> List[Worker]:
        """Find running workers for a task"""
        return self.find_all({"task_id": task_id, "status": "running"})

    def find_by_status(self, status: str) -> List[Worker]:
        """Find workers by status"""
        return self.find_all({"status": status})

    def find_by_fuzzer(self, task_id: str, fuzzer: str, sanitizer: str) -> Optional[Worker]:
        """Find worker by task, fuzzer, and sanitizer"""
        worker_id = Worker.generate_worker_id(task_id, fuzzer, sanitizer)
        return self.find_by_id(worker_id)

    def update_status(self, worker_id: str, status: str, error_msg: str = None) -> bool:
        """Update worker status"""
        updates = {"status": status}
        if error_msg:
            updates["error_msg"] = error_msg
        return self.update(worker_id, updates)

    def update_results(self, worker_id: str, povs: int = 0, patches: int = 0) -> bool:
        """Update worker results"""
        return self.update(worker_id, {
            "povs_found": povs,
            "patches_found": patches
        })

    def update_strategy(self, worker_id: str, strategy: str) -> bool:
        """Update current strategy and add to history"""
        try:
            result = self.collection.update_one(
                {"_id": worker_id},
                {
                    "$set": {
                        "current_strategy": strategy,
                        "updated_at": datetime.now()
                    },
                    "$push": {"strategy_history": strategy}
                }
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
        return self.find_all({"task_id": task_id})

    def find_successful_by_task(self, task_id: str) -> List[Fuzzer]:
        """Find successfully built fuzzers"""
        return self.find_all({"task_id": task_id, "status": "success"})

    def find_by_name(self, task_id: str, fuzzer_name: str) -> Optional[Fuzzer]:
        """Find fuzzer by task and name"""
        return self.find_one({"task_id": task_id, "fuzzer_name": fuzzer_name})

    def update_status(self, fuzzer_id: str, status: str, error_msg: str = None,
                      binary_path: str = None) -> bool:
        """Update fuzzer build status"""
        updates = {"status": status}
        if error_msg:
            updates["error_msg"] = error_msg
        if binary_path:
            updates["binary_path"] = binary_path
        return self.update(fuzzer_id, updates)


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
        self._workers: Optional[WorkerRepository] = None
        self._fuzzers: Optional[FuzzerRepository] = None

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
