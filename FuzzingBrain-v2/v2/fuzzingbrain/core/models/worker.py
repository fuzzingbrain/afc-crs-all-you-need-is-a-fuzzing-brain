"""
Worker Model - CRS execution unit
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List


class WorkerStatus(str, Enum):
    """Worker status enum"""
    PENDING = "pending"
    BUILDING = "building"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Worker:
    """
    Worker represents a CRS execution unit.

    Each Worker is responsible for one {fuzzer, sanitizer} combination.
    Workers are dynamically created by the Controller and managed via Celery.

    ID format: {task_id}__{fuzzer}__{sanitizer}
    Example: "task_A__fuzz_png__address"
    """

    # Identifiers
    # _id is the composite key: task_id__fuzzer__sanitizer
    worker_id: str = ""
    celery_job_id: Optional[str] = None  # Celery task ID
    task_id: str = ""

    # Assignment
    task_type: str = "pov"  # pov | patch | harness
    fuzzer: str = ""
    sanitizer: str = "address"

    # Execution context
    workspace_path: Optional[str] = None
    current_strategy: Optional[str] = None
    strategy_history: List[str] = field(default_factory=list)

    # Status
    status: WorkerStatus = WorkerStatus.PENDING
    error_msg: Optional[str] = None

    # Results
    povs_found: int = 0
    patches_found: int = 0

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    @staticmethod
    def generate_worker_id(task_id: str, fuzzer: str, sanitizer: str) -> str:
        """Generate worker ID from components"""
        return f"{task_id}__{fuzzer}__{sanitizer}"

    def __post_init__(self):
        """Generate worker_id if not provided"""
        if not self.worker_id and self.task_id and self.fuzzer:
            self.worker_id = self.generate_worker_id(
                self.task_id, self.fuzzer, self.sanitizer
            )

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": self.worker_id,
            "worker_id": self.worker_id,
            "celery_job_id": self.celery_job_id,
            "task_id": self.task_id,
            "task_type": self.task_type,
            "fuzzer": self.fuzzer,
            "sanitizer": self.sanitizer,
            "workspace_path": self.workspace_path,
            "current_strategy": self.current_strategy,
            "strategy_history": self.strategy_history,
            "status": self.status.value,
            "error_msg": self.error_msg,
            "povs_found": self.povs_found,
            "patches_found": self.patches_found,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Worker":
        """Create Worker from dictionary"""
        return cls(
            worker_id=data.get("worker_id", data.get("_id", "")),
            celery_job_id=data.get("celery_job_id"),
            task_id=data.get("task_id", ""),
            task_type=data.get("task_type", "pov"),
            fuzzer=data.get("fuzzer", ""),
            sanitizer=data.get("sanitizer", "address"),
            workspace_path=data.get("workspace_path"),
            current_strategy=data.get("current_strategy"),
            strategy_history=data.get("strategy_history", []),
            status=WorkerStatus(data.get("status", "pending")),
            error_msg=data.get("error_msg"),
            povs_found=data.get("povs_found", 0),
            patches_found=data.get("patches_found", 0),
            created_at=data.get("created_at", datetime.now()),
            updated_at=data.get("updated_at", datetime.now()),
        )

    def mark_running(self):
        """Mark worker as running"""
        self.status = WorkerStatus.RUNNING
        self.updated_at = datetime.now()

    def mark_completed(self, povs: int = 0, patches: int = 0):
        """Mark worker as completed"""
        self.status = WorkerStatus.COMPLETED
        self.povs_found = povs
        self.patches_found = patches
        self.updated_at = datetime.now()

    def mark_failed(self, error: str):
        """Mark worker as failed"""
        self.status = WorkerStatus.FAILED
        self.error_msg = error
        self.updated_at = datetime.now()
