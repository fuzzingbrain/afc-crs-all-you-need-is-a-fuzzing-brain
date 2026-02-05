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
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    # Phase timing (seconds) - for performance analysis
    # Build phase
    phase_build: float = 0.0
    # Strategy phases
    phase_reachability: float = 0.0  # Step 1: Diff reachability check
    phase_find_sp: float = 0.0  # Step 2: Find suspicious points
    phase_verify: float = 0.0  # Step 3: Verify suspicious points
    phase_pov: float = 0.0  # Step 4: POV generation
    phase_save: float = 0.0  # Step 5: Save results

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
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            # Phase timing
            "phase_build": self.phase_build,
            "phase_reachability": self.phase_reachability,
            "phase_find_sp": self.phase_find_sp,
            "phase_verify": self.phase_verify,
            "phase_pov": self.phase_pov,
            "phase_save": self.phase_save,
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
            started_at=data.get("started_at"),
            finished_at=data.get("finished_at"),
            # Phase timing
            phase_build=data.get("phase_build", 0.0),
            phase_reachability=data.get("phase_reachability", 0.0),
            phase_find_sp=data.get("phase_find_sp", 0.0),
            phase_verify=data.get("phase_verify", 0.0),
            phase_pov=data.get("phase_pov", 0.0),
            phase_save=data.get("phase_save", 0.0),
        )

    def mark_running(self):
        """Mark worker as running"""
        self.status = WorkerStatus.RUNNING
        self.started_at = datetime.now()
        self.updated_at = datetime.now()

    def mark_completed(self, povs: int = 0, patches: int = 0):
        """Mark worker as completed"""
        self.status = WorkerStatus.COMPLETED
        self.povs_found = povs
        self.patches_found = patches
        self.finished_at = datetime.now()
        self.updated_at = datetime.now()

    def mark_failed(self, error: str):
        """Mark worker as failed"""
        self.status = WorkerStatus.FAILED
        self.error_msg = error
        self.finished_at = datetime.now()
        self.updated_at = datetime.now()

    def get_duration_seconds(self) -> float:
        """Get worker execution duration in seconds"""
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        elif self.started_at:
            # Still running
            return (datetime.now() - self.started_at).total_seconds()
        return 0.0

    def get_duration_str(self) -> str:
        """Get worker execution duration as formatted string"""
        seconds = self.get_duration_seconds()
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"

    def get_phase_timing(self) -> dict:
        """
        Get phase timing breakdown.

        Returns:
            Dict with phase names, durations, and percentages
        """
        total = self.get_duration_seconds()
        phases = [
            ("Build", self.phase_build, "#4CAF50"),  # Green
            ("Reachability", self.phase_reachability, "#2196F3"),  # Blue
            ("Find SP", self.phase_find_sp, "#FF9800"),  # Orange
            ("Verify", self.phase_verify, "#9C27B0"),  # Purple
            ("POV", self.phase_pov, "#E91E63"),  # Pink
            ("Save", self.phase_save, "#607D8B"),  # Grey
        ]

        result = []
        tracked_total = sum(p[1] for p in phases)
        other_time = max(0, total - tracked_total)

        for name, duration, color in phases:
            if duration > 0:
                pct = (duration / total * 100) if total > 0 else 0
                result.append(
                    {
                        "name": name,
                        "duration": duration,
                        "duration_str": f"{duration:.1f}s"
                        if duration < 60
                        else f"{duration / 60:.1f}m",
                        "percentage": pct,
                        "color": color,
                    }
                )

        # Add "Other" if there's untracked time
        if other_time > 1:  # Only show if > 1 second
            pct = (other_time / total * 100) if total > 0 else 0
            result.append(
                {
                    "name": "Other",
                    "duration": other_time,
                    "duration_str": f"{other_time:.1f}s"
                    if other_time < 60
                    else f"{other_time / 60:.1f}m",
                    "percentage": pct,
                    "color": "#BDBDBD",  # Light grey
                }
            )

        return {
            "total_seconds": total,
            "total_str": self.get_duration_str(),
            "phases": result,
        }
