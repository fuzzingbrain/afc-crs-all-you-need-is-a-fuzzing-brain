"""
Worker Model - CRS execution unit

Uses MongoDB ObjectId as primary key for proper hierarchical linking:
    Task (ObjectId)
    └── Worker (ObjectId)
        └── Agent (ObjectId)
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List

from bson import ObjectId


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
    Workers are created by WorkerContext and persisted to MongoDB.

    ID: MongoDB ObjectId (unique per worker instance)
    Display name: {fuzzer}_{sanitizer} (for logging)
    """

    # Identifiers - ObjectId based
    worker_id: str = ""  # ObjectId string (set by WorkerContext)
    celery_job_id: Optional[str] = None  # Celery task ID
    task_id: str = ""  # Parent Task ObjectId

    # Assignment
    task_type: str = "pov"  # pov | patch | harness
    fuzzer: str = ""
    sanitizer: str = "address"
    scan_mode: str = "full"  # full | delta
    project_name: str = ""

    # Execution context
    workspace_path: Optional[str] = None
    current_strategy: Optional[str] = None
    strategy_history: List[str] = field(default_factory=list)

    # Status
    status: WorkerStatus = WorkerStatus.PENDING
    error_msg: Optional[str] = None

    # Statistics
    agents_spawned: int = 0
    agents_completed: int = 0
    agents_failed: int = 0
    sp_found: int = 0
    sp_verified: int = 0
    pov_generated: int = 0
    patch_generated: int = 0

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    # Phase timing (seconds) - for performance analysis
    phase_build: float = 0.0
    phase_reachability: float = 0.0
    phase_find_sp: float = 0.0
    phase_verify: float = 0.0
    phase_pov: float = 0.0
    phase_save: float = 0.0

    # Result summary
    result_summary: dict = field(default_factory=dict)

    # LLM usage aggregates (updated by flush)
    llm_calls: int = 0
    llm_cost: float = 0.0
    llm_input_tokens: int = 0
    llm_output_tokens: int = 0

    @property
    def display_name(self) -> str:
        """Get human-readable worker name for logging."""
        return f"{self.fuzzer}_{self.sanitizer}"

    @staticmethod
    def generate_display_name(fuzzer: str, sanitizer: str) -> str:
        """Generate display name from components (for logging only)."""
        return f"{fuzzer}_{sanitizer}"

    def __post_init__(self):
        """Generate worker_id if not provided."""
        if not self.worker_id:
            self.worker_id = str(ObjectId())

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "_id": ObjectId(self.worker_id) if self.worker_id else ObjectId(),
            # Note: worker_id removed - use _id only
            "celery_job_id": self.celery_job_id,
            "task_id": ObjectId(self.task_id) if self.task_id else None,
            "task_type": self.task_type,
            "fuzzer": self.fuzzer,
            "sanitizer": self.sanitizer,
            "scan_mode": self.scan_mode,
            "project_name": self.project_name,
            "workspace_path": self.workspace_path,
            "current_strategy": self.current_strategy,
            "strategy_history": self.strategy_history,
            "status": self.status.value,
            "error_msg": self.error_msg,
            # Statistics
            "agents_spawned": self.agents_spawned,
            "agents_completed": self.agents_completed,
            "agents_failed": self.agents_failed,
            "sp_found": self.sp_found,
            "sp_verified": self.sp_verified,
            "pov_generated": self.pov_generated,
            "patch_generated": self.patch_generated,
            # Timestamps
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
            # Result
            "result_summary": self.result_summary,
            # LLM usage
            "llm_calls": self.llm_calls,
            "llm_cost": self.llm_cost,
            "llm_input_tokens": self.llm_input_tokens,
            "llm_output_tokens": self.llm_output_tokens,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Worker":
        """Create Worker from dictionary."""
        # Handle ObjectId conversion
        worker_id = data.get("worker_id") or data.get("_id")
        if isinstance(worker_id, ObjectId):
            worker_id = str(worker_id)

        task_id = data.get("task_id")
        if isinstance(task_id, ObjectId):
            task_id = str(task_id)

        return cls(
            worker_id=worker_id or "",
            celery_job_id=data.get("celery_job_id"),
            task_id=task_id or "",
            task_type=data.get("task_type", "pov"),
            fuzzer=data.get("fuzzer", ""),
            sanitizer=data.get("sanitizer", "address"),
            scan_mode=data.get("scan_mode", "full"),
            project_name=data.get("project_name", ""),
            workspace_path=data.get("workspace_path"),
            current_strategy=data.get("current_strategy"),
            strategy_history=data.get("strategy_history", []),
            status=WorkerStatus(data.get("status", "pending")),
            error_msg=data.get("error_msg"),
            # Statistics
            agents_spawned=data.get("agents_spawned", 0),
            agents_completed=data.get("agents_completed", 0),
            agents_failed=data.get("agents_failed", 0),
            sp_found=data.get("sp_found", 0),
            sp_verified=data.get("sp_verified", 0),
            # Support legacy field names for backward compatibility
            pov_generated=data.get("pov_generated", data.get("povs_found", 0)),
            patch_generated=data.get("patch_generated", data.get("patches_found", 0)),
            # Timestamps
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
            # Result
            result_summary=data.get("result_summary", {}),
            # LLM usage
            llm_calls=data.get("llm_calls", 0),
            llm_cost=data.get("llm_cost", 0.0),
            llm_input_tokens=data.get("llm_input_tokens", 0),
            llm_output_tokens=data.get("llm_output_tokens", 0),
        )

    def mark_running(self):
        """Mark worker as running"""
        self.status = WorkerStatus.RUNNING
        self.started_at = datetime.now()
        self.updated_at = datetime.now()

    def mark_completed(self, pov_count: int = 0, patch_count: int = 0):
        """Mark worker as completed"""
        self.status = WorkerStatus.COMPLETED
        self.pov_generated = pov_count
        self.patch_generated = patch_count
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
