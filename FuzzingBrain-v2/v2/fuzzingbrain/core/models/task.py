"""
Task Model - Represents a single FuzzingBrain task
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List

from ..utils import generate_id


class TaskStatus(str, Enum):
    """Task status enum"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ERROR = "error"


class JobType(str, Enum):
    """Job type enum"""

    POV = "pov"
    PATCH = "patch"
    POV_PATCH = "pov-patch"
    HARNESS = "harness"


class ScanMode(str, Enum):
    """Scan mode enum"""

    FULL = "full"
    DELTA = "delta"


@dataclass
class Task:
    """
    Task represents a single FuzzingBrain task.

    A task can be:
    - Finding POVs (proof-of-vulnerability)
    - Generating patches
    - POV + Patch combo
    - Generating harnesses
    """

    # Core identifiers
    task_id: str = field(default_factory=generate_id)
    task_type: JobType = JobType.POV_PATCH
    scan_mode: ScanMode = ScanMode.FULL
    status: TaskStatus = TaskStatus.PENDING

    # Paths
    task_path: Optional[str] = None  # Workspace path
    src_path: Optional[str] = None  # Source code path (repo)
    fuzz_tooling_path: Optional[str] = None  # Fuzzing tooling path
    diff_path: Optional[str] = None  # Delta scan diff file path

    # Task configuration
    repo_url: Optional[str] = None
    project_name: Optional[str] = None
    sanitizers: List[str] = field(default_factory=lambda: ["address"])
    timeout_minutes: int = 60

    # Delta scan commits
    base_commit: Optional[str] = None
    delta_commit: Optional[str] = None

    # Flags
    is_sarif_check: bool = False
    is_fuzz_tooling_provided: bool = False

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    # Results (IDs of related POVs/Patches)
    pov_ids: List[str] = field(default_factory=list)
    patch_ids: List[str] = field(default_factory=list)

    # Error info
    error_msg: Optional[str] = None

    # LLM usage aggregates (updated by flush)
    llm_calls: int = 0
    llm_cost: float = 0.0
    llm_input_tokens: int = 0
    llm_output_tokens: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": self.task_id,
            "task_id": self.task_id,
            "task_type": self.task_type.value,
            "scan_mode": self.scan_mode.value,
            "status": self.status.value,
            "task_path": self.task_path,
            "src_path": self.src_path,
            "fuzz_tooling_path": self.fuzz_tooling_path,
            "diff_path": self.diff_path,
            "repo_url": self.repo_url,
            "project_name": self.project_name,
            "sanitizers": self.sanitizers,
            "timeout_minutes": self.timeout_minutes,
            "base_commit": self.base_commit,
            "delta_commit": self.delta_commit,
            "is_sarif_check": self.is_sarif_check,
            "is_fuzz_tooling_provided": self.is_fuzz_tooling_provided,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "pov_ids": self.pov_ids,
            "patch_ids": self.patch_ids,
            "error_msg": self.error_msg,
            "llm_calls": self.llm_calls,
            "llm_cost": self.llm_cost,
            "llm_input_tokens": self.llm_input_tokens,
            "llm_output_tokens": self.llm_output_tokens,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Task":
        """Create Task from dictionary"""
        return cls(
            task_id=data.get("task_id", data.get("_id")),
            task_type=JobType(data.get("task_type", "pov-patch")),
            scan_mode=ScanMode(data.get("scan_mode", "full")),
            status=TaskStatus(data.get("status", "pending")),
            task_path=data.get("task_path"),
            src_path=data.get("src_path"),
            fuzz_tooling_path=data.get("fuzz_tooling_path"),
            diff_path=data.get("diff_path"),
            repo_url=data.get("repo_url"),
            project_name=data.get("project_name"),
            sanitizers=data.get("sanitizers", ["address"]),
            timeout_minutes=data.get("timeout_minutes", 60),
            base_commit=data.get("base_commit"),
            delta_commit=data.get("delta_commit"),
            is_sarif_check=data.get("is_sarif_check", False),
            is_fuzz_tooling_provided=data.get("is_fuzz_tooling_provided", False),
            created_at=data.get("created_at", datetime.now()),
            updated_at=data.get("updated_at", datetime.now()),
            pov_ids=data.get("pov_ids", []),
            patch_ids=data.get("patch_ids", []),
            error_msg=data.get("error_msg"),
            llm_calls=data.get("llm_calls", 0),
            llm_cost=data.get("llm_cost", 0.0),
            llm_input_tokens=data.get("llm_input_tokens", 0),
            llm_output_tokens=data.get("llm_output_tokens", 0),
        )

    def mark_running(self):
        """Mark task as running"""
        self.status = TaskStatus.RUNNING
        self.updated_at = datetime.now()

    def mark_completed(self):
        """Mark task as completed"""
        self.status = TaskStatus.COMPLETED
        self.updated_at = datetime.now()

    def mark_error(self, msg: str):
        """Mark task as error"""
        self.status = TaskStatus.ERROR
        self.error_msg = msg
        self.updated_at = datetime.now()
