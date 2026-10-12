# SPDX-License-Identifier: Apache-2.0
"""
Run Model - one execution of a task
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List

from bson import ObjectId

from ..utils import generate_id


class RunStatus(str, Enum):
    """Run status enum"""

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
class Run:
    """
    One execution of a task. The task file describes what to do; a run is one
    attempt at it, with its own id, workspace, status and results.

    What it does is the task's task_type:
    - Finding POVs (proof-of-vulnerability)
    - Generating patches
    - POV + Patch combo
    - Generating harnesses
    """

    # Core identifiers
    run_id: str = field(default_factory=generate_id)
    task_type: JobType = JobType.POV_PATCH
    scan_mode: ScanMode = ScanMode.FULL
    status: RunStatus = RunStatus.PENDING

    # Paths
    workspace_path: Optional[str] = None  # Workspace path
    src_path: Optional[str] = None  # Source code path (repo)
    fuzz_tooling_path: Optional[str] = None  # Fuzzing tooling path
    diff_path: Optional[str] = None  # Delta scan diff file path

    # Task configuration
    repo_url: Optional[str] = None
    project_name: Optional[str] = None
    ossfuzz_project_name: Optional[str] = None
    sanitizers: List[str] = field(default_factory=lambda: ["address"])
    timeout_minutes: int = 30
    pov_count: int = 1
    budget_limit: float = 50.0

    # Commit configuration
    target_commit: Optional[str] = None
    base_commit: Optional[str] = None
    delta_commit: Optional[str] = None

    # Fuzz tooling source
    fuzz_tooling_url: Optional[str] = None
    fuzz_tooling_ref: Optional[str] = None

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
            "_id": ObjectId(self.run_id) if self.run_id else ObjectId(),
            "task_type": self.task_type.value,
            "scan_mode": self.scan_mode.value,
            "status": self.status.value,
            "workspace_path": self.workspace_path,
            "src_path": self.src_path,
            "fuzz_tooling_path": self.fuzz_tooling_path,
            "diff_path": self.diff_path,
            "repo_url": self.repo_url,
            "project_name": self.project_name,
            "ossfuzz_project_name": self.ossfuzz_project_name,
            "sanitizers": self.sanitizers,
            "timeout_minutes": self.timeout_minutes,
            "pov_count": self.pov_count,
            "budget_limit": self.budget_limit,
            "target_commit": self.target_commit,
            "base_commit": self.base_commit,
            "delta_commit": self.delta_commit,
            "fuzz_tooling_url": self.fuzz_tooling_url,
            "fuzz_tooling_ref": self.fuzz_tooling_ref,
            "is_sarif_check": self.is_sarif_check,
            "is_fuzz_tooling_provided": self.is_fuzz_tooling_provided,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "pov_ids": [ObjectId(pid) for pid in self.pov_ids] if self.pov_ids else [],
            "patch_ids": [ObjectId(pid) for pid in self.patch_ids]
            if self.patch_ids
            else [],
            "error_msg": self.error_msg,
            "llm_calls": self.llm_calls,
            "llm_cost": self.llm_cost,
            "llm_input_tokens": self.llm_input_tokens,
            "llm_output_tokens": self.llm_output_tokens,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Run":
        """Create Run from dictionary"""
        # Handle ObjectId conversion
        run_id = data.get("run_id") or data.get("_id")
        if isinstance(run_id, ObjectId):
            run_id = str(run_id)

        return cls(
            run_id=run_id,
            task_type=JobType(data.get("task_type", "pov-patch")),
            scan_mode=ScanMode(data.get("scan_mode", "full")),
            status=RunStatus(data.get("status", "pending")),
            workspace_path=data.get("workspace_path"),
            src_path=data.get("src_path"),
            fuzz_tooling_path=data.get("fuzz_tooling_path"),
            diff_path=data.get("diff_path"),
            repo_url=data.get("repo_url"),
            project_name=data.get("project_name"),
            ossfuzz_project_name=data.get("ossfuzz_project_name"),
            sanitizers=data.get("sanitizers", ["address"]),
            timeout_minutes=data.get("timeout_minutes", 30),
            pov_count=data.get("pov_count", 1),
            budget_limit=data.get("budget_limit", 50.0),
            target_commit=data.get("target_commit"),
            base_commit=data.get("base_commit"),
            delta_commit=data.get("delta_commit"),
            fuzz_tooling_url=data.get("fuzz_tooling_url"),
            fuzz_tooling_ref=data.get("fuzz_tooling_ref"),
            is_sarif_check=data.get("is_sarif_check", False),
            is_fuzz_tooling_provided=data.get("is_fuzz_tooling_provided", False),
            created_at=data.get("created_at", datetime.now()),
            updated_at=data.get("updated_at", datetime.now()),
            pov_ids=[
                str(pid) if isinstance(pid, ObjectId) else pid
                for pid in data.get("pov_ids", [])
            ],
            patch_ids=[
                str(pid) if isinstance(pid, ObjectId) else pid
                for pid in data.get("patch_ids", [])
            ],
            error_msg=data.get("error_msg"),
            llm_calls=data.get("llm_calls", 0),
            llm_cost=data.get("llm_cost", 0.0),
            llm_input_tokens=data.get("llm_input_tokens", 0),
            llm_output_tokens=data.get("llm_output_tokens", 0),
        )

    def mark_running(self):
        """Mark run as running"""
        self.status = RunStatus.RUNNING
        self.updated_at = datetime.now()

    def mark_completed(self):
        """Mark run as completed"""
        self.status = RunStatus.COMPLETED
        self.updated_at = datetime.now()

    def mark_error(self, msg: str):
        """Mark run as error"""
        self.status = RunStatus.ERROR
        self.error_msg = msg
        self.updated_at = datetime.now()
