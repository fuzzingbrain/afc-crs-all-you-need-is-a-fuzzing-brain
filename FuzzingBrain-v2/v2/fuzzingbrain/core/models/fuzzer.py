"""
Fuzzer Model - Fuzzer build tracking
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from bson import ObjectId

from ..utils import generate_id


class FuzzerStatus(str, Enum):
    """Fuzzer build status enum"""

    PENDING = "pending"
    BUILDING = "building"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class Fuzzer:
    """
    Fuzzer tracks the build status of each fuzzer in a task.

    A Task may have multiple fuzzers, each needs to be built separately.
    The Controller manages fuzzer builds and assigns successful ones to Workers.

    Status flow: pending -> building -> success / failed
    """

    # Identifiers
    fuzzer_id: str = field(default_factory=generate_id)
    task_id: str = ""

    # Fuzzer info
    fuzzer_name: str = ""  # Executable name, e.g., "fuzz_png"
    source_path: Optional[str] = None  # Source file path, e.g., "fuzz/fuzz_png.c"
    repo_name: Optional[str] = None  # Software name, e.g., "libpng"

    # Build status
    status: FuzzerStatus = FuzzerStatus.PENDING
    error_msg: Optional[str] = None

    # Build output
    binary_path: Optional[str] = None  # Path to built executable

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": ObjectId(self.fuzzer_id) if self.fuzzer_id else ObjectId(),
            "fuzzer_id": self.fuzzer_id,
            "task_id": ObjectId(self.task_id) if self.task_id else None,
            "fuzzer_name": self.fuzzer_name,
            "source_path": self.source_path,
            "repo_name": self.repo_name,
            "status": self.status.value,
            "error_msg": self.error_msg,
            "binary_path": self.binary_path,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Fuzzer":
        """Create Fuzzer from dictionary"""
        # Handle ObjectId conversion
        fuzzer_id = data.get("fuzzer_id") or data.get("_id")
        if isinstance(fuzzer_id, ObjectId):
            fuzzer_id = str(fuzzer_id)

        task_id = data.get("task_id", "")
        if isinstance(task_id, ObjectId):
            task_id = str(task_id)

        return cls(
            fuzzer_id=fuzzer_id or generate_id(),
            task_id=task_id,
            fuzzer_name=data.get("fuzzer_name", ""),
            source_path=data.get("source_path"),
            repo_name=data.get("repo_name"),
            status=FuzzerStatus(data.get("status", "pending")),
            error_msg=data.get("error_msg"),
            binary_path=data.get("binary_path"),
            created_at=data.get("created_at", datetime.now()),
            updated_at=data.get("updated_at", datetime.now()),
        )

    def mark_building(self):
        """Mark fuzzer as building"""
        self.status = FuzzerStatus.BUILDING
        self.updated_at = datetime.now()

    def mark_success(self, binary_path: str):
        """Mark fuzzer build as successful"""
        self.status = FuzzerStatus.SUCCESS
        self.binary_path = binary_path
        self.updated_at = datetime.now()

    def mark_failed(self, error: str):
        """Mark fuzzer build as failed"""
        self.status = FuzzerStatus.FAILED
        self.error_msg = error
        self.updated_at = datetime.now()
