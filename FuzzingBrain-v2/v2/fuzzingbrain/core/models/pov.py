"""
POV Model - Proof of Vulnerability
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List
import uuid


@dataclass
class POV:
    """
    POV (Proof-of-Vulnerability) represents a fuzzing input
    that triggers a bug in the target software.

    In the context of OSS-Fuzz projects, a POV is essentially
    a test input that causes a crash or sanitizer violation.
    """

    # Identifiers
    pov_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str = ""  # Required: which task does this POV belong to

    # POV content
    blob: Optional[str] = None  # Base64 encoded blob content
    gen_blob: Optional[str] = None  # Python code to generate the blob

    # Detection info
    harness_name: Optional[str] = None  # Which fuzzer/harness detected this
    sanitizer: str = "address"  # address | memory | undefined
    sanitizer_output: Optional[str] = None  # Sanitizer crash report

    # Description
    description: Optional[str] = None

    # Status
    is_successful: bool = False  # Does this POV actually trigger a bug?
    is_active: bool = True  # False if duplicate or failed

    # Fixed values (for current version)
    architecture: str = "x86_64"
    engine: str = "libfuzzer"

    # LLM context
    msg_history: List[dict] = field(default_factory=list)

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": self.pov_id,
            "pov_id": self.pov_id,
            "task_id": self.task_id,
            "blob": self.blob,
            "gen_blob": self.gen_blob,
            "harness_name": self.harness_name,
            "sanitizer": self.sanitizer,
            "sanitizer_output": self.sanitizer_output,
            "description": self.description,
            "is_successful": self.is_successful,
            "is_active": self.is_active,
            "architecture": self.architecture,
            "engine": self.engine,
            "msg_history": self.msg_history,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "POV":
        """Create POV from dictionary"""
        return cls(
            pov_id=data.get("pov_id", data.get("_id", str(uuid.uuid4()))),
            task_id=data.get("task_id", ""),
            blob=data.get("blob"),
            gen_blob=data.get("gen_blob"),
            harness_name=data.get("harness_name"),
            sanitizer=data.get("sanitizer", "address"),
            sanitizer_output=data.get("sanitizer_output"),
            description=data.get("description"),
            is_successful=data.get("is_successful", False),
            is_active=data.get("is_active", True),
            architecture=data.get("architecture", "x86_64"),
            engine=data.get("engine", "libfuzzer"),
            msg_history=data.get("msg_history", []),
            created_at=data.get("created_at", datetime.now()),
        )

    def deactivate(self):
        """Mark POV as inactive (duplicate or failed)"""
        self.is_active = False

    def mark_successful(self):
        """Mark POV as successfully triggering a bug"""
        self.is_successful = True
