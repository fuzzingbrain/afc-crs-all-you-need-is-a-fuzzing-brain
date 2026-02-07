"""
POV Model - Proof of Vulnerability
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List

from bson import ObjectId

from ..utils import generate_id


@dataclass
class POV:
    """
    POV (Proof-of-Vulnerability) represents a fuzzing input
    that triggers a bug in the target software.

    In the context of OSS-Fuzz projects, a POV is essentially
    a test input that causes a crash or sanitizer violation.
    """

    # Identifiers
    pov_id: str = field(default_factory=generate_id)
    task_id: str = ""  # Required: which task does this POV belong to
    suspicious_point_id: str = ""  # Which suspicious point this POV is for
    generation_id: str = (
        ""  # Group POVs from same generation (same code, multiple variants)
    )

    # Agent reference (ObjectId stored as string)
    agent_id: Optional[str] = None  # Which POVAgent created this POV

    # Source tracking - where this POV came from
    source: str = "agent"  # "agent" | "global_fuzzer" | "sp_fuzzer"
    source_worker_id: Optional[str] = None  # Worker ID for fuzzer-discovered POVs

    # Iteration tracking (for model evaluation)
    iteration: int = 0  # Which agent loop iteration when created
    attempt: int = 1  # Which POV attempt (1-40)
    variant: int = 1  # Which variant in this attempt (1-3)

    # POV content
    blob: Optional[str] = None  # Base64 encoded blob content
    blob_path: Optional[str] = None  # File path where blob is saved
    gen_blob: Optional[str] = None  # Python code to generate the blob

    # Vulnerability info (parsed from sanitizer output after verification)
    vuln_type: Optional[str] = None  # heap-buffer-overflow, stack-use-after-free, etc.

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
    verified_at: Optional[datetime] = None  # When POV was verified

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": ObjectId(self.pov_id) if self.pov_id else ObjectId(),
            # Note: pov_id removed - use _id only
            "task_id": ObjectId(self.task_id) if self.task_id else None,
            "suspicious_point_id": ObjectId(self.suspicious_point_id)
            if self.suspicious_point_id
            else None,
            "generation_id": self.generation_id,
            "agent_id": ObjectId(self.agent_id) if self.agent_id else None,
            "source": self.source,
            "source_worker_id": self.source_worker_id,  # Store as string (metadata, not a reference)
            "iteration": self.iteration,
            "attempt": self.attempt,
            "variant": self.variant,
            "blob": self.blob,
            "blob_path": self.blob_path,
            "gen_blob": self.gen_blob,
            "vuln_type": self.vuln_type,
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
            "verified_at": self.verified_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "POV":
        """Create POV from dictionary"""
        # Handle ObjectId conversion
        pov_id = data.get("pov_id") or data.get("_id")
        if isinstance(pov_id, ObjectId):
            pov_id = str(pov_id)

        task_id = data.get("task_id", "")
        if isinstance(task_id, ObjectId):
            task_id = str(task_id)

        agent_id = data.get("agent_id")
        if isinstance(agent_id, ObjectId):
            agent_id = str(agent_id)

        source_worker_id = data.get("source_worker_id")
        if isinstance(source_worker_id, ObjectId):
            source_worker_id = str(source_worker_id)

        suspicious_point_id = data.get("suspicious_point_id", "")
        if isinstance(suspicious_point_id, ObjectId):
            suspicious_point_id = str(suspicious_point_id)

        return cls(
            pov_id=pov_id or generate_id(),
            task_id=task_id,
            suspicious_point_id=suspicious_point_id,
            generation_id=data.get("generation_id", ""),
            agent_id=agent_id,
            source=data.get("source", "agent"),
            source_worker_id=source_worker_id,
            iteration=data.get("iteration", 0),
            attempt=data.get("attempt", 1),
            variant=data.get("variant", 1),
            blob=data.get("blob"),
            blob_path=data.get("blob_path"),
            gen_blob=data.get("gen_blob"),
            vuln_type=data.get("vuln_type"),
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
            verified_at=data.get("verified_at"),
        )

    def deactivate(self):
        """Mark POV as inactive (duplicate or failed)"""
        self.is_active = False

    def mark_successful(self):
        """Mark POV as successfully triggering a bug"""
        self.is_successful = True
