# SPDX-License-Identifier: Apache-2.0
"""
PoC Model - Proof of Vulnerability
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List

from bson import ObjectId

from ..utils import generate_id


@dataclass
class POC:
    """
    PoC (Proof-of-Vulnerability) represents a fuzzing input
    that triggers a bug in the target software.

    In the context of OSS-Fuzz projects, a PoC is essentially
    a test input that causes a crash or sanitizer violation.
    """

    # Identifiers
    poc_id: str = field(default_factory=generate_id)
    run_id: str = ""  # Required: which run does this PoC belong to
    vulnerability_hypothesis_id: str = ""  # Which vulnerability hypothesis this PoC is for
    generation_id: str = (
        ""  # Group PoCs from same generation (same code, multiple variants)
    )

    # Agent reference (ObjectId stored as string)
    agent_id: Optional[str] = None  # Which POCAgent created this PoC

    # Source tracking - where this PoC came from
    source: str = "agent"  # "agent" | "global_fuzzer" | "vh_fuzzer"
    source_worker_id: Optional[str] = None  # Worker ID for fuzzer-discovered PoCs

    # Iteration tracking (for model evaluation)
    iteration: int = 0  # Which agent loop iteration when created
    attempt: int = 1  # Which PoC attempt (1-40)
    variant: int = 1  # Which variant in this attempt (1-3)

    # PoC content
    blob: Optional[str] = None  # Base64 encoded blob content
    blob_path: Optional[str] = None  # File path where blob is saved
    gen_blob: Optional[str] = None  # Python code to generate the blob

    # Vulnerability info (parsed from sanitizer output after verification)
    vuln_type: Optional[str] = None  # heap-buffer-overflow, stack-use-after-free, etc.
    # The crash's identity: sanitizer class plus the innermost project frames.
    # Two PoCs sharing it are two inputs into one bug, and only the first is a
    # finding.
    signature: str = ""
    # The poc this one repeats, when it repeats one. Kept rather than dropped:
    # the dashboard needs to show both how many inputs were produced and how
    # many bugs they prove, and a row that vanished can answer neither.
    duplicate_of: Optional[str] = None

    # Detection info
    harness_name: Optional[str] = None  # Which fuzzer/harness detected this
    sanitizer: str = "address"  # address | memory | undefined
    sanitizer_output: Optional[str] = None  # Sanitizer crash report

    # Description
    description: Optional[str] = None

    # Status
    is_successful: bool = False  # Does this PoC actually trigger a bug?
    is_active: bool = True  # False if duplicate or failed

    # Fixed values (for current version)
    architecture: str = "x86_64"
    engine: str = "libfuzzer"

    # LLM context
    msg_history: List[dict] = field(default_factory=list)

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    verified_at: Optional[datetime] = None  # When PoC was verified

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": ObjectId(self.poc_id) if self.poc_id else ObjectId(),
            "poc_id": self.poc_id,
            "run_id": ObjectId(self.run_id) if self.run_id else None,
            "vulnerability_hypothesis_id": ObjectId(self.vulnerability_hypothesis_id)
            if self.vulnerability_hypothesis_id
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
            "signature": self.signature,
            "duplicate_of": self.duplicate_of,
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
    def from_dict(cls, data: dict) -> "POC":
        """Create PoC from dictionary"""
        # Handle ObjectId conversion
        poc_id = data.get("poc_id") or data.get("_id")
        if isinstance(poc_id, ObjectId):
            poc_id = str(poc_id)

        run_id = data.get("run_id", "")
        if isinstance(run_id, ObjectId):
            run_id = str(run_id)

        agent_id = data.get("agent_id")
        if isinstance(agent_id, ObjectId):
            agent_id = str(agent_id)

        source_worker_id = data.get("source_worker_id")
        if isinstance(source_worker_id, ObjectId):
            source_worker_id = str(source_worker_id)

        vulnerability_hypothesis_id = data.get("vulnerability_hypothesis_id", "")
        if isinstance(vulnerability_hypothesis_id, ObjectId):
            vulnerability_hypothesis_id = str(vulnerability_hypothesis_id)

        return cls(
            poc_id=poc_id or generate_id(),
            run_id=run_id,
            vulnerability_hypothesis_id=vulnerability_hypothesis_id,
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
            signature=data.get("signature", ""),
            duplicate_of=data.get("duplicate_of"),
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
        """Mark PoC as inactive (duplicate or failed)"""
        self.is_active = False

    def mark_successful(self):
        """Mark PoC as successfully triggering a bug"""
        self.is_successful = True
