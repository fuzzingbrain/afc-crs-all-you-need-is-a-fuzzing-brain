"""
SuspiciousPoint Model

A suspicious point is a vulnerability analysis granularity between line-level and function-level.
Each suspicious point represents a potential vulnerability location that needs to be verified by AI Agent.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict
import uuid


class SPStatus(str, Enum):
    """SuspiciousPoint pipeline status"""
    # Verification stage
    PENDING_VERIFY = "pending_verify"  # Waiting for verification
    VERIFYING = "verifying"            # Being verified by an agent
    VERIFIED = "verified"              # Verification complete (low score, won't proceed to POV)

    # POV generation stage
    PENDING_POV = "pending_pov"        # High score, waiting for POV generation
    GENERATING_POV = "generating_pov"  # Being processed by POV agent
    POV_GENERATED = "pov_generated"    # POV generation complete

    # Terminal states
    FAILED = "failed"                  # Processing failed
    SKIPPED = "skipped"                # Skipped (e.g., unreachable)


@dataclass
class ControlFlowItem:
    """
    Control flow related item, can be function or variable
    """
    type: str  # "function" | "variable"
    name: str
    location: str  # Location description


@dataclass
class SuspiciousPoint:
    """
    Suspicious Point - Potential vulnerability location

    Suspicious point analysis is the core of the refactored CRS. Previous CRS used function-level
    analysis, which might miss multiple bugs in the same function or fail to detect subtle bugs.
    Each suspicious point represents a line-level analysis.
    """

    # Identifiers
    suspicious_point_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str = ""  # Which task this belongs to
    function_name: str = ""  # Which function this belongs to
    direction_id: str = ""  # Which direction this belongs to (SP Find v2)

    # Sources - which harness/sanitizer combinations discovered this SP
    # Multiple sources indicate the same bug was found by multiple workers (higher confidence)
    # Format: [{"harness_name": "fuzz_png", "sanitizer": "address"}, ...]
    sources: List[Dict] = field(default_factory=list)

    # Description (uses control flow instead of line numbers, as LLMs are not good at generating line numbers)
    description: str = ""

    # Vulnerability type
    vuln_type: str = ""  # buffer-overflow, use-after-free, integer-overflow, null-pointer, etc.

    # Pipeline status (for parallel processing)
    status: str = SPStatus.PENDING_VERIFY.value  # Current pipeline status
    processor_id: Optional[str] = None  # ID of agent currently processing this SP

    # Verification status
    is_checked: bool = False  # Whether verified by LLM
    is_real: bool = False  # True if Agent confirms it's a real bug

    # Priority
    score: float = 0.0  # Score (0.0-1.0), used for queue ordering
    is_important: bool = False  # If marked as high-probability bug, goes to front of queue

    # Related control flow information
    important_controlflow: List[Dict] = field(default_factory=list)
    # Format: [{"type": "function"|"variable", "name": "xxx", "location": "xxx"}, ...]

    # Merged duplicates - records of SPs that were identified as duplicates and merged into this one
    # For human review of dedup decisions
    # Format: [{"description": "...", "vuln_type": "...", "harness_name": "...",
    #           "sanitizer": "...", "score": 0.7, "merged_at": "ISO timestamp"}, ...]
    merged_duplicates: List[Dict] = field(default_factory=list)

    # Verification notes
    verification_notes: Optional[str] = None

    # POV guidance - filled by Verify agent when is_important=True
    # Brief guidance for POV agent: what input directions to try, what to watch out for
    pov_guidance: Optional[str] = None

    # POV generation result
    pov_id: Optional[str] = None  # ID of generated POV (if any)
    pov_success_by: Optional[Dict] = None  # Which worker succeeded: {"harness_name": "...", "sanitizer": "..."}

    # POV attempt tracking - which workers are currently attempting or have failed
    # Format: [{"harness_name": "fuzz_png", "sanitizer": "address"}, ...]
    pov_attempted_by: List[Dict] = field(default_factory=list)

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    checked_at: Optional[datetime] = None
    pov_generated_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        """Convert to dict for MongoDB storage and JSON serialization"""
        return {
            "_id": self.suspicious_point_id,
            "suspicious_point_id": self.suspicious_point_id,
            "task_id": self.task_id,
            "function_name": self.function_name,
            "sources": self.sources,
            "description": self.description,
            "vuln_type": self.vuln_type,
            "status": self.status,
            "processor_id": self.processor_id,
            "is_checked": self.is_checked,
            "is_real": self.is_real,
            "score": self.score,
            "is_important": self.is_important,
            "important_controlflow": self.important_controlflow,
            "merged_duplicates": self.merged_duplicates,
            "verification_notes": self.verification_notes,
            "pov_guidance": self.pov_guidance,
            "pov_id": self.pov_id,
            "pov_success_by": self.pov_success_by,
            "pov_attempted_by": self.pov_attempted_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
            "pov_generated_at": self.pov_generated_at.isoformat() if self.pov_generated_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SuspiciousPoint":
        """Create SuspiciousPoint from dict"""
        # Parse datetime fields (handles both datetime objects and ISO strings)
        def parse_datetime(val):
            if isinstance(val, str):
                return datetime.fromisoformat(val)
            elif isinstance(val, datetime):
                return val
            return None

        created_at = parse_datetime(data.get("created_at"))
        if created_at is None:
            created_at = datetime.now()

        # Handle backward compatibility: convert old harness_name/sanitizer to sources
        sources = data.get("sources", [])
        if not sources and (data.get("harness_name") or data.get("sanitizer")):
            sources = [{"harness_name": data.get("harness_name", ""), "sanitizer": data.get("sanitizer", "")}]

        return cls(
            suspicious_point_id=data.get("suspicious_point_id", data.get("_id", str(uuid.uuid4()))),
            task_id=data.get("task_id", ""),
            function_name=data.get("function_name", ""),
            sources=sources,
            description=data.get("description", ""),
            vuln_type=data.get("vuln_type", ""),
            status=data.get("status", SPStatus.PENDING_VERIFY.value),
            processor_id=data.get("processor_id"),
            is_checked=data.get("is_checked", False),
            is_real=data.get("is_real", False),
            score=data.get("score", 0.0),
            is_important=data.get("is_important", False),
            important_controlflow=data.get("important_controlflow", []),
            merged_duplicates=data.get("merged_duplicates", []),
            verification_notes=data.get("verification_notes"),
            pov_guidance=data.get("pov_guidance"),
            pov_id=data.get("pov_id"),
            pov_success_by=data.get("pov_success_by"),
            pov_attempted_by=data.get("pov_attempted_by", []),
            created_at=created_at,
            checked_at=parse_datetime(data.get("checked_at")),
            pov_generated_at=parse_datetime(data.get("pov_generated_at")),
        )

    def mark_checked(self, is_real: bool, notes: str = None):
        """Mark as verified"""
        self.is_checked = True
        self.is_real = is_real
        self.checked_at = datetime.now()
        if notes:
            self.verification_notes = notes

    def mark_important(self):
        """Mark as important (high priority)"""
        self.is_important = True

    def has_source(self, harness_name: str, sanitizer: str) -> bool:
        """Check if this SP has a specific source"""
        for source in self.sources:
            if source.get("harness_name") == harness_name and source.get("sanitizer") == sanitizer:
                return True
        return False

    def add_source(self, harness_name: str, sanitizer: str) -> bool:
        """
        Add a new source to this SP.

        Returns:
            True if source was added, False if already exists
        """
        if self.has_source(harness_name, sanitizer):
            return False
        self.sources.append({"harness_name": harness_name, "sanitizer": sanitizer})
        return True
