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

    # Verification notes
    verification_notes: Optional[str] = None

    # POV generation result
    pov_id: Optional[str] = None  # ID of generated POV (if any)

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
            "description": self.description,
            "vuln_type": self.vuln_type,
            "status": self.status,
            "processor_id": self.processor_id,
            "is_checked": self.is_checked,
            "is_real": self.is_real,
            "score": self.score,
            "is_important": self.is_important,
            "important_controlflow": self.important_controlflow,
            "verification_notes": self.verification_notes,
            "pov_id": self.pov_id,
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

        return cls(
            suspicious_point_id=data.get("suspicious_point_id", data.get("_id", str(uuid.uuid4()))),
            task_id=data.get("task_id", ""),
            function_name=data.get("function_name", ""),
            description=data.get("description", ""),
            vuln_type=data.get("vuln_type", ""),
            status=data.get("status", SPStatus.PENDING_VERIFY.value),
            processor_id=data.get("processor_id"),
            is_checked=data.get("is_checked", False),
            is_real=data.get("is_real", False),
            score=data.get("score", 0.0),
            is_important=data.get("is_important", False),
            important_controlflow=data.get("important_controlflow", []),
            verification_notes=data.get("verification_notes"),
            pov_id=data.get("pov_id"),
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
