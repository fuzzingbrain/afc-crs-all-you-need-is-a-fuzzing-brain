# SPDX-License-Identifier: Apache-2.0
"""
Logic group Model

A logic group represents a logical grouping of related functions for Full-scan analysis.
Logic group Planning Agent divides the call graph into logic groups, which are then analyzed
by VH Find Agents in parallel.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List

from bson import ObjectId

from ..utils import generate_id, safe_object_id


class LogicGroupStatus(str, Enum):
    """Logic group pipeline status"""

    PENDING = "pending"  # Waiting for analysis
    IN_PROGRESS = "in_progress"  # Being analyzed by an agent
    COMPLETED = "completed"  # Analysis complete
    SKIPPED = "skipped"  # Skipped (e.g., no interesting functions)


class RiskLevel(str, Enum):
    """Security risk level for a logic group"""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class LogicGroup:
    """
    Logic group - A logical grouping of functions for Full-scan analysis.

    Logic group Planning Agent analyzes the call graph and divides it into logic groups,
    each representing a cohesive area of code (e.g., "chunk parsing", "memory management").
    VH Find Agents then claim logic groups and analyze them for vulnerabilities.
    """

    # Identifiers
    lg_id: str = field(default_factory=generate_id)
    run_id: str = ""  # Which run this belongs to
    fuzzer: str = ""  # Which fuzzer this logic group is for

    # Agent reference (ObjectId stored as string)
    created_by_agent_id: Optional[str] = (
        None  # Which LGPlanningAgent created this
    )

    # Logic group info
    name: str = ""  # Human-readable name (e.g., "Chunk Handlers")
    risk_level: str = RiskLevel.MEDIUM.value  # Security risk assessment
    risk_reason: str = ""  # Why this risk level was assigned

    # Functions in this logic group
    core_functions: List[str] = field(default_factory=list)  # Main functions to analyze
    entry_functions: List[str] = field(default_factory=list)  # Entry points from fuzzer

    # Context for VH Find Agent
    call_chain_summary: str = ""  # Summary of call paths
    code_summary: str = ""  # Brief description of what this code does

    # Pipeline status
    status: str = LogicGroupStatus.PENDING.value
    processor_id: Optional[str] = None  # Agent ID processing this logic group

    # Results
    vh_count: int = 0  # Number of VHs found in this logic group
    functions_analyzed: int = 0  # Number of functions analyzed

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        """Convert to dict for MongoDB storage"""
        return {
            "_id": ObjectId(self.lg_id) if self.lg_id else ObjectId(),
            "lg_id": self.lg_id,
            "run_id": ObjectId(self.run_id) if self.run_id else None,
            "created_by_agent_id": ObjectId(self.created_by_agent_id)
            if self.created_by_agent_id
            else None,
            "fuzzer": self.fuzzer,
            "name": self.name,
            "risk_level": self.risk_level,
            "risk_reason": self.risk_reason,
            "core_functions": self.core_functions,
            "entry_functions": self.entry_functions,
            "call_chain_summary": self.call_chain_summary,
            "code_summary": self.code_summary,
            "status": self.status,
            "processor_id": safe_object_id(self.processor_id)
            if self.processor_id
            else None,
            "vh_count": self.vh_count,
            "functions_analyzed": self.functions_analyzed,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LogicGroup":
        """Create Logic group from dict"""

        def parse_datetime(val):
            if isinstance(val, str):
                return datetime.fromisoformat(val)
            elif isinstance(val, datetime):
                return val
            return None

        created_at = parse_datetime(data.get("created_at"))
        if created_at is None:
            created_at = datetime.now()

        # Handle ObjectId conversion
        lg_id = data.get("lg_id") or data.get("_id")
        if isinstance(lg_id, ObjectId):
            lg_id = str(lg_id)

        run_id = data.get("run_id", "")
        if isinstance(run_id, ObjectId):
            run_id = str(run_id)

        created_by_agent_id = data.get("created_by_agent_id")
        if isinstance(created_by_agent_id, ObjectId):
            created_by_agent_id = str(created_by_agent_id)

        processor_id = data.get("processor_id")
        if isinstance(processor_id, ObjectId):
            processor_id = str(processor_id)

        return cls(
            lg_id=lg_id or generate_id(),
            run_id=run_id,
            created_by_agent_id=created_by_agent_id,
            fuzzer=data.get("fuzzer", ""),
            name=data.get("name", ""),
            risk_level=data.get("risk_level", RiskLevel.MEDIUM.value),
            risk_reason=data.get("risk_reason", ""),
            core_functions=data.get("core_functions", []),
            entry_functions=data.get("entry_functions", []),
            call_chain_summary=data.get("call_chain_summary", ""),
            code_summary=data.get("code_summary", ""),
            status=data.get("status", LogicGroupStatus.PENDING.value),
            processor_id=processor_id,
            vh_count=data.get("vh_count", 0),
            functions_analyzed=data.get("functions_analyzed", 0),
            created_at=created_at,
            started_at=parse_datetime(data.get("started_at")),
            completed_at=parse_datetime(data.get("completed_at")),
        )

    def claim(self, agent_id: str):
        """Claim this logic group for processing"""
        self.status = LogicGroupStatus.IN_PROGRESS.value
        self.processor_id = agent_id
        self.started_at = datetime.now()

    def complete(self, vh_count: int = 0, functions_analyzed: int = 0):
        """Mark logic group as completed"""
        self.status = LogicGroupStatus.COMPLETED.value
        self.vh_count = vh_count
        self.functions_analyzed = functions_analyzed
        self.completed_at = datetime.now()

    def skip(self, reason: str = ""):
        """Mark logic group as skipped"""
        self.status = LogicGroupStatus.SKIPPED.value
        if reason:
            self.risk_reason = f"Skipped: {reason}"
        self.completed_at = datetime.now()

    @property
    def is_high_priority(self) -> bool:
        """Check if this is a high priority logic group"""
        return self.risk_level == RiskLevel.HIGH.value

    def get_priority_score(self) -> int:
        """
        Get numeric priority score for sorting.
        Higher score = higher priority.
        """
        risk_scores = {
            RiskLevel.HIGH.value: 100,
            RiskLevel.MEDIUM.value: 50,
            RiskLevel.LOW.value: 10,
        }
        return risk_scores.get(self.risk_level, 50)
