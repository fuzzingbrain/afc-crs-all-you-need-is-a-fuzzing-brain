"""
CallGraphNode Model - Call graph relationships per fuzzer

Data source: OSS-Fuzz introspector (generated during fuzzer build)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List

from bson import ObjectId


@dataclass
class CallGraphNode:
    """
    CallGraphNode stores call graph relationships for a specific fuzzer.

    Each fuzzer has its own set of reachable functions and call relationships.
    The node_id is {task_id}_{fuzzer_id}_{function_name} to ensure uniqueness.

    Data comes from OSS-Fuzz introspector output, which is generated
    automatically during the fuzzer build process.
    """

    # Identifiers
    node_id: str = ""  # {task_id}_{fuzzer_id}_{function_name}
    task_id: str = ""
    fuzzer_id: str = ""
    fuzzer_name: str = ""  # Redundant for convenience

    # Function reference
    function_name: str = ""  # Links to Function.name

    # Call relationships
    callers: List[str] = field(default_factory=list)  # Functions that call this
    callees: List[str] = field(default_factory=list)  # Functions this calls
    call_depth: int = 0  # Distance from fuzzer entry point

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        """Auto-generate node_id if not set"""
        if not self.node_id and self.task_id and self.fuzzer_id and self.function_name:
            self.node_id = f"{self.task_id}_{self.fuzzer_id}_{self.function_name}"

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": self.node_id,
            "node_id": self.node_id,
            "task_id": ObjectId(self.task_id) if self.task_id else None,
            "fuzzer_id": self.fuzzer_id,
            "fuzzer_name": self.fuzzer_name,
            "function_name": self.function_name,
            "callers": self.callers,
            "callees": self.callees,
            "call_depth": self.call_depth,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CallGraphNode":
        """Create CallGraphNode from dictionary"""
        # Handle ObjectId conversion
        task_id = data.get("task_id", "")
        if isinstance(task_id, ObjectId):
            task_id = str(task_id)

        return cls(
            node_id=data.get("node_id", data.get("_id", "")),
            task_id=task_id,
            fuzzer_id=data.get("fuzzer_id", ""),
            fuzzer_name=data.get("fuzzer_name", ""),
            function_name=data.get("function_name", ""),
            callers=data.get("callers", []),
            callees=data.get("callees", []),
            call_depth=data.get("call_depth", 0),
            created_at=data.get("created_at", datetime.now()),
        )

    def is_entry_point(self) -> bool:
        """Check if this is a fuzzer entry point (depth 0)"""
        return self.call_depth == 0

    def is_leaf(self) -> bool:
        """Check if this function has no callees"""
        return len(self.callees) == 0
