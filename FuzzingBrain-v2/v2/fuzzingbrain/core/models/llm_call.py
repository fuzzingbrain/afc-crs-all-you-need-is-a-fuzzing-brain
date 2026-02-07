"""
LLM Call Model

Represents a single LLM API call for tracking and cost analysis.

Hierarchy:
    Task (ObjectId)
    └── Worker (ObjectId)
        └── Agent (ObjectId)
            └── LLMCall (ObjectId)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any

from bson import ObjectId


@dataclass
class LLMCall:
    """
    Represents a single LLM API call.

    Used for:
    - Cost tracking at granular level
    - Performance analysis (latency)
    - Debugging and auditing
    - Usage analytics
    """

    # Identifiers - ObjectId based
    call_id: str = ""  # ObjectId string
    agent_id: str = ""  # Parent Agent ObjectId
    worker_id: str = ""  # Grandparent Worker ObjectId
    task_id: str = ""  # Great-grandparent Task ObjectId

    # Model info
    model: str = ""  # e.g., "claude-sonnet-4-20250514"
    provider: str = "anthropic"  # anthropic, openai, etc.

    # Token usage
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0

    # Cost (USD)
    cost: float = 0.0

    # Performance
    latency_ms: int = 0  # Response time in milliseconds

    # Status
    success: bool = True
    error_msg: Optional[str] = None

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)

    # Optional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Generate call_id if not provided."""
        if not self.call_id:
            self.call_id = str(ObjectId())

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB/Redis storage."""
        return {
            "_id": ObjectId(self.call_id) if self.call_id else ObjectId(),
            # Note: call_id removed - use _id only
            "agent_id": ObjectId(self.agent_id) if self.agent_id else None,
            "worker_id": ObjectId(self.worker_id) if self.worker_id else None,
            "task_id": ObjectId(self.task_id) if self.task_id else None,
            "model": self.model,
            "provider": self.provider,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_creation_tokens": self.cache_creation_tokens,
            "cost": self.cost,
            "latency_ms": self.latency_ms,
            "success": self.success,
            "error_msg": self.error_msg,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }

    def to_json_dict(self) -> dict:
        """Convert to JSON-serializable dict (for Redis)."""
        return {
            "call_id": self.call_id,
            "agent_id": self.agent_id,
            "worker_id": self.worker_id,
            "task_id": self.task_id,
            "model": self.model,
            "provider": self.provider,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_creation_tokens": self.cache_creation_tokens,
            "cost": self.cost,
            "latency_ms": self.latency_ms,
            "success": self.success,
            "error_msg": self.error_msg,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LLMCall":
        """Create LLMCall from dictionary."""
        # Handle ObjectId conversion
        call_id = data.get("call_id") or data.get("_id")
        if isinstance(call_id, ObjectId):
            call_id = str(call_id)

        agent_id = data.get("agent_id")
        if isinstance(agent_id, ObjectId):
            agent_id = str(agent_id)

        worker_id = data.get("worker_id")
        if isinstance(worker_id, ObjectId):
            worker_id = str(worker_id)

        task_id = data.get("task_id")
        if isinstance(task_id, ObjectId):
            task_id = str(task_id)

        # Handle datetime
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        elif created_at is None:
            created_at = datetime.now()

        return cls(
            call_id=call_id or "",
            agent_id=agent_id or "",
            worker_id=worker_id or "",
            task_id=task_id or "",
            model=data.get("model", ""),
            provider=data.get("provider", "anthropic"),
            input_tokens=data.get("input_tokens", 0),
            output_tokens=data.get("output_tokens", 0),
            cache_read_tokens=data.get("cache_read_tokens", 0),
            cache_creation_tokens=data.get("cache_creation_tokens", 0),
            cost=data.get("cost", 0.0),
            latency_ms=data.get("latency_ms", 0),
            success=data.get("success", True),
            error_msg=data.get("error_msg"),
            created_at=created_at,
            metadata=data.get("metadata", {}),
        )

    @property
    def total_tokens(self) -> int:
        """Get total tokens used."""
        return self.input_tokens + self.output_tokens

    def __repr__(self) -> str:
        return (
            f"LLMCall(id={self.call_id[:8]}..., model={self.model}, "
            f"tokens={self.total_tokens}, cost=${self.cost:.4f})"
        )
