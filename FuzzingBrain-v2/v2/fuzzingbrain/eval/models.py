"""
Data models for Evaluation Infrastructure.

These models define the structure of data reported by FuzzingBrain instances
to the Evaluation Server.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ReportLevel(Enum):
    """Reporting detail level."""

    MINIMAL = "minimal"  # Only costs and major events
    NORMAL = "normal"  # Costs + events + summary logs
    FULL = "full"  # Complete logs with full content


class EventType(Enum):
    """Event types for the evaluation system."""

    # Lifecycle events
    INSTANCE_STARTED = "instance.started"
    INSTANCE_STOPPED = "instance.stopped"
    TASK_STARTED = "task.started"
    TASK_COMPLETED = "task.completed"
    TASK_FAILED = "task.failed"
    WORKER_STARTED = "worker.started"
    WORKER_COMPLETED = "worker.completed"
    AGENT_STARTED = "agent.started"
    AGENT_ITERATION = "agent.iteration"
    AGENT_COMPLETED = "agent.completed"
    AGENT_FAILED = "agent.failed"

    # Artifact events
    DIRECTION_CREATED = "direction.created"
    DIRECTION_COMPLETED = "direction.completed"
    SP_CREATED = "sp.created"
    SP_VERIFIED = "sp.verified"
    SP_MARKED_REAL = "sp.marked_real"
    SP_MARKED_FP = "sp.marked_fp"
    POV_ATTEMPT = "pov.attempt"
    POV_CREATED = "pov.created"
    POV_CRASHED = "pov.crashed"
    PATCH_CREATED = "patch.created"
    PATCH_VERIFIED = "patch.verified"

    # LLM events
    LLM_CALLED = "llm.called"
    LLM_FAILED = "llm.failed"
    LLM_FALLBACK = "llm.fallback"
    LLM_RATE_LIMITED = "llm.rate_limited"

    # Tool events
    TOOL_CALLED = "tool.called"
    TOOL_FAILED = "tool.failed"

    # Cost events
    COST_THRESHOLD_50 = "cost.threshold_50"
    COST_THRESHOLD_80 = "cost.threshold_80"
    COST_BUDGET_EXCEEDED = "cost.budget_exceeded"


class Severity(Enum):
    """Event severity levels."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class EvalContext:
    """Context for tracking which component is making reports."""

    instance_id: str = ""
    task_id: str = ""
    worker_id: str = ""
    agent_id: str = ""
    agent_type: str = ""
    operation: str = ""
    iteration: int = 0


@dataclass
class LLMCallRecord:
    """Record of a single LLM API call."""

    call_id: str
    timestamp: datetime

    # Model info
    model: str
    provider: str
    fallback_used: bool = False
    original_model: Optional[str] = None

    # Tokens
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

    # Cost (in USD)
    cost_input: float = 0.0
    cost_output: float = 0.0
    cost_total: float = 0.0

    # Timing
    latency_ms: int = 0

    # Context
    context: EvalContext = field(default_factory=EvalContext)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "call_id": self.call_id,
            "timestamp": self.timestamp.isoformat(),
            "model": self.model,
            "provider": self.provider,
            "fallback_used": self.fallback_used,
            "original_model": self.original_model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "cost_input": self.cost_input,
            "cost_output": self.cost_output,
            "cost_total": self.cost_total,
            "latency_ms": self.latency_ms,
            "instance_id": self.context.instance_id,
            "task_id": self.context.task_id,
            "worker_id": self.context.worker_id,
            "agent_id": self.context.agent_id,
            "agent_type": self.context.agent_type,
            "operation": self.context.operation,
            "iteration": self.context.iteration,
        }


@dataclass
class ToolCallRecord:
    """Record of a single tool call."""

    call_id: str
    timestamp: datetime
    tool_name: str
    tool_category: str = ""

    # Arguments (summarized)
    arguments_summary: str = ""

    # Result
    success: bool = True
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    result_size_bytes: int = 0

    # Timing
    latency_ms: int = 0

    # Context
    context: EvalContext = field(default_factory=EvalContext)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "call_id": self.call_id,
            "timestamp": self.timestamp.isoformat(),
            "tool_name": self.tool_name,
            "tool_category": self.tool_category,
            "arguments_summary": self.arguments_summary,
            "success": self.success,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "result_size_bytes": self.result_size_bytes,
            "latency_ms": self.latency_ms,
            "instance_id": self.context.instance_id,
            "task_id": self.context.task_id,
            "worker_id": self.context.worker_id,
            "agent_id": self.context.agent_id,
            "agent_type": self.context.agent_type,
            "iteration": self.context.iteration,
        }


@dataclass
class AgentLogRecord:
    """Record of an agent conversation message."""

    log_id: str
    agent_id: str
    timestamp: datetime

    # Message
    role: str  # system / user / assistant / tool
    content: str = ""  # May be truncated
    content_truncated: bool = False
    thinking: Optional[str] = None  # For assistant messages

    # Tool calls (for assistant messages)
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)

    # Tool result (for tool messages)
    tool_call_id: Optional[str] = None
    tool_name: Optional[str] = None
    tool_success: Optional[bool] = None

    # Context
    context: EvalContext = field(default_factory=EvalContext)

    # Metadata
    tokens: int = 0
    cost: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_id": self.log_id,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp.isoformat(),
            "role": self.role,
            "content": self.content,
            "content_truncated": self.content_truncated,
            "thinking": self.thinking,
            "tool_calls": self.tool_calls,
            "tool_call_id": self.tool_call_id,
            "tool_name": self.tool_name,
            "tool_success": self.tool_success,
            "instance_id": self.context.instance_id,
            "task_id": self.context.task_id,
            "worker_id": self.context.worker_id,
            "agent_type": self.context.agent_type,
            "iteration": self.context.iteration,
            "tokens": self.tokens,
            "cost": self.cost,
        }


@dataclass
class Event:
    """An event in the evaluation system."""

    event_id: str
    event_type: EventType
    timestamp: datetime
    severity: Severity = Severity.INFO

    # Context
    context: EvalContext = field(default_factory=EvalContext)

    # Payload
    payload: Dict[str, Any] = field(default_factory=dict)

    # Tags for filtering
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "instance_id": self.context.instance_id,
            "task_id": self.context.task_id,
            "worker_id": self.context.worker_id,
            "agent_id": self.context.agent_id,
            "agent_type": self.context.agent_type,
            "operation": self.context.operation,
            "payload": self.payload,
            "tags": self.tags,
        }


@dataclass
class InstanceInfo:
    """Information about a FuzzingBrain instance."""

    instance_id: str
    host: str
    pid: int
    version: str
    started_at: datetime
    config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "host": self.host,
            "pid": self.pid,
            "version": self.version,
            "started_at": self.started_at.isoformat(),
            "config": self.config,
        }


@dataclass
class HeartbeatData:
    """Heartbeat data sent periodically."""

    instance_id: str
    timestamp: datetime
    status: str = "running"
    tasks_running: int = 0
    agents_running: int = 0
    cpu_percent: float = 0.0
    memory_gb: float = 0.0
    cost_total: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "tasks_running": self.tasks_running,
            "agents_running": self.agents_running,
            "cpu_percent": self.cpu_percent,
            "memory_gb": self.memory_gb,
            "cost_total": self.cost_total,
        }


# Cost summary for aggregation
@dataclass
class CostSummary:
    """Aggregated cost summary."""

    total_cost: float = 0.0
    total_calls: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0

    by_model: Dict[str, float] = field(default_factory=dict)
    by_provider: Dict[str, float] = field(default_factory=dict)
    by_agent_type: Dict[str, float] = field(default_factory=dict)
    by_operation: Dict[str, float] = field(default_factory=dict)


@dataclass
class ToolSummary:
    """Aggregated tool usage summary."""

    total_calls: int = 0
    total_success: int = 0
    total_failures: int = 0

    by_tool: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    by_category: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    by_error_type: Dict[str, int] = field(default_factory=dict)


@dataclass
class AgentSummary:
    """Aggregated agent summary."""

    agent_id: str
    agent_type: str
    status: str = "running"

    iterations: int = 0
    max_iterations: int = 0
    tool_calls: int = 0
    messages: int = 0

    cost_total: float = 0.0
    duration_seconds: float = 0.0

    exit_reason: Optional[str] = None
