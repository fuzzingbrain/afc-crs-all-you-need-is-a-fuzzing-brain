"""
Evaluation Infrastructure for FuzzingBrain.

This module provides real-time monitoring, cost tracking, and analytics
for FuzzingBrain instances. Data is reported to a central Evaluation Server
for visualization and analysis.

Usage:
    # Enable reporting (typically done once at startup)
    from fuzzingbrain.eval import create_reporter, get_reporter

    # Create reporter with server URL
    create_reporter(server_url="http://localhost:8081", level="normal")

    # Or disable reporting (default)
    create_reporter()  # Creates NullReporter

    # Get reporter anywhere in code
    reporter = get_reporter()
    reporter.llm_called(...)
    reporter.tool_called(...)
"""

from .models import (
    AgentLogRecord,
    AgentSummary,
    CostSummary,
    EvalContext,
    Event,
    EventType,
    HeartbeatData,
    InstanceInfo,
    LLMCallRecord,
    ReportLevel,
    Severity,
    ToolCallRecord,
    ToolSummary,
)

from .reporter import (
    BaseReporter,
    NullReporter,
    Reporter,
    create_reporter,
    get_reporter,
    set_reporter,
)

__all__ = [
    # Models
    "AgentLogRecord",
    "AgentSummary",
    "CostSummary",
    "EvalContext",
    "Event",
    "EventType",
    "HeartbeatData",
    "InstanceInfo",
    "LLMCallRecord",
    "ReportLevel",
    "Severity",
    "ToolCallRecord",
    "ToolSummary",
    # Reporter
    "BaseReporter",
    "NullReporter",
    "Reporter",
    "create_reporter",
    "get_reporter",
    "set_reporter",
]
