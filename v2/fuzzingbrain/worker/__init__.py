"""
FuzzingBrain Worker Package

Contains worker execution logic:
- builder: Build fuzzer with specific sanitizer
- executor: Run fuzzing strategies
- cleanup: Clean up workspace after completion
- context: Worker isolation with MongoDB ObjectId

Hierarchy:
    Task (ObjectId)
    └── Worker (ObjectId) ← WorkerContext provides this
        └── Agent (ObjectId) ← AgentContext provides this
"""

from .builder import WorkerBuilder
from .executor import WorkerExecutor
from .cleanup import cleanup_worker_workspace
from .context import (
    WorkerContext,
    get_worker_context,
    get_all_worker_contexts,
    # Monitoring API
    get_worker_status,
    get_workers_by_task,
    get_active_workers,
)

__all__ = [
    "WorkerBuilder",
    "WorkerExecutor",
    "cleanup_worker_workspace",
    # Context
    "WorkerContext",
    "get_worker_context",
    "get_all_worker_contexts",
    # Monitoring API
    "get_worker_status",
    "get_workers_by_task",
    "get_active_workers",
]
