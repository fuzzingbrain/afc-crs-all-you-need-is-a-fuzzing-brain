"""
FuzzingBrain Core Module

Contains core business logic, configuration, and models.
"""

from .config import Config
from .task_processor import TaskProcessor, process_task
from .logging import (
    logger,
    setup_logging,
    setup_console_only,
    get_log_dir,
    add_task_log,
    get_task_logger,
)

# Re-export models
from .models import (
    Task, TaskStatus, JobType, ScanMode,
    POV,
    Patch,
    Worker, WorkerStatus,
    Fuzzer, FuzzerStatus,
)

__all__ = [
    # Config
    "Config",
    # Processor
    "TaskProcessor",
    "process_task",
    # Logging
    "logger",
    "setup_logging",
    "setup_console_only",
    "get_log_dir",
    "add_task_log",
    "get_task_logger",
    # Models
    "Task", "TaskStatus", "JobType", "ScanMode",
    "POV",
    "Patch",
    "Worker", "WorkerStatus",
    "Fuzzer", "FuzzerStatus",
]
