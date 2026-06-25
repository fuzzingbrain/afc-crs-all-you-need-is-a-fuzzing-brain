"""
FuzzingBrain Core Module

Contains core business logic, configuration, and models.
"""

from .config import Config, FuzzerWorkerConfig

# NOTE: task_processor and dispatcher are NOT imported here to avoid circular dependency
# Import directly: from fuzzingbrain.core.task_processor import TaskProcessor, process_task
# Import directly: from fuzzingbrain.core.dispatcher import WorkerDispatcher
from .fuzzer_builder import FuzzerBuilder
from .infrastructure import InfrastructureManager, RedisManager, CeleryWorkerManager
from .logging import (
    logger,
    setup_logging,
    setup_celery_logging,
    setup_console_only,
    get_log_dir,
    add_task_log,
    get_task_logger,
    get_analyzer_banner_and_header,
)

# Re-export models
from .models import (
    Task,
    TaskStatus,
    JobType,
    ScanMode,
    POV,
    Patch,
    Worker,
    WorkerStatus,
    Fuzzer,
    FuzzerStatus,
)

__all__ = [
    # Config
    "Config",
    "FuzzerWorkerConfig",
    # NOTE: TaskProcessor, process_task, WorkerDispatcher not exported (circular dependency)
    # Import directly: from fuzzingbrain.core.task_processor import TaskProcessor, process_task
    # Import directly: from fuzzingbrain.core.dispatcher import WorkerDispatcher
    # Builder
    "FuzzerBuilder",
    # Infrastructure
    "InfrastructureManager",
    "RedisManager",
    "CeleryWorkerManager",
    # Logging
    "logger",
    "setup_logging",
    "setup_celery_logging",
    "setup_console_only",
    "get_log_dir",
    "add_task_log",
    "get_task_logger",
    "get_analyzer_banner_and_header",
    # Models
    "Task",
    "TaskStatus",
    "JobType",
    "ScanMode",
    "POV",
    "Patch",
    "Worker",
    "WorkerStatus",
    "Fuzzer",
    "FuzzerStatus",
]
