# SPDX-License-Identifier: Apache-2.0
"""
FuzzingBrain Core Module

Contains core business logic, configuration, and models.
"""

from .config import Config, FuzzerWorkerConfig

# NOTE: run_processor and dispatcher are NOT imported here to avoid circular dependency
# Import directly: from fuzzingbrain.core.run_processor import RunProcessor, process_run
# Import directly: from fuzzingbrain.core.dispatcher import WorkerDispatcher
from .infrastructure import InfrastructureManager, RedisManager, CeleryWorkerManager
from .logging import (
    logger,
    setup_logging,
    file_logger,
    get_log_dir,
    get_analyzer_banner_and_header,
)

__all__ = [
    # Config
    "Config",
    "FuzzerWorkerConfig",
    # NOTE: RunProcessor, process_run, WorkerDispatcher not exported (circular dependency)
    # Import directly: from fuzzingbrain.core.run_processor import RunProcessor, process_run
    # Import directly: from fuzzingbrain.core.dispatcher import WorkerDispatcher
    # Infrastructure
    "InfrastructureManager",
    "RedisManager",
    "CeleryWorkerManager",
    # Logging
    "logger",
    "setup_logging",
    "file_logger",
    "get_log_dir",
    "get_analyzer_banner_and_header",
]
