"""
Base Strategy

Abstract base class for all worker strategies.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional, TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from ..executor import WorkerExecutor


class BaseStrategy(ABC):
    """
    Base class for worker strategies.

    Each strategy implements the core logic for a specific job type:
    - POVStrategy: Find vulnerabilities, generate POVs
    - PatchStrategy: Generate patches for existing POVs
    - HarnessStrategy: Generate new fuzz harnesses
    """

    def __init__(self, executor: "WorkerExecutor"):
        """
        Initialize strategy with executor context.

        Args:
            executor: Parent WorkerExecutor instance (provides workspace, config, etc.)
        """
        self.executor = executor

        # Shortcuts for common executor attributes
        self.workspace_path = executor.workspace_path
        self.project_name = executor.project_name
        self.fuzzer = executor.fuzzer
        self.sanitizer = executor.sanitizer
        self.task_id = executor.task_id
        self.worker_id = executor.worker_id
        self.repos = executor.repos
        self.scan_mode = executor.scan_mode
        self.log_dir = executor.log_dir

        # Paths
        self.results_path = executor.results_path
        self.crashes_path = executor.crashes_path
        self.povs_path = executor.povs_path
        self.patches_path = executor.patches_path

    @property
    def strategy_name(self) -> str:
        """Strategy name for logging."""
        return self.__class__.__name__

    @abstractmethod
    def execute(self) -> Dict[str, Any]:
        """
        Execute the strategy.

        Returns:
            Result dictionary with findings
        """
        pass

    def get_analysis_client(self):
        """Get Analysis Server client from executor."""
        return self.executor.analysis_client

    def get_function(self, name: str) -> Optional[dict]:
        """Query function info from Analysis Server."""
        return self.executor.get_function(name)

    def get_function_source(self, name: str) -> Optional[str]:
        """Get function source code from Analysis Server."""
        return self.executor.get_function_source(name)

    def get_callees(self, function: str) -> list:
        """Get functions called by the given function."""
        return self.executor.get_callees(function)

    def is_reachable(self, function: str) -> bool:
        """Check if function is reachable from this fuzzer."""
        return self.executor.is_reachable(function)

    def log_info(self, msg: str):
        """Log info message with strategy context."""
        logger.info(f"[{self.strategy_name}] {msg}")

    def log_debug(self, msg: str):
        """Log debug message with strategy context."""
        logger.debug(f"[{self.strategy_name}] {msg}")

    def log_warning(self, msg: str):
        """Log warning message with strategy context."""
        logger.warning(f"[{self.strategy_name}] {msg}")

    def log_error(self, msg: str):
        """Log error message with strategy context."""
        logger.error(f"[{self.strategy_name}] {msg}")
