"""
Worker Executor

Dispatches work to the appropriate strategy based on job type.
This is the main entry point for worker logic.
"""

from pathlib import Path
from typing import Dict, Any, Optional

from ..core import logger
from ..db import RepositoryManager
from ..analyzer import AnalysisClient


class WorkerExecutor:
    """
    Executes fuzzing strategies for a {fuzzer, sanitizer} pair.

    The executor is a thin layer that:
    1. Initializes common resources (workspace, analysis client)
    2. Selects the appropriate strategy based on task_type
    3. Delegates execution to the strategy
    """

    def __init__(
        self,
        workspace_path: str,
        project_name: str,
        fuzzer: str,
        sanitizer: str,
        task_type: str,
        repos: RepositoryManager,
        task_id: str,
        scan_mode: str = "full",
        fuzzer_binary_path: str = None,
        analysis_socket_path: str = None,
        diff_path: str = None,
        log_dir: str = None,
    ):
        """
        Initialize WorkerExecutor.

        Args:
            workspace_path: Path to worker workspace
            project_name: Project name
            fuzzer: Fuzzer name
            sanitizer: Sanitizer (address, memory, undefined)
            task_type: Job type (pov, patch, pov-patch, harness)
            repos: Database repository manager
            task_id: Parent task ID
            scan_mode: Scan mode ("full" or "delta")
            fuzzer_binary_path: Path to pre-built fuzzer binary (from Analyzer)
            analysis_socket_path: Path to Analysis Server socket for code queries
            diff_path: Path to diff file (required for delta mode)
            log_dir: Main task log directory for agent logs
        """
        self.workspace_path = Path(workspace_path)
        self.project_name = project_name
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.task_type = task_type
        self.repos = repos
        self.task_id = task_id
        self.scan_mode = scan_mode
        self.log_dir = Path(log_dir) if log_dir else None

        # Fuzzer binary path (from Analyzer or built locally)
        self.fuzzer_binary_path = Path(fuzzer_binary_path) if fuzzer_binary_path else None

        # Analysis Server client for code queries
        self.analysis_socket_path = analysis_socket_path
        self._analysis_client: Optional[AnalysisClient] = None

        # Diff file path (for delta mode)
        # Handle both file path and directory path
        if diff_path:
            diff_p = Path(diff_path)
            if diff_p.is_dir():
                # If directory, look for ref.diff inside
                self.diff_path = diff_p / "ref.diff"
            else:
                self.diff_path = diff_p
        else:
            self.diff_path = self.workspace_path / "diff" / "ref.diff"

        # Paths
        self.results_path = self.workspace_path / "results"
        self.crashes_path = self.results_path / "crashes"
        self.povs_path = self.results_path / "povs"
        self.patches_path = self.results_path / "patches"

        # Ensure directories exist
        self.results_path.mkdir(parents=True, exist_ok=True)
        self.crashes_path.mkdir(parents=True, exist_ok=True)
        self.povs_path.mkdir(parents=True, exist_ok=True)
        self.patches_path.mkdir(parents=True, exist_ok=True)

    @property
    def worker_id(self) -> str:
        """Get worker identifier for logging."""
        return f"worker_{self.task_id}_{self.fuzzer}_{self.sanitizer}"

    @property
    def analysis_client(self) -> Optional[AnalysisClient]:
        """
        Get Analysis Server client (lazy initialization).

        Returns:
            AnalysisClient or None if socket not available
        """
        if self._analysis_client is None and self.analysis_socket_path:
            try:
                self._analysis_client = AnalysisClient(
                    self.analysis_socket_path,
                    client_id=self.worker_id,
                )
                if self._analysis_client.ping():
                    logger.info(f"Connected to Analysis Server: {self.analysis_socket_path}")
                else:
                    logger.warning("Analysis Server not responding")
                    self._analysis_client = None
            except Exception as e:
                logger.warning(f"Failed to connect to Analysis Server: {e}")
                self._analysis_client = None
        return self._analysis_client

    def get_function(self, name: str) -> Optional[dict]:
        """Query function information from Analysis Server."""
        if self.analysis_client:
            try:
                return self.analysis_client.get_function(name)
            except Exception as e:
                logger.warning(f"Failed to get function {name}: {e}")
        return None

    def get_function_source(self, name: str) -> Optional[str]:
        """Get function source code from Analysis Server."""
        if self.analysis_client:
            try:
                return self.analysis_client.get_function_source(name)
            except Exception as e:
                logger.warning(f"Failed to get source for {name}: {e}")
        return None

    def get_callees(self, function: str) -> list:
        """Get functions called by the given function."""
        if self.analysis_client:
            try:
                return self.analysis_client.get_callees(function)
            except Exception as e:
                logger.warning(f"Failed to get callees for {function}: {e}")
        return []

    def is_reachable(self, function: str) -> bool:
        """Check if function is reachable from this fuzzer."""
        if self.analysis_client:
            try:
                return self.analysis_client.is_reachable(self.fuzzer, function)
            except Exception as e:
                logger.warning(f"Failed to check reachability for {function}: {e}")
        return False

    def close(self):
        """Clean up resources."""
        if self._analysis_client:
            self._analysis_client.close()
            self._analysis_client = None

    def _get_strategy(self):
        """
        Get the appropriate strategy for this job type.

        Returns:
            Strategy instance
        """
        from .strategies import POVStrategy, PatchStrategy, HarnessStrategy

        if self.task_type in ["pov", "pov-patch"]:
            return POVStrategy(self)
        elif self.task_type == "patch":
            return PatchStrategy(self)
        elif self.task_type == "harness":
            return HarnessStrategy(self)
        else:
            raise ValueError(f"Unknown job type: {self.task_type}")

    def run(self) -> Dict[str, Any]:
        """
        Run the worker execution pipeline.

        Selects and executes the appropriate strategy based on task_type.

        Returns:
            Result dictionary with findings
        """
        logger.info(f"Starting executor: {self.fuzzer} with {self.sanitizer} (mode: {self.scan_mode}, job: {self.task_type})")

        try:
            # Get strategy for this job type
            strategy = self._get_strategy()
            logger.info(f"Using strategy: {strategy.strategy_name}")

            # Execute strategy
            result = strategy.execute()

            # Add common fields
            result["fuzzer"] = self.fuzzer
            result["sanitizer"] = self.sanitizer
            result["task_type"] = self.task_type

            # Map strategy-specific fields to common result fields
            # (for backward compatibility with tasks.py)
            if "pov_generated" in result:
                result["povs_found"] = result["pov_generated"]
            elif "povs_generated" in result:
                result["povs_found"] = result["povs_generated"]
            if "patches_verified" in result:
                result["patches_found"] = result["patches_verified"]

            return result

        except Exception as e:
            logger.exception(f"Executor failed: {e}")
            raise
