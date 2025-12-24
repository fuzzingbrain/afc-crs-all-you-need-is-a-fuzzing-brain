"""
Worker Executor

Executes fuzzing strategies and generates POV/Patch.
This is the main worker logic that runs after the fuzzer is built.
"""

from pathlib import Path
from typing import Dict, Any, Optional

from ..core import logger
from ..db import RepositoryManager
from ..analyzer import AnalysisClient


class WorkerExecutor:
    """
    Executes fuzzing strategies for a {fuzzer, sanitizer} pair.

    Workflow:
    1. Run fuzzing (libFuzzer)
    2. Collect crashes
    3. Generate POV from crashes
    4. (If patch job) Generate patches
    """

    def __init__(
        self,
        workspace_path: str,
        project_name: str,
        fuzzer: str,
        sanitizer: str,
        job_type: str,
        repos: RepositoryManager,
        task_id: str,
        fuzzer_binary_path: str = None,
        analysis_socket_path: str = None,
    ):
        """
        Initialize WorkerExecutor.

        Args:
            workspace_path: Path to worker workspace
            project_name: Project name
            fuzzer: Fuzzer name
            sanitizer: Sanitizer (address, memory, undefined)
            job_type: Job type (pov, patch, pov-patch, harness)
            repos: Database repository manager
            task_id: Parent task ID
            fuzzer_binary_path: Path to pre-built fuzzer binary (from Analyzer)
            analysis_socket_path: Path to Analysis Server socket for code queries
        """
        self.workspace_path = Path(workspace_path)
        self.project_name = project_name
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.job_type = job_type
        self.repos = repos
        self.task_id = task_id

        # Fuzzer binary path (from Analyzer or built locally)
        self.fuzzer_binary_path = Path(fuzzer_binary_path) if fuzzer_binary_path else None

        # Analysis Server client for code queries
        self.analysis_socket_path = analysis_socket_path
        self._analysis_client: Optional[AnalysisClient] = None

        # Paths
        self.results_path = self.workspace_path / "results"
        self.crashes_path = self.results_path / "crashes"
        self.povs_path = self.results_path / "povs"
        self.patches_path = self.results_path / "patches"

        # Ensure directories exist
        self.crashes_path.mkdir(parents=True, exist_ok=True)
        self.povs_path.mkdir(parents=True, exist_ok=True)
        self.patches_path.mkdir(parents=True, exist_ok=True)

    @property
    def analysis_client(self) -> Optional[AnalysisClient]:
        """
        Get Analysis Server client (lazy initialization).

        Returns:
            AnalysisClient or None if socket not available
        """
        if self._analysis_client is None and self.analysis_socket_path:
            try:
                self._analysis_client = AnalysisClient(self.analysis_socket_path)
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
        """
        Query function information from Analysis Server.

        Args:
            name: Function name

        Returns:
            Function info dict or None
        """
        if self.analysis_client:
            try:
                return self.analysis_client.get_function(name)
            except Exception as e:
                logger.warning(f"Failed to get function {name}: {e}")
        return None

    def get_function_source(self, name: str) -> Optional[str]:
        """
        Get function source code from Analysis Server.

        Args:
            name: Function name

        Returns:
            Source code string or None
        """
        if self.analysis_client:
            try:
                return self.analysis_client.get_function_source(name)
            except Exception as e:
                logger.warning(f"Failed to get source for {name}: {e}")
        return None

    def get_callees(self, function: str) -> list:
        """
        Get functions called by the given function.

        Args:
            function: Function name

        Returns:
            List of callee function names
        """
        if self.analysis_client:
            try:
                return self.analysis_client.get_callees(function)
            except Exception as e:
                logger.warning(f"Failed to get callees for {function}: {e}")
        return []

    def is_reachable(self, function: str) -> bool:
        """
        Check if function is reachable from this fuzzer.

        Args:
            function: Function name

        Returns:
            True if reachable
        """
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

    def run(self) -> Dict[str, Any]:
        """
        Run the worker execution pipeline.

        Returns:
            Result dictionary with findings
        """
        logger.info(f"Starting executor: {self.fuzzer} with {self.sanitizer}")

        result = {
            "povs_found": 0,
            "patches_found": 0,
            "crashes": [],
        }

        try:
            # Step 1: Run fuzzing
            crashes = self._run_fuzzing()
            result["crashes"] = crashes

            if not crashes:
                logger.info("No crashes found")
                return result

            # Step 2: Generate POVs from crashes
            if self.job_type in ["pov", "pov-patch"]:
                povs = self._generate_povs(crashes)
                result["povs_found"] = len(povs)

            # Step 3: Generate patches (if requested)
            if self.job_type in ["patch", "pov-patch"]:
                patches = self._generate_patches()
                result["patches_found"] = len(patches)

            return result

        except Exception as e:
            logger.exception(f"Executor failed: {e}")
            raise

    def _run_fuzzing(self) -> list:
        """
        Run libFuzzer on the target.

        Returns:
            List of crash file paths
        """
        logger.info("Running fuzzing...")

        # TODO: Implement actual fuzzing logic
        # This will involve:
        # 1. Finding the fuzzer binary
        # 2. Running libFuzzer with appropriate flags
        # 3. Collecting crash files
        # 4. Optionally running AI-guided fuzzing

        # Placeholder - return empty list for now
        logger.warning("Fuzzing not yet implemented, returning empty crashes")
        return []

    def _generate_povs(self, crashes: list) -> list:
        """
        Generate POV from crash files.

        Args:
            crashes: List of crash file paths

        Returns:
            List of POV IDs
        """
        logger.info(f"Generating POVs from {len(crashes)} crashes...")

        # TODO: Implement POV generation
        # This will involve:
        # 1. Minimize crash inputs
        # 2. Verify crash reproducibility
        # 3. Generate POV blob
        # 4. Save to database

        povs = []

        for crash in crashes:
            # TODO: Process each crash
            pass

        logger.info(f"Generated {len(povs)} POVs")
        return povs

    def _generate_patches(self) -> list:
        """
        Generate patches for found vulnerabilities.

        Returns:
            List of Patch IDs
        """
        logger.info("Generating patches...")

        # TODO: Implement patch generation
        # This will involve:
        # 1. Analyze vulnerability
        # 2. Use AI to generate fix
        # 3. Verify patch
        # 4. Save to database

        patches = []

        logger.info(f"Generated {len(patches)} patches")
        return patches
