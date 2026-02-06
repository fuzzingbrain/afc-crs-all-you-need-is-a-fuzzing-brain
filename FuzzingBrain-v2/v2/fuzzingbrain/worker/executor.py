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
from ..fuzzer import (
    FuzzerManager,
    register_fuzzer_manager,
)


class WorkerExecutor:
    """
    Executes fuzzing strategies for a {fuzzer, sanitizer} pair.

    The executor is a thin layer that:
    1. Initializes common resources (workspace, analysis client, fuzzer manager)
    2. Selects the appropriate strategy based on task_type
    3. Delegates execution to the strategy
    4. Manages fuzzer lifecycle (Global Fuzzer + SP Fuzzer Pool)
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
        docker_image: str = "gcr.io/oss-fuzz-base/base-runner",
        enable_fuzzer_worker: bool = True,
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
            docker_image: Docker image for running fuzzers
            enable_fuzzer_worker: Whether to enable FuzzerManager (default True)
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
        self.docker_image = docker_image
        self.enable_fuzzer_worker = enable_fuzzer_worker

        # Fuzzer binary path (from Analyzer or built locally)
        self.fuzzer_binary_path = (
            Path(fuzzer_binary_path) if fuzzer_binary_path else None
        )

        # Analysis Server client for code queries
        self.analysis_socket_path = analysis_socket_path
        self._analysis_client: Optional[AnalysisClient] = None

        # FuzzerManager for Global Fuzzer + SP Fuzzer Pool
        self._fuzzer_manager: Optional[FuzzerManager] = None

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
    def fuzzer_manager(self) -> Optional[FuzzerManager]:
        """
        Get FuzzerManager (lazy initialization).

        Creates FuzzerManager on first access if enabled and fuzzer binary exists.
        """
        if self._fuzzer_manager is None and self.enable_fuzzer_worker:
            if self.fuzzer_binary_path and self.fuzzer_binary_path.exists():
                try:
                    self._fuzzer_manager = FuzzerManager(
                        task_id=self.task_id,
                        worker_id=self.worker_id,
                        fuzzer_path=self.fuzzer_binary_path,
                        docker_image=self.docker_image,
                        workspace_path=self.workspace_path,
                        fuzzer_name=self.fuzzer,
                        sanitizer=self.sanitizer,
                        # Note: crash_monitor is Task-level (in Dispatcher), not Worker-level
                    )
                    # Register for cross-module access
                    register_fuzzer_manager(self.worker_id, self._fuzzer_manager)
                    logger.info(f"[{self.worker_id}] FuzzerManager initialized")
                except Exception as e:
                    logger.warning(
                        f"[{self.worker_id}] Failed to initialize FuzzerManager: {e}"
                    )
                    self._fuzzer_manager = None
            else:
                logger.debug(
                    f"[{self.worker_id}] FuzzerManager not initialized: no fuzzer binary"
                )
        return self._fuzzer_manager

    def _on_crash_found(self, crash_record) -> None:
        """
        Callback when FuzzerMonitor finds a new crash.

        The crash file IS the PoV - directly create POV record.
        Flow: Create POV (inactive) -> Generate Report -> Activate POV

        Args:
            crash_record: CrashRecord from FuzzerMonitor
        """
        import asyncio
        import base64
        import uuid
        from pathlib import Path

        from ..core.models import POV
        from ..core.pov_packager import POVPackager

        logger.info(
            f"[{self.worker_id}] ╔══════════════════════════════════════════════════════════════╗"
        )
        logger.info(
            f"[{self.worker_id}] ║  🎯 CRASH FOUND BY FUZZER!                                   ║"
        )
        logger.info(f"[{self.worker_id}] ║  Hash: {crash_record.crash_hash[:16]:<44} ║")
        logger.info(
            f"[{self.worker_id}] ║  Type: {(crash_record.vuln_type or 'unknown'):<44} ║"
        )
        logger.info(
            f"[{self.worker_id}] ╚══════════════════════════════════════════════════════════════╝"
        )

        try:
            # 1. Read crash file bytes
            crash_path = Path(crash_record.crash_path)
            if not crash_path.exists():
                logger.error(f"[{self.worker_id}] Crash file not found: {crash_path}")
                return

            crash_blob = crash_path.read_bytes()
            crash_blob_b64 = base64.b64encode(crash_blob).decode("utf-8")

            # 2. Create POV record (is_successful=False - don't trigger dispatcher yet!)
            pov_id = str(uuid.uuid4())

            # Get task workspace (not worker workspace) for results
            task_workspace = self.workspace_path
            if "worker_workspace" in str(task_workspace):
                task_workspace = task_workspace.parent.parent
            results_dir = task_workspace / "results"
            povs_dir = results_dir / "povs"
            povs_dir.mkdir(parents=True, exist_ok=True)

            # Copy crash file to povs directory
            pov_blob_path = povs_dir / f"crash_{crash_record.crash_hash[:16]}.bin"
            pov_blob_path.write_bytes(crash_blob)

            pov = POV(
                pov_id=pov_id,
                task_id=self.task_id,
                suspicious_point_id="",  # No SP - fuzzer-discovered
                generation_id=str(uuid.uuid4()),  # Unique generation ID
                iteration=0,
                attempt=1,
                variant=1,
                blob=crash_blob_b64,
                blob_path=str(pov_blob_path),
                gen_blob=f"""# Fuzzer-discovered crash
# Hash: {crash_record.crash_hash}
# Type: {crash_record.vuln_type}

import base64

# POV blob (base64 encoded)
POV_BLOB_B64 = "{crash_blob_b64}"

def generate(variant: int = 1) -> bytes:
    return base64.b64decode(POV_BLOB_B64)
""",
                vuln_type=crash_record.vuln_type,
                harness_name=self.fuzzer,
                sanitizer=self.sanitizer,
                sanitizer_output=crash_record.sanitizer_output[:10000]
                if crash_record.sanitizer_output
                else "",
                description=f"Fuzzer-discovered crash ({crash_record.source})",
                is_successful=False,  # NOT yet! Generate report first
                is_active=True,
                verified_at=None,  # Not verified yet
            )

            # Save POV to database (inactive)
            self.repos.povs.save(pov)
            logger.info(f"[{self.worker_id}] POV {pov_id[:8]} created (pending report)")

            # 3. Package POV with report, then activate
            packager = POVPackager(
                str(results_dir),
                task_id=self.task_id,
                worker_id=self.worker_id,
                repos=self.repos,
                analyzer_socket_path=self.analysis_socket_path,
            )

            # Schedule: package -> activate (called from async context)
            try:
                loop = asyncio.get_running_loop()
                asyncio.create_task(
                    self._package_and_activate_pov(packager, pov, pov_id)
                )
            except RuntimeError:
                # No running loop - run synchronously
                self._package_and_activate_pov_sync(packager, pov, pov_id)

        except Exception as e:
            logger.error(f"[{self.worker_id}] Error processing crash: {e}")
            import traceback

            logger.debug(traceback.format_exc())

    async def _package_and_activate_pov(self, packager, pov, pov_id: str) -> None:
        """
        Async: Package POV with report, then activate it.

        Flow: Generate Report -> Package -> Activate (is_successful=True)

        Args:
            packager: POVPackager instance
            pov: POV object
            pov_id: POV ID for logging
        """
        try:
            # 1. Package POV with report
            logger.info(f"[{self.worker_id}] Generating report for POV {pov_id[:8]}...")
            zip_path = await packager.package_pov_async(pov.to_dict(), None)

            if zip_path:
                logger.info(
                    f"[{self.worker_id}] ✅ POV {pov_id[:8]} packaged: {zip_path}"
                )

                # 2. Activate POV (now dispatcher will detect it)
                self.repos.povs.update(pov_id, {"is_successful": True})
                logger.info(f"[{self.worker_id}] ✅ POV {pov_id[:8]} activated!")
            else:
                logger.warning(f"[{self.worker_id}] Failed to package POV {pov_id[:8]}")

        except Exception as e:
            logger.error(f"[{self.worker_id}] Error packaging POV {pov_id[:8]}: {e}")
            import traceback

            logger.debug(traceback.format_exc())

    def _package_and_activate_pov_sync(self, packager, pov, pov_id: str) -> None:
        """
        Sync: Package POV with report, then activate it.

        Args:
            packager: POVPackager instance
            pov: POV object
            pov_id: POV ID for logging
        """
        try:
            # 1. Package POV with report
            logger.info(f"[{self.worker_id}] Generating report for POV {pov_id[:8]}...")
            zip_path = packager.package_pov(pov.to_dict(), None)

            if zip_path:
                logger.info(
                    f"[{self.worker_id}] ✅ POV {pov_id[:8]} packaged: {zip_path}"
                )

                # 2. Activate POV (now dispatcher will detect it)
                self.repos.povs.update(pov_id, {"is_successful": True})
                logger.info(f"[{self.worker_id}] ✅ POV {pov_id[:8]} activated!")
            else:
                logger.warning(f"[{self.worker_id}] Failed to package POV {pov_id[:8]}")

        except Exception as e:
            logger.error(f"[{self.worker_id}] Error packaging POV {pov_id[:8]}: {e}")
            import traceback

            logger.debug(traceback.format_exc())

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
                    logger.info(
                        f"Connected to Analysis Server: {self.analysis_socket_path}"
                    )
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
        """
        Clean up resources when Worker completes.

        Only shuts down SP Fuzzers; Global Fuzzer and FuzzerMonitor continue
        running until FuzzingBrain ends (timeout/budget/pov_target/manual).
        """
        if self._analysis_client:
            self._analysis_client.close()
            self._analysis_client = None

        # Only shutdown SP Fuzzers, keep Global Fuzzer running
        # Global Fuzzer will be shut down by Dispatcher when task truly ends
        if self._fuzzer_manager:
            import asyncio

            try:
                # Run SP fuzzer shutdown in event loop
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self._fuzzer_manager.shutdown_sp_fuzzers_only())
                else:
                    loop.run_until_complete(
                        self._fuzzer_manager.shutdown_sp_fuzzers_only()
                    )
            except Exception as e:
                logger.warning(
                    f"[{self.worker_id}] Error shutting down SP fuzzers: {e}"
                )
            # NOTE: Do NOT unregister or set to None!
            # FuzzerManager stays registered so Dispatcher can shut it down later

    def _get_strategy(self):
        """
        Get the appropriate strategy for this job type and scan mode.

        Returns:
            Strategy instance
        """
        from .strategies import (
            POVDeltaStrategy,
            POVFullscanStrategy,
            PatchStrategy,
            HarnessStrategy,
        )

        if self.task_type in ["pov", "pov-patch"]:
            # Select POV strategy based on scan mode
            if self.scan_mode == "delta":
                return POVDeltaStrategy(self)
            else:
                return POVFullscanStrategy(self)
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
        logger.info(
            f"Starting executor: {self.fuzzer} with {self.sanitizer} (mode: {self.scan_mode}, job: {self.task_type})"
        )

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
