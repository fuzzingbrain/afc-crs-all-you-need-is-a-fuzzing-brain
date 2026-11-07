# SPDX-License-Identifier: Apache-2.0
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
from ..core.config import DEFAULT_MAX_PARALLEL_FUZZERS
from ..fuzzer import (
    FuzzerManager,
    register_fuzzer_manager,
)
from ..fuzzer.signature import extract_class
from .context import WorkerContext


def build_harness_source_blob(paths) -> str:
    """Assemble harness/fuzzer source files into one text blob for prompts.

    `paths` is a str, a list of absolute paths, or None (typically
    fuzzer_sources[fuzzer] from the task file). Each readable file becomes
    ``<basename>\\n<full contents>`` (basename only, no path); blocks are joined
    by a line containing only ``----``. Missing/unreadable files are skipped.
    Returns "" when nothing is configured or readable. Not truncated.
    """
    if not paths:
        return ""
    if isinstance(paths, str):
        paths = [paths]
    blocks = []
    for p in paths:
        try:
            f = Path(p)
            blocks.append(f"{f.name}\n{f.read_text()}")
        except Exception:
            continue
    return "\n----\n".join(blocks)


class WorkerExecutor:
    """
    Executes fuzzing strategies for a {fuzzer, sanitizer} pair.

    The executor is a thin layer that:
    1. Initializes common resources (workspace, analysis client, fuzzer manager)
    2. Selects the appropriate strategy based on task_type
    3. Delegates execution to the strategy
    4. Manages fuzzer lifecycle (Global Fuzzer + VH Fuzzer Pool)
    """

    def __init__(
        self,
        workspace_path: str,
        project_name: str,
        fuzzer: str,
        sanitizer: str,
        task_type: str,
        repos: RepositoryManager,
        run_id: str,
        scan_mode: str = "full",
        fuzzer_binary_path: str = None,
        analysis_socket_path: str = None,
        index_path: Optional[str] = None,
        diff_path: str = None,
        log_dir: str = None,
        docker_image: str = "gcr.io/oss-fuzz-base/base-runner",
        enable_fuzzer_worker: bool = True,
        celery_job_id: str = None,
        run_workspace_path: str = None,
        max_parallel_fuzzers: int = DEFAULT_MAX_PARALLEL_FUZZERS,
        vh_max_count: Optional[int] = None,
        fuzzer_sources: Optional[dict] = None,
    ):
        """
        Initialize WorkerExecutor.

        Args:
            workspace_path: Path to worker workspace
            project_name: Project name
            fuzzer: Fuzzer name
            sanitizer: Sanitizer (address, memory, undefined)
            task_type: Job type (poc, patch, poc-patch, harness)
            repos: Database repository manager
            run_id: Parent run ID
            scan_mode: Scan mode ("full" or "delta")
            fuzzer_binary_path: Path to pre-built fuzzer binary (from Analyzer)
            analysis_socket_path: Path to Analysis Server socket for code queries
            index_path: The run's function index / call graph file
            diff_path: Path to diff file (required for delta mode)
            log_dir: Main run log directory for agent logs
            docker_image: Docker image for running fuzzers
            enable_fuzzer_worker: Whether to enable FuzzerManager (default True)
            celery_job_id: Celery task ID (for WorkerContext tracking)
            run_workspace_path: Path to main run workspace (shared repo/fuzz-tooling/diff)
            max_parallel_fuzzers: run-wide ceiling on running fuzzers
            vh_max_count: per-worker ceiling on running VH fuzzers
        """
        self.workspace_path = Path(workspace_path)
        self.run_workspace_path = (
            Path(run_workspace_path) if run_workspace_path else self.workspace_path
        )
        self.project_name = project_name
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.task_type = task_type
        self.repos = repos
        self.run_id = run_id
        self.scan_mode = scan_mode
        self.log_dir = Path(log_dir) if log_dir else None
        self.docker_image = docker_image
        self.enable_fuzzer_worker = enable_fuzzer_worker
        self.max_parallel_fuzzers = max_parallel_fuzzers
        self.vh_max_count = vh_max_count
        self.celery_job_id = celery_job_id
        # {fuzzer_name: [abs source path, ...]} from the task file, carried in the
        # assignment. Read directly from disk into an in-memory blob (cached) so the
        # many agents that need the harness source never hammer the Analysis Server.
        self.fuzzer_sources = fuzzer_sources or {}
        self._harness_source_cache: Optional[str] = None

        # Fuzzer binary path (from Analyzer or built locally)
        self.fuzzer_binary_path = (
            Path(fuzzer_binary_path) if fuzzer_binary_path else None
        )

        # Analysis Server client for code queries
        self.analysis_socket_path = analysis_socket_path
        self._analysis_client: Optional[AnalysisClient] = None
        self.index_path = index_path
        self._graph = None

        # FuzzerManager for Global Fuzzer + VH Fuzzer Pool
        self._fuzzer_manager: Optional[FuzzerManager] = None

        # WorkerContext for isolation (set during run())
        self._worker_context: Optional[WorkerContext] = None

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
            self.diff_path = self.run_workspace_path / "diff" / "ref.diff"

        # Paths
        self.results_path = self.workspace_path / "results"
        self.crashes_path = self.results_path / "crashes"
        self.pocs_path = self.results_path / "pocs"
        self.patches_path = self.results_path / "patches"

        # Ensure directories exist
        self.results_path.mkdir(parents=True, exist_ok=True)
        self.crashes_path.mkdir(parents=True, exist_ok=True)
        self.pocs_path.mkdir(parents=True, exist_ok=True)
        self.patches_path.mkdir(parents=True, exist_ok=True)

    @property
    def worker_id(self) -> str:
        """
        Get worker identifier.

        Returns ObjectId from WorkerContext if available (for isolation and MongoDB linking),
        otherwise returns descriptive string for logging during initialization.
        """
        if self._worker_context:
            return self._worker_context.worker_id
        return f"worker_{self.run_id}_{self.fuzzer}_{self.sanitizer}"

    @property
    def worker_display_name(self) -> str:
        """Get human-readable worker name for logging."""
        return f"worker_{self.run_id}_{self.fuzzer}_{self.sanitizer}"

    @property
    def fuzzer_manager(self) -> Optional[FuzzerManager]:
        """
        Get FuzzerManager (lazy initialization).

        Creates FuzzerManager on first access if enabled and fuzzer binary exists.
        """
        if self._fuzzer_manager is None and self.enable_fuzzer_worker:
            if self.fuzzer_binary_path and self.fuzzer_binary_path.exists():
                try:
                    vh_config = None
                    if self.vh_max_count:
                        from ..fuzzer.models import VHFuzzerConfig

                        vh_config = VHFuzzerConfig(max_count=int(self.vh_max_count))
                    self._fuzzer_manager = FuzzerManager(
                        run_id=self.run_id,
                        worker_id=self.worker_id,
                        fuzzer_path=self.fuzzer_binary_path,
                        docker_image=self.docker_image,
                        workspace_path=self.workspace_path,
                        fuzzer_name=self.fuzzer,
                        sanitizer=self.sanitizer,
                        vh_config=vh_config,
                        max_parallel_fuzzers=self.max_parallel_fuzzers,
                        # Note: crash_monitor is Run-level (in Dispatcher), not Worker-level
                    )
                    # Wire the worker-local monitor's crash callback so that
                    # crashes found by the Global / VH fuzzers get promoted to
                    # scored PoCs. Without this, monitor._handle_crash records
                    # the crash ([CRASH FOUND] Global) but on_crash is None, so
                    # the PoC is never created/activated and the fuzzer-found bug
                    # scores 0 -- only POCAgent create_poc crashes counted.
                    try:
                        _mon = getattr(self._fuzzer_manager, "crash_monitor", None)
                        if _mon is not None and getattr(_mon, "on_crash", None) is None:
                            _mon.on_crash = self._on_crash_found
                            logger.info(
                                f"[{self.worker_display_name}] Wired fuzzer crash callback "
                                f"(global/VH crashes now promote to PoCs)"
                            )
                    except Exception as _e:
                        logger.warning(
                            f"[{self.worker_display_name}] Could not wire crash callback: {_e}"
                        )
                    # Register for cross-module access using ObjectId
                    register_fuzzer_manager(self.worker_id, self._fuzzer_manager)
                    logger.info(
                        f"[{self.worker_display_name}] FuzzerManager initialized"
                    )
                except Exception as e:
                    logger.warning(
                        f"[{self.worker_display_name}] Failed to initialize FuzzerManager: {e}"
                    )
                    self._fuzzer_manager = None
            else:
                logger.debug(
                    f"[{self.worker_display_name}] FuzzerManager not initialized: no fuzzer binary"
                )
        return self._fuzzer_manager

    def _on_crash_found(self, crash_record) -> None:
        """
        Callback when FuzzerMonitor finds a new crash.

        The crash file IS the PoC - directly create PoC record.
        Flow: Create PoC (inactive) -> Generate Report -> Activate PoC

        Args:
            crash_record: CrashRecord from FuzzerMonitor
        """
        import asyncio
        import base64
        from pathlib import Path

        from ..core.models import POC
        from ..core.poc_packager import POCPackager

        logger.info(
            f"[{self.worker_display_name}] ╔══════════════════════════════════════════════════════════════╗"
        )
        logger.info(
            f"[{self.worker_display_name}] ║  🎯 CRASH FOUND BY FUZZER!                                   ║"
        )
        logger.info(
            f"[{self.worker_display_name}] ║  Hash: {crash_record.crash_hash[:16]:<44} ║"
        )
        logger.info(
            f"[{self.worker_display_name}] ║  Type: {(crash_record.vuln_type or 'unknown'):<44} ║"
        )
        logger.info(
            f"[{self.worker_display_name}] ╚══════════════════════════════════════════════════════════════╝"
        )

        try:
            # 1. Read crash file bytes
            crash_path = Path(crash_record.crash_path)
            if not crash_path.exists():
                logger.error(
                    f"[{self.worker_display_name}] Crash file not found: {crash_path}"
                )
                return

            crash_blob = crash_path.read_bytes()
            crash_blob_b64 = base64.b64encode(crash_blob).decode("utf-8")

            # 2. Create PoC record (is_successful=False - don't trigger dispatcher yet!)
            from ..core.utils import generate_id

            poc_id = generate_id()

            # Get run workspace for results
            results_dir = self.run_workspace_path / "results"
            pocs_dir = results_dir / "pocs"
            pocs_dir.mkdir(parents=True, exist_ok=True)

            # Copy crash file to pocs directory
            poc_blob_path = pocs_dir / f"crash_{crash_record.crash_hash[:16]}.bin"
            poc_blob_path.write_bytes(crash_blob)

            # Determine source from crash_record
            source = crash_record.source  # "global_fuzzer" | "vh_fuzzer"

            # Look up the POCAgent that triggered this VH Fuzzer
            agent_id = None
            if source == "vh_fuzzer" and crash_record.vh_id:
                try:
                    from ..db import get_database

                    db = get_database()
                    if db is not None:
                        from bson import ObjectId

                        agent_doc = db.agents.find_one(
                            {
                                "vh_id": crash_record.vh_id,
                                "run_id": ObjectId(self.run_id),
                                "agent_type": "POCAgent",
                            }
                        )
                        if agent_doc:
                            agent_id = str(agent_doc["_id"])
                            logger.info(
                                f"[{self.worker_display_name}] Linked VH Fuzzer PoC to POCAgent {agent_id[:8]}"
                            )
                except Exception as e:
                    logger.debug(
                        f"[{self.worker_display_name}] Failed to look up POCAgent for VH: {e}"
                    )

            poc = POC(
                poc_id=poc_id,
                run_id=self.run_id,
                vulnerability_hypothesis_id=crash_record.vh_id or "",  # VH ID if from VH Fuzzer
                generation_id=generate_id(),  # Unique generation ID
                source=source,  # Track PoC source
                source_worker_id=crash_record.worker_id,  # Track which worker found it
                agent_id=agent_id,  # POCAgent that initiated fuzzing (if VH Fuzzer)
                iteration=0,
                attempt=1,
                variant=1,
                blob=crash_blob_b64,
                blob_path=str(poc_blob_path),
                gen_blob=f"""# Fuzzer-discovered crash
# Source: {source}
# Hash: {crash_record.crash_hash}
# Type: {crash_record.vuln_type}
# Worker: {crash_record.worker_id}

import base64

# PoC blob (base64 encoded)
POC_BLOB_B64 = "{crash_blob_b64}"

def generate(variant: int = 1) -> bytes:
    return base64.b64decode(POC_BLOB_B64)
""",
                vuln_type=crash_record.vuln_type,
                harness_name=self.fuzzer,
                sanitizer=self.sanitizer,
                sanitizer_output=crash_record.sanitizer_output[:10000]
                if crash_record.sanitizer_output
                else "",
                description=f"Fuzzer-discovered crash ({source})",
                # The monitor already deduplicated this crash and computed its
                # signature; carrying it onto the PoC is what lets the PoC count
                # be a count of bugs (one signature = one bug) across workers.
                # Without it every fuzzer-found crash reached the DB unsigned.
                signature=crash_record.signature,
                is_successful=False,  # NOT yet! Generate report first
                is_active=True,
                verified_at=None,  # Not verified yet
            )

            # Save PoC to database (inactive)
            self.repos.pocs.save(poc)
            logger.info(
                f"[{self.worker_display_name}] PoC {poc_id[:8]} created (pending report)"
            )

            # 3. Package PoC with report, then activate
            packager = POCPackager(
                str(results_dir),
                run_id=self.run_id,
                worker_id=self.worker_id,
                repos=self.repos,
                analyzer_socket_path=self.analysis_socket_path,
            )

            # Schedule: package -> activate (called from async context)
            try:
                loop = asyncio.get_running_loop()
                asyncio.create_task(
                    self._package_and_activate_poc(packager, poc, poc_id)
                )
            except RuntimeError:
                # No running loop - run synchronously
                self._package_and_activate_poc_sync(packager, poc, poc_id)

        except Exception as e:
            logger.error(f"[{self.worker_display_name}] Error processing crash: {e}")
            import traceback

            logger.debug(traceback.format_exc())

    async def _package_and_activate_poc(self, packager, poc, poc_id: str) -> None:
        """
        Async: Package PoC with report, then activate it.

        Flow: Generate Report -> Package -> Activate (is_successful=True)

        Args:
            packager: POCPackager instance
            poc: PoC object
            poc_id: PoC ID for logging
        """
        try:
            # 1. Package PoC with report
            logger.info(
                f"[{self.worker_display_name}] Generating report for PoC {poc_id[:8]}..."
            )
            if not extract_class(poc.sanitizer_output or ""):
                logger.warning(
                    f"[{self.worker_display_name}] PoC {poc_id[:8]} NOT activated: "
                    f"no real fault class (sanitizer/fatal-signal) in its output -- "
                    f"a plain exit() is not a memory-safety finding"
                )
                return

            zip_path = await packager.package_poc_async(poc.to_dict(), None)

            if zip_path:
                logger.info(
                    f"[{self.worker_display_name}] ✅ PoC {poc_id[:8]} packaged: {zip_path}"
                )

                # 2. Activate PoC (now dispatcher will detect it)
                self.repos.pocs.update(poc_id, {"is_successful": True})
                self.repos.runs.add_poc(self.run_id, poc_id)
                logger.info(
                    f"[{self.worker_display_name}] ✅ PoC {poc_id[:8]} activated!"
                )
            else:
                logger.warning(
                    f"[{self.worker_display_name}] Failed to package PoC {poc_id[:8]}"
                )

        except Exception as e:
            logger.error(
                f"[{self.worker_display_name}] Error packaging PoC {poc_id[:8]}: {e}"
            )
            import traceback

            logger.debug(traceback.format_exc())

    def _package_and_activate_poc_sync(self, packager, poc, poc_id: str) -> None:
        """
        Sync: Package PoC with report, then activate it.

        Args:
            packager: POCPackager instance
            poc: PoC object
            poc_id: PoC ID for logging
        """
        try:
            # 1. Package PoC with report
            logger.info(
                f"[{self.worker_display_name}] Generating report for PoC {poc_id[:8]}..."
            )
            if not extract_class(poc.sanitizer_output or ""):
                logger.warning(
                    f"[{self.worker_display_name}] PoC {poc_id[:8]} NOT activated: "
                    f"no real fault class (sanitizer/fatal-signal) in its output -- "
                    f"a plain exit() is not a memory-safety finding"
                )
                return

            zip_path = packager.package_poc(poc.to_dict(), None)

            if zip_path:
                logger.info(
                    f"[{self.worker_display_name}] ✅ PoC {poc_id[:8]} packaged: {zip_path}"
                )

                # 2. Activate PoC (now dispatcher will detect it)
                self.repos.pocs.update(poc_id, {"is_successful": True})
                self.repos.runs.add_poc(self.run_id, poc_id)
                logger.info(
                    f"[{self.worker_display_name}] ✅ PoC {poc_id[:8]} activated!"
                )
            else:
                logger.warning(
                    f"[{self.worker_display_name}] Failed to package PoC {poc_id[:8]}"
                )

        except Exception as e:
            logger.error(
                f"[{self.worker_display_name}] Error packaging PoC {poc_id[:8]}: {e}"
            )
            import traceback

            logger.debug(traceback.format_exc())

    @property
    def graph(self):
        """The run's function index, opened in this process on first use."""
        if self._graph is None:
            from ..graph import CallGraph

            if not self.index_path:
                raise RuntimeError("the worker was dispatched without an index_path")
            self._graph = CallGraph(self.index_path)
        return self._graph

    @property
    def graph_harness(self) -> Optional[str]:
        """This worker's harness if the graph has reachability for it."""
        return self.fuzzer if self.fuzzer in self.graph.harnesses else None

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
                    harness=self.fuzzer,
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

    def harness_source(self) -> str:
        """Full harness/fuzzer source for this worker's fuzzer, as one text blob.

        Read once from the absolute paths in fuzzer_sources (from the task file)
        and cached in memory — every agent/prompt that needs the harness reads
        this, so we never round-trip the Analysis Server for it. Format is, per
        file, the basename (no path) then its full contents, blocks joined by a
        `----` line. Empty string if no sources are configured/readable.
        """
        if self._harness_source_cache is not None:
            return self._harness_source_cache
        self._harness_source_cache = build_harness_source_blob(
            self.fuzzer_sources.get(self.fuzzer)
        )
        return self._harness_source_cache

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

        Only shuts down VH Fuzzers; Global Fuzzer and FuzzerMonitor continue
        running until FuzzingBrain ends (timeout/budget/poc_target/manual).
        """
        if self._analysis_client:
            self._analysis_client.close()
            self._analysis_client = None

        # Only shutdown VH Fuzzers, keep Global Fuzzer running
        # Global Fuzzer will be shut down by Dispatcher when run truly ends
        if self._fuzzer_manager:
            import asyncio

            try:
                # Run VH fuzzer shutdown in event loop
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self._fuzzer_manager.shutdown_vh_fuzzers_only())
                else:
                    loop.run_until_complete(
                        self._fuzzer_manager.shutdown_vh_fuzzers_only()
                    )
            except Exception as e:
                logger.warning(
                    f"[{self.worker_display_name}] Error shutting down VH fuzzers: {e}"
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
            POCDeltaStrategy,
            POCFullscanStrategy,
            PatchStrategy,
            HarnessStrategy,
        )

        if self.task_type in ["poc", "poc-patch"]:
            # Select PoC strategy based on scan mode
            if self.scan_mode == "delta":
                return POCDeltaStrategy(self)
            else:
                return POCFullscanStrategy(self)
        elif self.task_type == "patch":
            return PatchStrategy(self)
        elif self.task_type == "harness":
            return HarnessStrategy(self)
        else:
            raise ValueError(f"Unknown job type: {self.task_type}")

    def _start_global_fuzzer_early(self) -> None:
        """Start the global fuzzer as soon as the worker has a binary.

        Best-effort: a failure here costs the background fuzzing, not the run,
        so it is logged and stepped over. Strategies still call
        ``start_global_fuzzer`` themselves and it returns False when one is
        already running, so nothing double-starts.
        """
        import asyncio

        manager = self.fuzzer_manager
        if not manager:
            return
        if manager.global_fuzzer:
            return
        try:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            if loop.run_until_complete(manager.start_global_fuzzer()):
                logger.info(
                    f"[{self.worker_display_name}] Global fuzzer started at "
                    f"worker start; seeds will join its corpus as they arrive"
                )
        except Exception as e:
            logger.warning(
                f"[{self.worker_display_name}] Could not start global fuzzer "
                f"early, leaving it to the strategy: {e}"
            )

    def run(self) -> Dict[str, Any]:
        """
        Run the worker execution pipeline.

        Selects and executes the appropriate strategy based on task_type.
        Uses WorkerContext for proper isolation and MongoDB linking.

        Hierarchy:
            Run (ObjectId)
            └── Worker (ObjectId) ← WorkerContext provides this
                └── Agent (ObjectId) ← AgentContext provides this

        Returns:
            Result dictionary with findings
        """
        logger.info(
            f"Starting executor: {self.fuzzer} with {self.sanitizer} (mode: {self.scan_mode}, job: {self.task_type})"
        )

        # Create WorkerContext for isolation
        # This creates the Worker record in MongoDB with unique ObjectId
        with WorkerContext(
            run_id=self.run_id,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            scan_mode=self.scan_mode,
            project_name=self.project_name,
            task_type=self.task_type,
            workspace_path=str(self.workspace_path),
            celery_job_id=self.celery_job_id,
        ) as ctx:
            self._worker_context = ctx

            logger.info(
                f"[{self.worker_display_name}] Worker context created: {ctx.worker_id}"
            )

            # The global fuzzer needs the binary and nothing else -- not seeds,
            # not vulnerability hypotheses, not a diff. Starting it here rather than
            # from inside a strategy means it is fuzzing while the agents are
            # still reading code, and the strategies' seeds land in its corpus
            # as they are produced (add_seed writes into the live corpus dir and
            # libFuzzer picks new files up within seconds).
            #
            # It used to start from the delta strategy's seed step, which gave
            # up early when there was no function index -- so a run without one
            # fuzzed for eight minutes out of thirty.
            self._start_global_fuzzer_early()

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
                result["worker_id"] = ctx.worker_id  # Include ObjectId in result

                # Map strategy-specific fields to common result fields
                if "poc_generated" in result:
                    ctx.poc_generated = result["poc_generated"]
                elif "pocs_generated" in result:
                    result["poc_generated"] = result["pocs_generated"]
                    ctx.poc_generated = result["pocs_generated"]
                if "patches_verified" in result:
                    result["patch_generated"] = result["patches_verified"]
                    ctx.patch_generated = result["patches_verified"]

                # Update context statistics
                ctx.result_summary = result

                return result

            except Exception as e:
                logger.exception(f"Executor failed: {e}")
                raise

        # Context exits here, automatically persisting to MongoDB
