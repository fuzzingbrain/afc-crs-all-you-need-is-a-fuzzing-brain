# SPDX-License-Identifier: Apache-2.0
"""
Worker Executor

Dispatches work to the appropriate strategy based on job type.
This is the main entry point for worker logic.
"""

from pathlib import Path
from typing import Dict, Any, Optional

from ..core import logger
from ..analyzer import AnalysisClient
from ..core.config import DEFAULT_MAX_PARALLEL_FUZZERS
from ..fuzzer import (
    FuzzerManager,
    register_fuzzer_manager,
)
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
        run_id: str,
        worker_id: str,
        harness_id: str,
        scan_mode: str = "full",
        fuzzer_binary_path: str = None,
        analysis_socket_path: str = None,
        index_path: Optional[str] = None,
        diff_path: str = None,
        log_dir: str = None,
        docker_image: str = "",
        enable_fuzzer_worker: bool = True,
        run_workspace_path: str = None,
        max_parallel_fuzzers: int = DEFAULT_MAX_PARALLEL_FUZZERS,
        vh_max_count: Optional[int] = None,
        fuzzer_sources: Optional[dict] = None,
        fuzzer_worker: Optional[dict] = None,
    ):
        """
        Initialize WorkerExecutor.

        Args:
            workspace_path: Path to worker workspace
            project_name: Project name
            fuzzer: Fuzzer name
            sanitizer: Sanitizer (address, memory, undefined)
            task_type: Job type (poc, patch, poc-patch, harness)
            run_id: Parent run ID
            worker_id: this worker's row (inserted by the dispatcher)
            harness_id: the harness row it works on
            scan_mode: Scan mode ("full" or "delta")
            fuzzer_binary_path: Path to pre-built fuzzer binary (from Analyzer)
            analysis_socket_path: Path to Analysis Server socket for code queries
            index_path: The run's function index / call graph file
            diff_path: Path to diff file (required for delta mode)
            log_dir: Main run log directory for agent logs
            docker_image: Docker image for running fuzzers
            enable_fuzzer_worker: Whether to enable FuzzerManager (default True)
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
        self.run_id = str(run_id)
        self._worker_id = str(worker_id)
        self.harness_id = str(harness_id)
        self.scan_mode = scan_mode
        self.log_dir = Path(log_dir) if log_dir else None
        self.docker_image = docker_image
        # fuzzer_worker from the task file (FuzzerWorkerConfig as a dict)
        self.fuzzer_worker = dict(fuzzer_worker or {})
        self.enable_fuzzer_worker = enable_fuzzer_worker and self.fuzzer_worker.get("enabled", True)
        self.max_parallel_fuzzers = max_parallel_fuzzers
        self.vh_max_count = vh_max_count
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
        return self._worker_id

    @property
    def worker_display_name(self) -> str:
        """Get human-readable worker name for logging."""
        return f"{self.fuzzer}/{self._worker_id[:8]}"

    @property
    def fuzzer_manager(self) -> Optional[FuzzerManager]:
        """
        Get FuzzerManager (lazy initialization).

        Creates FuzzerManager on first access if enabled and fuzzer binary exists.
        """
        if self._fuzzer_manager is None and self.enable_fuzzer_worker:
            if self.fuzzer_binary_path and self.fuzzer_binary_path.exists():
                try:
                    from ..fuzzer.models import GlobalFuzzerConfig, VHFuzzerConfig
                    fw = self.fuzzer_worker
                    g, v = GlobalFuzzerConfig(), VHFuzzerConfig()
                    global_config = GlobalFuzzerConfig(
                        fork_level=int(fw.get("global_fork_level", g.fork_level)),
                        rss_limit_mb=int(fw.get("global_rss_limit_mb", g.rss_limit_mb)),
                        max_time=int(fw.get("global_max_time", g.max_time)),
                        timeout_per_input=int(fw.get("global_timeout_per_input", g.timeout_per_input)),
                    )
                    vh_config = VHFuzzerConfig(
                        fork_level=int(fw.get("vh_fork_level", v.fork_level)),
                        rss_limit_mb=int(fw.get("vh_rss_limit_mb", v.rss_limit_mb)),
                        max_count=int(self.vh_max_count or fw.get("vh_max_count", v.max_count)),
                    )
                    self._fuzzer_manager = FuzzerManager(
                        run_id=self.run_id,
                        worker_id=self.worker_id,
                        fuzzer_path=self.fuzzer_binary_path,
                        docker_image=self.docker_image,
                        workspace_path=self.workspace_path,
                        fuzzer_name=self.fuzzer,
                        sanitizer=self.sanitizer,
                        global_config=global_config,
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
                        if _mon is not None:
                            _mon.check_interval = float(fw.get("crash_check_interval", 5.0))
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
                    # Register for cross-module access, by worker id
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
        """A fuzzer (global or VH) found a crashing input.

        It becomes a poc_attempt (source global_fuzzer or vh_fuzzer) that
        crashed; record_crash gives it its signature and says whether the run
        has seen that bug. A new one is reported and packaged.
        """
        from ..core.crashes import package_crash, record_crash
        from ..db.store import get_store

        source = crash_record.source  # "global_fuzzer" | "vh_fuzzer"
        try:
            blob = Path(crash_record.crash_path).read_bytes()
        except OSError as e:
            logger.error(f"[{self.worker_display_name}] crash file unreadable: {e}")
            return

        store = get_store()
        vh_id = None
        if source == "vh_fuzzer":
            vh = store.find_vh_by_prefix(self.worker_id, crash_record.vh_id or "")
            if vh is None:
                logger.error(
                    f"[{self.worker_display_name}] VH fuzzer crash for unknown VH "
                    f"{crash_record.vh_id!r}; recorded as the global fuzzer's"
                )
                source = "global_fuzzer"
            else:
                vh_id = vh.id
        try:
            attempt_id = store.add_poc_attempt(
                self.run_id,
                source,
                self.harness_id,
                crash_record.sanitizer or self.sanitizer,
                blob,
                vh_id=vh_id,
                worker_id=self.worker_id if source == "vh_fuzzer" else None,
            )
            result = record_crash(
                attempt_id,
                crash_record.sanitizer_output or "",
                self.fuzzer,
                blob,
                vuln_type=crash_record.vuln_type,
            )
        except Exception as e:
            logger.exception(f"[{self.worker_display_name}] could not record the crash: {e}")
            return

        if not result.is_new:
            logger.info(
                f"[{self.worker_display_name}] {source} crash is a known bug "
                f"({result.describe}, crash {result.crash_id[:8]})"
            )
            return
        logger.info(
            f"[{self.worker_display_name}] NEW crash from {source}: {result.describe} "
            f"(crash {result.crash_id[:8]})"
        )
        results_dir = str(self.run_workspace_path / "results")
        # The monitor calls this from its own thread: the report agent runs
        # in its own event loop there, off the strategy's.
        package_crash(result.crash_id, results_dir, self.analysis_socket_path)

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
        The worker row goes running -> completed / error in WorkerContext.

        Returns:
            Result dictionary with findings
        """
        logger.info(
            f"Starting executor: {self.fuzzer} with {self.sanitizer} (mode: {self.scan_mode}, job: {self.task_type})"
        )

        with WorkerContext(
            run_id=self.run_id,
            worker_id=self.worker_id,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
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
                result["worker_id"] = ctx.worker_id

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

