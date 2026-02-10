"""
Crash Monitor

Task-level background monitoring of all fuzzer crash directories.
Uses threading for independent execution (not affected by asyncio event loop lifecycle).

Handles deduplication, verification, and reporting.

Maintains its own log file (fuzzer_monitor.log) for real-time tracking of:
- Fuzzer start/stop events
- Crash discoveries
"""

import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from loguru import logger

from .models import CrashRecord


@dataclass
class ActiveFuzzerInfo:
    """Information about an active fuzzer."""

    worker_id: str
    source: str  # "global" or sp_id
    fuzzer_name: str
    sanitizer: str
    crash_dir: Path
    started_at: datetime = field(default_factory=datetime.now)


@dataclass
class WatchEntry:
    """Entry for a watched crash directory."""

    path: Path
    worker_id: str  # Worker that owns this directory
    source: str  # "global" or sp_id
    fuzzer_name: str
    sanitizer: str


# Crash indicators from sanitizers
CRASH_INDICATORS = [
    "ERROR: AddressSanitizer:",
    "ERROR: MemorySanitizer:",
    "WARNING: MemorySanitizer:",
    "ERROR: ThreadSanitizer:",
    "WARNING: ThreadSanitizer:",
    "ERROR: UndefinedBehaviorSanitizer:",
    "ERROR: HWAddressSanitizer:",
    "SEGV on unknown address",
    "Segmentation fault",
    "runtime error:",
    "AddressSanitizer: heap-buffer-overflow",
    "AddressSanitizer: heap-use-after-free",
    "AddressSanitizer: stack-buffer-overflow",
    "AddressSanitizer: stack-use-after-return",
    "AddressSanitizer: global-buffer-overflow",
    "AddressSanitizer: use-after-poison",
    "UndefinedBehaviorSanitizer: undefined-behavior",
    "AddressSanitizer:DEADLYSIGNAL",
    "assertion failed",
]

# Patterns to extract vulnerability type
VULN_TYPE_PATTERNS = [
    (r"AddressSanitizer: ([\w-]+)", 1),
    (r"MemorySanitizer: ([\w-]+)", 1),
    (r"UndefinedBehaviorSanitizer: ([\w-]+)", 1),
    (r"ThreadSanitizer: ([\w-]+)", 1),
    (r"HWAddressSanitizer: ([\w-]+)", 1),
    (r"runtime error: ([\w\s-]+)", 1),
]


class FuzzerMonitor:
    """
    Task-level Crash Monitor.

    Runs as a background thread to monitor crash directories from all workers.
    Thread-based design ensures monitoring continues regardless of asyncio event loop state.

    Supports two modes:
    1. Manual registration: Workers call add_watch_dir() to register directories
    2. Auto-discovery: Monitor scans workspace for crash directories with .active marker

    Responsibilities:
    - Monitor all fuzzer crash directories (Global + SP Fuzzers from all Workers)
    - Deduplicate crashes (based on hash)
    - Verify crashes
    - Report to callbacks
    """

    # Marker file indicating a fuzzer is actively running
    ACTIVE_MARKER = ".active"

    def __init__(
        self,
        task_id: str,
        workspace_path: Optional[Path] = None,
        check_interval: float = 5.0,
        dedupe_enabled: bool = True,
        on_crash: Optional[Callable[[CrashRecord], None]] = None,
        auto_discover: bool = False,
        docker_image: Optional[str] = None,
        log_dir: Optional[Path] = None,
        repos: Any = None,
    ):
        """
        Initialize FuzzerMonitor.

        Args:
            task_id: Parent task ID
            workspace_path: Task workspace path (required for auto-discovery)
            check_interval: Seconds between directory checks
            dedupe_enabled: Whether to deduplicate crashes
            on_crash: Callback when new crash is found (must be thread-safe)
            auto_discover: If True, automatically discover crash directories
            docker_image: Docker image for crash verification
            log_dir: Directory for fuzzer_monitor.log (defaults to workspace_path)
            repos: RepositoryManager for querying Worker info (optional)
        """
        self.task_id = task_id
        self.workspace_path = Path(workspace_path) if workspace_path else None
        self.check_interval = check_interval
        self.dedupe_enabled = dedupe_enabled
        self.on_crash = on_crash
        self.auto_discover = auto_discover
        self.docker_image = docker_image
        self.repos = repos

        # Cache for worker info (workspace_path -> (worker_id, fuzzer, sanitizer))
        self._worker_cache: Dict[str, tuple] = {}

        # Thread safety locks
        self._lock = threading.Lock()

        # Known crashes for deduplication
        self.known_crashes: Set[str] = set()

        # Watched directories (protected by _lock)
        # For auto-discover mode, this is rebuilt each scan
        self.watch_dirs: List[WatchEntry] = []

        # Background thread
        self._monitor_thread: Optional[threading.Thread] = None
        self._running = False

        # Crash records (protected by _lock)
        self.crash_records: List[CrashRecord] = []

        # Verification context (set per-worker via add_watch_dir)
        # Maps worker_id -> (fuzzer_path, docker_image)
        self._verification_context: Dict[str, tuple] = {}

        # Active fuzzer tracking for start/stop detection (auto-discover mode)
        # Key: "{worker_id}:{source}" -> ActiveFuzzerInfo
        self._active_fuzzers: Dict[str, ActiveFuzzerInfo] = {}

        # Dedicated Loguru logger for FuzzerMonitor
        self._monitor_logger = logger.bind(monitor=task_id)
        self._log_sink_id: Optional[int] = None
        self._log_path: Optional[Path] = None
        # Use log_dir if provided, otherwise fall back to workspace_path
        # New structure: fuzzer/monitor.log
        if log_dir:
            fuzzer_log_dir = Path(log_dir) / "fuzzer"
            fuzzer_log_dir.mkdir(parents=True, exist_ok=True)
            self._log_path = fuzzer_log_dir / "monitor.log"
        elif self.workspace_path:
            fuzzer_log_dir = self.workspace_path / "fuzzer"
            fuzzer_log_dir.mkdir(parents=True, exist_ok=True)
            self._log_path = fuzzer_log_dir / "monitor.log"

        logger.debug(
            f"[FuzzerMonitor:{task_id}] Initialized (thread-based, "
            f"auto_discover={auto_discover})"
        )

    def add_watch_dir(
        self,
        crash_dir: Path,
        worker_id: str,
        source: str,
        fuzzer_name: str = "",
        sanitizer: str = "address",
        fuzzer_path: Optional[Path] = None,
        docker_image: Optional[str] = None,
    ) -> None:
        """
        Add a directory to monitor for crashes.

        Thread-safe: can be called from any thread.

        Args:
            crash_dir: Path to crash directory
            worker_id: Worker identifier
            source: Source identifier ("global" or sp_id)
            fuzzer_name: Fuzzer binary name
            sanitizer: Sanitizer type
            fuzzer_path: Path to fuzzer binary (for verification)
            docker_image: Docker image (for verification)
        """
        entry = WatchEntry(
            path=Path(crash_dir),
            worker_id=worker_id,
            source=source,
            fuzzer_name=fuzzer_name,
            sanitizer=sanitizer,
        )

        with self._lock:
            self.watch_dirs.append(entry)
            # Store verification context for this worker
            if fuzzer_path and docker_image:
                self._verification_context[worker_id] = (fuzzer_path, docker_image)

        logger.debug(
            f"[FuzzerMonitor:{self.task_id}] Added watch: {crash_dir} "
            f"(worker={worker_id}, source={source})"
        )

    def remove_watch_dir(self, worker_id: str, source: str) -> None:
        """
        Remove a watched directory by worker_id and source.

        Thread-safe: can be called from any thread.

        Args:
            worker_id: Worker identifier
            source: Source identifier ("global" or sp_id)
        """
        with self._lock:
            self.watch_dirs = [
                w
                for w in self.watch_dirs
                if not (w.worker_id == worker_id and w.source == source)
            ]

        logger.debug(
            f"[FuzzerMonitor:{self.task_id}] Removed watch: worker={worker_id}, source={source}"
        )

    def remove_all_worker_watches(self, worker_id: str) -> None:
        """
        Remove all watched directories for a specific worker.

        Thread-safe: can be called from any thread.

        Args:
            worker_id: Worker identifier
        """
        with self._lock:
            self.watch_dirs = [w for w in self.watch_dirs if w.worker_id != worker_id]

        logger.debug(
            f"[FuzzerMonitor:{self.task_id}] Removed all watches for worker={worker_id}"
        )

    def start_monitoring(self) -> None:
        """
        Start background monitoring thread.

        Thread-safe: can be called from any thread.
        """
        if self._running:
            return

        # Add dedicated log file sink for FuzzerMonitor
        if self._log_path:
            try:
                # Filter to only log messages from this monitor
                def monitor_filter(record):
                    return record["extra"].get("monitor") == self.task_id

                self._log_sink_id = logger.add(
                    self._log_path,
                    format="{time:YYYY-MM-DD HH:mm:ss} | {level:<7} | {message}",
                    filter=monitor_filter,
                    level="INFO",
                    enqueue=True,  # Thread-safe
                )

                # Log startup info
                self._log("=" * 70)
                self._log("CRASH MONITOR STARTED")
                self._log(f"Task ID: {self.task_id}")
                self._log(f"Workspace: {self.workspace_path}")
                self._log(f"Auto-discover: {self.auto_discover}")
                self._log(f"Check interval: {self.check_interval}s")
                self._log("=" * 70)
            except Exception as e:
                logger.warning(
                    f"[FuzzerMonitor:{self.task_id}] Failed to setup log file: {e}"
                )
                self._log_sink_id = None

        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name=f"FuzzerMonitor-{self.task_id}",
            daemon=True,  # Auto-exit when main process exits
        )
        self._monitor_thread.start()
        logger.info(f"[FuzzerMonitor:{self.task_id}] Started monitoring thread")

    def _log(self, message: str, level: str = "INFO") -> None:
        """
        Log to the dedicated FuzzerMonitor log file.

        Args:
            message: Log message
            level: Log level (INFO, WARNING, ERROR, etc.)
        """
        log_func = getattr(
            self._monitor_logger, level.lower(), self._monitor_logger.info
        )
        log_func(message)

    def stop_monitoring(self) -> None:
        """
        Stop background monitoring.

        Thread-safe: can be called from any thread.
        Blocks until monitoring thread exits.
        """
        if not self._running:
            return

        self._running = False

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=10.0)
            if self._monitor_thread.is_alive():
                logger.warning(
                    f"[FuzzerMonitor:{self.task_id}] Monitor thread did not exit cleanly"
                )

        self._monitor_thread = None

        # Final sweep
        logger.debug(f"[FuzzerMonitor:{self.task_id}] Running final sweep...")
        with self._lock:
            entries_to_check = list(self.watch_dirs)

        for watch_entry in entries_to_check:
            try:
                self._check_directory(watch_entry)
            except Exception as e:
                logger.warning(
                    f"[FuzzerMonitor:{self.task_id}] Final sweep error for {watch_entry.path}: {e}"
                )

        # Log summary and close dedicated log file
        self._log("=" * 70)
        self._log("CRASH MONITOR STOPPED")
        self._log(f"Total crashes found: {len(self.crash_records)}")
        self._log(f"Unique crash hashes: {len(self.known_crashes)}")

        # Log per-worker stats
        stats = self.get_stats()
        if stats["by_worker"]:
            self._log("Crashes by worker:")
            for worker_id, count in stats["by_worker"].items():
                self._log(f"  {worker_id}: {count}")

        if stats["by_vuln_type"]:
            self._log("Crashes by vulnerability type:")
            for vuln_type, count in stats["by_vuln_type"].items():
                self._log(f"  {vuln_type}: {count}")

        self._log("=" * 70)

        # Remove the dedicated log sink
        if self._log_sink_id is not None:
            try:
                logger.remove(self._log_sink_id)
            except Exception:
                pass
            self._log_sink_id = None

        logger.info(
            f"[FuzzerMonitor:{self.task_id}] Stopped monitoring "
            f"(found {len(self.crash_records)} total crashes)"
        )

    def _monitor_loop(self) -> None:
        """Background monitoring loop (runs in separate thread)."""
        logger.debug(f"[FuzzerMonitor:{self.task_id}] Monitor loop started")

        while self._running:
            try:
                # Get directories to check
                if self.auto_discover and self.workspace_path:
                    # Auto-discover mode: scan for active crash directories
                    entries_to_check = self._discover_crash_directories()
                else:
                    # Manual mode: use registered directories
                    with self._lock:
                        entries_to_check = list(self.watch_dirs)

                # Check all watched directories
                for watch_entry in entries_to_check:
                    if not self._running:
                        break
                    try:
                        self._check_directory(watch_entry)
                    except Exception as e:
                        logger.error(
                            f"[FuzzerMonitor:{self.task_id}] Error checking {watch_entry.path}: {e}"
                        )

                # Wait before next check
                time.sleep(self.check_interval)

            except Exception as e:
                logger.error(f"[FuzzerMonitor:{self.task_id}] Monitor loop error: {e}")
                time.sleep(self.check_interval)

        logger.debug(f"[FuzzerMonitor:{self.task_id}] Monitor loop exited")

    def _discover_crash_directories(self) -> List[WatchEntry]:
        """
        Auto-discover crash directories in the workspace.

        Scans for:
        - Global Fuzzer: worker_workspace/*/fuzzer_worker/global/crashes/ (if .active exists)
        - SP Fuzzer: worker_workspace/*/fuzzer_worker/sp_fuzzers/*/crashes/ (if .active exists)

        Also tracks fuzzer start/stop events and logs them.

        Returns:
            List of WatchEntry for active crash directories
        """
        entries = []
        current_active_keys: Set[str] = set()

        if not self.workspace_path or not self.workspace_path.exists():
            # Check for stopped fuzzers
            self._check_stopped_fuzzers(current_active_keys)
            return entries

        worker_workspace = self.workspace_path / "worker_workspace"
        if not worker_workspace.exists():
            self._check_stopped_fuzzers(current_active_keys)
            return entries

        # Scan each worker directory
        for worker_dir in worker_workspace.iterdir():
            if not worker_dir.is_dir():
                continue

            # Get worker info from cache or database
            worker_dir_str = str(worker_dir)
            if worker_dir_str in self._worker_cache:
                worker_id, fuzzer_name, sanitizer = self._worker_cache[worker_dir_str]
            else:
                # Query database for worker with this workspace_path
                worker_id, fuzzer_name, sanitizer, from_db = self._get_worker_info(
                    worker_dir_str
                )
                # Only cache DB results; fallback may race with Worker record creation
                if from_db:
                    self._worker_cache[worker_dir_str] = (worker_id, fuzzer_name, sanitizer)

            fuzzer_worker_dir = worker_dir / "fuzzer_worker"
            if not fuzzer_worker_dir.exists():
                continue

            # Check Global Fuzzer crashes directory
            global_crashes = fuzzer_worker_dir / "global" / "crashes"
            global_active = fuzzer_worker_dir / "global" / self.ACTIVE_MARKER
            if global_crashes.exists() and global_active.exists():
                # Find fuzzer binary path for verification
                fuzzer_path = self._find_fuzzer_binary(
                    worker_dir, fuzzer_name, sanitizer
                )

                entry = WatchEntry(
                    path=global_crashes,
                    worker_id=worker_id,
                    source="global",
                    fuzzer_name=fuzzer_name,
                    sanitizer=sanitizer,
                )
                entries.append(entry)

                # Track this fuzzer and log if newly started
                fuzzer_key = f"{worker_id}:global"
                current_active_keys.add(fuzzer_key)
                self._check_fuzzer_started(fuzzer_key, entry, global_crashes)

                # Store verification context
                if fuzzer_path and self.docker_image:
                    with self._lock:
                        self._verification_context[worker_id] = (
                            fuzzer_path,
                            self.docker_image,
                        )

            # Check SP Fuzzer crashes directories
            sp_fuzzers_dir = fuzzer_worker_dir / "sp_fuzzers"
            if sp_fuzzers_dir.exists():
                for sp_dir in sp_fuzzers_dir.iterdir():
                    if not sp_dir.is_dir():
                        continue

                    sp_id = sp_dir.name
                    sp_crashes = sp_dir / "crashes"
                    sp_active = sp_dir / self.ACTIVE_MARKER

                    if sp_crashes.exists() and sp_active.exists():
                        entry = WatchEntry(
                            path=sp_crashes,
                            worker_id=worker_id,
                            source=sp_id,
                            fuzzer_name=fuzzer_name,
                            sanitizer=sanitizer,
                        )
                        entries.append(entry)

                        # Track this fuzzer and log if newly started
                        fuzzer_key = f"{worker_id}:{sp_id}"
                        current_active_keys.add(fuzzer_key)
                        self._check_fuzzer_started(fuzzer_key, entry, sp_crashes)

        # Check for stopped fuzzers
        self._check_stopped_fuzzers(current_active_keys)

        return entries

    def _get_worker_info(self, workspace_path: str) -> tuple:
        """
        Get worker info from database by workspace path.

        Args:
            workspace_path: Worker workspace path

        Returns:
            Tuple of (worker_id, fuzzer_name, sanitizer, from_db)
            from_db is True if the result came from MongoDB, False if fallback.
        """
        if self.repos:
            try:
                # Query worker by workspace_path
                worker = self.repos.workers.collection.find_one(
                    {"workspace_path": workspace_path}
                )
                if worker:
                    # Worker model stores _id (ObjectId), not worker_id
                    raw_id = worker.get("_id")
                    worker_id = str(raw_id) if raw_id else workspace_path
                    return (
                        worker_id,
                        worker.get("fuzzer", "unknown"),
                        worker.get("sanitizer", "address"),
                        True,
                    )
            except Exception as e:
                logger.debug(f"[FuzzerMonitor] Failed to query worker: {e}")

        # Fallback: parse from directory name (best effort)
        # NOT cached by caller — Worker record may not exist yet (race condition)
        dir_name = Path(workspace_path).name
        # Try to find sanitizer suffix
        for san in ["address", "memory", "undefined", "thread", "hwaddress"]:
            suffix = f"_{san}"
            if dir_name.endswith(suffix):
                prefix = dir_name[: -len(suffix)]
                # The prefix is {project}_{fuzzer}, but we can't reliably split
                # Just use the whole prefix as worker_id
                return (dir_name, prefix, san, False)

        # Last resort
        return (dir_name, dir_name, "address", False)

    def _check_fuzzer_started(
        self, fuzzer_key: str, entry: WatchEntry, crash_dir: Path
    ) -> None:
        """
        Check if a fuzzer just started and log it.

        Args:
            fuzzer_key: Unique key "{worker_id}:{source}"
            entry: WatchEntry for this fuzzer
            crash_dir: Path to crash directory
        """
        with self._lock:
            if fuzzer_key not in self._active_fuzzers:
                # New fuzzer started
                info = ActiveFuzzerInfo(
                    worker_id=entry.worker_id,
                    source=entry.source,
                    fuzzer_name=entry.fuzzer_name,
                    sanitizer=entry.sanitizer,
                    crash_dir=crash_dir,
                )
                self._active_fuzzers[fuzzer_key] = info

                # Log the start event
                fuzzer_type = (
                    "Global" if entry.source == "global" else f"SP({entry.source[:8]})"
                )
                self._log(
                    f"[FUZZER STARTED] {fuzzer_type} | "
                    f"worker={entry.worker_id} | "
                    f"fuzzer={entry.fuzzer_name} | "
                    f"sanitizer={entry.sanitizer} | "
                    f"path={crash_dir}"
                )

    def _check_stopped_fuzzers(self, current_active_keys: Set[str]) -> None:
        """
        Check for stopped fuzzers and log them.

        Args:
            current_active_keys: Set of currently active fuzzer keys
        """
        with self._lock:
            stopped_keys = set(self._active_fuzzers.keys()) - current_active_keys

            for fuzzer_key in stopped_keys:
                info = self._active_fuzzers.pop(fuzzer_key)
                runtime = (datetime.now() - info.started_at).total_seconds()

                # Log the stop event
                fuzzer_type = (
                    "Global" if info.source == "global" else f"SP({info.source[:8]})"
                )
                self._log(
                    f"[FUZZER STOPPED] {fuzzer_type} | "
                    f"worker={info.worker_id} | "
                    f"fuzzer={info.fuzzer_name} | "
                    f"sanitizer={info.sanitizer} | "
                    f"runtime={runtime:.1f}s"
                )

    def _find_fuzzer_binary(
        self, worker_dir: Path, fuzzer_name: str, sanitizer: str
    ) -> Optional[Path]:
        """
        Find the fuzzer binary path for a worker.

        Args:
            worker_dir: Worker directory
            fuzzer_name: Fuzzer name
            sanitizer: Sanitizer type

        Returns:
            Path to fuzzer binary, or None if not found
        """
        # Try fuzz-tooling build output
        fuzz_tooling = worker_dir / "fuzz-tooling" / "build" / "out"
        if fuzz_tooling.exists():
            # Look for sanitizer-specific directory
            for subdir in fuzz_tooling.iterdir():
                if sanitizer in subdir.name:
                    fuzzer_path = subdir / fuzzer_name
                    if fuzzer_path.exists():
                        return fuzzer_path

        return None

    def _check_directory(self, watch_entry: WatchEntry) -> None:
        """
        Check a single directory for new crashes.

        Args:
            watch_entry: Directory watch entry
        """
        crash_dir = watch_entry.path

        if not crash_dir.exists():
            return

        # Find crash files
        for crash_file in crash_dir.glob("crash-*"):
            if not crash_file.is_file():
                continue

            try:
                # Compute hash for deduplication
                crash_data = crash_file.read_bytes()
                crash_hash = CrashRecord.compute_hash(crash_data)

                # Skip if already known (thread-safe check)
                with self._lock:
                    if self.dedupe_enabled and crash_hash in self.known_crashes:
                        continue
                    self.known_crashes.add(crash_hash)

                # Handle new crash
                self._handle_crash(crash_file, watch_entry, crash_data, crash_hash)

            except Exception as e:
                logger.error(
                    f"[FuzzerMonitor:{self.task_id}] Error processing {crash_file}: {e}"
                )

    def _handle_crash(
        self,
        crash_path: Path,
        watch_entry: WatchEntry,
        crash_data: bytes,
        crash_hash: str,
    ) -> Optional[CrashRecord]:
        """
        Handle a newly discovered crash.

        Args:
            crash_path: Path to crash file
            watch_entry: Watch entry for source info
            crash_data: Raw crash data
            crash_hash: SHA1 hash of crash

        Returns:
            CrashRecord if successfully handled
        """
        logger.info(
            f"[FuzzerMonitor:{self.task_id}] New crash: {crash_path.name} "
            f"(worker={watch_entry.worker_id}, source={watch_entry.source})"
        )

        # Verify crash and get sanitizer output
        vuln_type = None
        sanitizer_output = ""

        # Get verification context for this worker
        with self._lock:
            verify_ctx = self._verification_context.get(watch_entry.worker_id)

        if verify_ctx:
            fuzzer_path, docker_image = verify_ctx
            verify_result = self._verify_crash(
                crash_path,
                fuzzer_path,
                docker_image,
                watch_entry.fuzzer_name,
                watch_entry.sanitizer,
            )
            vuln_type = verify_result.get("vuln_type")
            sanitizer_output = verify_result.get("output", "")

        # Create crash record
        record = CrashRecord(
            task_id=self.task_id,
            worker_id=watch_entry.worker_id,
            crash_path=str(crash_path),
            crash_hash=crash_hash,
            vuln_type=vuln_type,
            sanitizer_output=sanitizer_output[:10000],  # Truncate
            found_at=datetime.now(),
            source="global_fuzzer" if watch_entry.source == "global" else "sp_fuzzer",
            sp_id=watch_entry.source if watch_entry.source != "global" else None,
            fuzzer_name=watch_entry.fuzzer_name,
            sanitizer=watch_entry.sanitizer,
        )

        # Store record (thread-safe)
        with self._lock:
            self.crash_records.append(record)

        # Log crash to dedicated log file
        fuzzer_type = (
            "Global"
            if watch_entry.source == "global"
            else f"SP({watch_entry.source[:8]})"
        )
        self._log(
            f"[CRASH FOUND] {fuzzer_type} | "
            f"worker={watch_entry.worker_id} | "
            f"fuzzer={watch_entry.fuzzer_name} | "
            f"hash={crash_hash[:12]} | "
            f"vuln={vuln_type or 'unknown'} | "
            f"file={crash_path.name}"
        )

        # Notify callback
        if self.on_crash:
            try:
                self.on_crash(record)
            except Exception as e:
                logger.error(f"[FuzzerMonitor:{self.task_id}] Callback error: {e}")

        logger.info(
            f"[FuzzerMonitor:{self.task_id}] Crash recorded: {record.crash_id[:8]} "
            f"worker={watch_entry.worker_id[:16]}... vuln_type={vuln_type}"
        )

        return record

    def _verify_crash(
        self,
        crash_path: Path,
        fuzzer_path: Path,
        docker_image: str,
        fuzzer_name: str,
        sanitizer: str,
    ) -> Dict[str, Any]:
        """
        Verify a crash by re-running with sanitizer.

        Mounts the crash file's directory directly — no copying needed
        since crash files are already in the worker workspace.

        Args:
            crash_path: Path to crash file (in worker workspace)
            fuzzer_path: Path to fuzzer binary
            docker_image: Docker image to use
            fuzzer_name: Fuzzer binary name
            sanitizer: Sanitizer type

        Returns:
            Dict with vuln_type and output
        """
        FALLBACK_IMAGE = "gcr.io/oss-fuzz-base/base-runner"

        fuzzer_dir = fuzzer_path.parent
        fuzzer_binary = fuzzer_path.name
        work_dir = crash_path.parent

        def _run_with_image(image: str):
            cmd = [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--entrypoint",
                "",
                "-e",
                "FUZZING_ENGINE=libfuzzer",
                "-e",
                f"SANITIZER={sanitizer}",
                "-e",
                "ARCHITECTURE=x86_64",
                "-v",
                f"{fuzzer_dir}:/fuzzers:ro",
                "-v",
                f"{work_dir}:/work",
                image,
                f"/fuzzers/{fuzzer_binary}",
                "-timeout=30",
                f"/work/{crash_path.name}",
            ]

            logger.debug(f"[FuzzerMonitor:{self.task_id}] Verifying: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            return result.stderr + "\n" + result.stdout

        try:
            combined_output = _run_with_image(docker_image)

            # Fallback to base-runner on GLIBC / shared library errors
            if (
                "error while loading shared libraries" in combined_output
                or "GLIBC" in combined_output
            ) and docker_image != FALLBACK_IMAGE:
                logger.warning(
                    f"[FuzzerMonitor:{self.task_id}] Library error with {docker_image}, "
                    f"falling back to {FALLBACK_IMAGE}"
                )
                combined_output = _run_with_image(FALLBACK_IMAGE)

            crashed = self._check_crash(combined_output)
            vuln_type = self._parse_vuln_type(combined_output) if crashed else None

            return {
                "crashed": crashed,
                "vuln_type": vuln_type,
                "output": combined_output,
            }

        except subprocess.TimeoutExpired:
            return {"vuln_type": None, "output": "Verification timed out"}
        except Exception as e:
            return {"vuln_type": None, "output": f"Verification error: {e}"}

    def _check_crash(self, output: str) -> bool:
        """Check if output contains crash indicators."""
        output_lower = output.lower()
        for indicator in CRASH_INDICATORS:
            if indicator.lower() in output_lower:
                return True
        return False

    def _parse_vuln_type(self, output: str) -> Optional[str]:
        """Extract vulnerability type from sanitizer output."""
        for pattern, group in VULN_TYPE_PATTERNS:
            match = re.search(pattern, output)
            if match:
                return match.group(group).strip()

        # Fallback checks
        if "SEGV" in output or "Segmentation fault" in output:
            return "segmentation-fault"
        if "assertion failed" in output.lower():
            return "assertion-failure"

        return None

    def _is_duplicate(self, crash_hash: str) -> bool:
        """Check if crash hash is already known."""
        with self._lock:
            return crash_hash in self.known_crashes

    def get_crash_count(self) -> int:
        """Get total number of unique crashes found."""
        with self._lock:
            return len(self.crash_records)

    def get_crashes_by_worker(self, worker_id: str) -> List[CrashRecord]:
        """
        Get crashes from a specific worker.

        Args:
            worker_id: Worker identifier

        Returns:
            List of crash records
        """
        with self._lock:
            return [r for r in self.crash_records if r.worker_id == worker_id]

    def get_crashes_by_source(self, worker_id: str, source: str) -> List[CrashRecord]:
        """
        Get crashes from a specific source within a worker.

        Args:
            worker_id: Worker identifier
            source: "global" or sp_id

        Returns:
            List of crash records
        """
        with self._lock:
            expected_source = "global_fuzzer" if source == "global" else "sp_fuzzer"
            return [
                r
                for r in self.crash_records
                if r.worker_id == worker_id
                and r.source == expected_source
                and (source == "global" or r.sp_id == source)
            ]

    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        with self._lock:
            by_worker = {}
            by_source = {}
            by_vuln_type = {}

            for record in self.crash_records:
                # Count by worker
                worker = record.worker_id
                by_worker[worker] = by_worker.get(worker, 0) + 1

                # Count by source
                source = record.source
                by_source[source] = by_source.get(source, 0) + 1

                # Count by vuln type
                vtype = record.vuln_type or "unknown"
                by_vuln_type[vtype] = by_vuln_type.get(vtype, 0) + 1

            return {
                "total_crashes": len(self.crash_records),
                "unique_hashes": len(self.known_crashes),
                "watched_directories": len(self.watch_dirs),
                "by_worker": by_worker,
                "by_source": by_source,
                "by_vuln_type": by_vuln_type,
                "is_running": self._running,
            }

    def is_running(self) -> bool:
        """Check if monitor is currently running."""
        return (
            self._running
            and self._monitor_thread is not None
            and self._monitor_thread.is_alive()
        )
