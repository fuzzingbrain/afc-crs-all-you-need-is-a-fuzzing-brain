"""
Crash Monitor

Background monitoring of all fuzzer crash directories.
Handles deduplication, verification, and reporting.
"""

import asyncio
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from loguru import logger

from .models import CrashRecord


@dataclass
class WatchEntry:
    """Entry for a watched crash directory."""

    path: Path
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


class CrashMonitor:
    """
    Crash Monitor.

    Responsibilities:
    - Monitor all fuzzer crash directories
    - Deduplicate crashes (based on hash)
    - Verify crashes
    - Report to database/callbacks
    """

    def __init__(
        self,
        task_id: str,
        check_interval: float = 5.0,
        dedupe_enabled: bool = True,
        on_crash: Optional[Callable[[CrashRecord], None]] = None,
    ):
        """
        Initialize CrashMonitor.

        Args:
            task_id: Parent task ID
            check_interval: Seconds between directory checks
            dedupe_enabled: Whether to deduplicate crashes
            on_crash: Callback when new crash is found
        """
        self.task_id = task_id
        self.check_interval = check_interval
        self.dedupe_enabled = dedupe_enabled
        self.on_crash = on_crash

        # Known crashes for deduplication
        self.known_crashes: Set[str] = set()

        # Watched directories
        self.watch_dirs: List[WatchEntry] = []

        # Background task
        self._monitor_task: Optional[asyncio.Task] = None
        self._running = False

        # Crash records
        self.crash_records: List[CrashRecord] = []

        # Verification context (set by manager)
        self.fuzzer_path: Optional[Path] = None
        self.docker_image: Optional[str] = None

        logger.debug(f"[CrashMonitor:{task_id}] Initialized")

    def add_watch_dir(
        self,
        crash_dir: Path,
        source: str,
        fuzzer_name: str = "",
        sanitizer: str = "address",
    ) -> None:
        """
        Add a directory to monitor for crashes.

        Args:
            crash_dir: Path to crash directory
            source: Source identifier ("global" or sp_id)
            fuzzer_name: Fuzzer binary name
            sanitizer: Sanitizer type
        """
        entry = WatchEntry(
            path=Path(crash_dir),
            source=source,
            fuzzer_name=fuzzer_name,
            sanitizer=sanitizer,
        )
        self.watch_dirs.append(entry)
        logger.debug(
            f"[CrashMonitor:{self.task_id}] Added watch: {crash_dir} ({source})"
        )

    def remove_watch_dir(self, source: str) -> None:
        """
        Remove a watched directory by source.

        Args:
            source: Source identifier to remove
        """
        self.watch_dirs = [w for w in self.watch_dirs if w.source != source]
        logger.debug(f"[CrashMonitor:{self.task_id}] Removed watch: {source}")

    async def start_monitoring(self) -> None:
        """Start background monitoring coroutine."""
        if self._running:
            return

        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info(f"[CrashMonitor:{self.task_id}] Started monitoring")

    async def stop_monitoring(self) -> None:
        """Stop background monitoring."""
        self._running = False

        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

        # Final sweep: check all directories one last time before stopping
        # This ensures we don't miss crashes that appeared right before shutdown
        logger.debug(f"[CrashMonitor:{self.task_id}] Running final sweep...")
        for watch_entry in self.watch_dirs:
            try:
                await self._check_directory(watch_entry)
            except Exception as e:
                logger.warning(
                    f"[CrashMonitor:{self.task_id}] Final sweep error for {watch_entry.path}: {e}"
                )

        logger.info(
            f"[CrashMonitor:{self.task_id}] Stopped monitoring (found {len(self.crash_records)} total crashes)"
        )

    async def _monitor_loop(self) -> None:
        """Background monitoring loop."""
        while self._running:
            try:
                # Check all watched directories
                for watch_entry in self.watch_dirs:
                    await self._check_directory(watch_entry)

                # Wait before next check
                await asyncio.sleep(self.check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[CrashMonitor:{self.task_id}] Monitor loop error: {e}")
                await asyncio.sleep(self.check_interval)

    async def _check_directory(self, watch_entry: WatchEntry) -> None:
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

            # Compute hash for deduplication
            crash_data = crash_file.read_bytes()
            crash_hash = CrashRecord.compute_hash(crash_data)

            # Skip if already known
            if self.dedupe_enabled and crash_hash in self.known_crashes:
                continue

            # New crash found
            self.known_crashes.add(crash_hash)
            await self._handle_crash(crash_file, watch_entry, crash_data, crash_hash)

    async def _handle_crash(
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
            f"[CrashMonitor:{self.task_id}] New crash: {crash_path.name} "
            f"(source={watch_entry.source})"
        )

        # Verify crash and get sanitizer output
        vuln_type = None
        sanitizer_output = ""

        if self.fuzzer_path and self.docker_image:
            verify_result = await self._verify_crash(
                crash_data,
                watch_entry.fuzzer_name,
                watch_entry.sanitizer,
            )
            vuln_type = verify_result.get("vuln_type")
            sanitizer_output = verify_result.get("output", "")

        # Create crash record
        record = CrashRecord(
            task_id=self.task_id,
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

        self.crash_records.append(record)

        # Notify callback
        if self.on_crash:
            try:
                self.on_crash(record)
            except Exception as e:
                logger.error(f"[CrashMonitor:{self.task_id}] Callback error: {e}")

        logger.info(
            f"[CrashMonitor:{self.task_id}] Crash recorded: {record.crash_id[:8]} "
            f"vuln_type={vuln_type}"
        )

        return record

    async def _verify_crash(
        self,
        crash_data: bytes,
        fuzzer_name: str,
        sanitizer: str,
    ) -> Dict[str, Any]:
        """
        Verify a crash by re-running with sanitizer.

        Args:
            crash_data: Raw crash data
            fuzzer_name: Fuzzer binary name
            sanitizer: Sanitizer type

        Returns:
            Dict with vuln_type and output
        """
        if not self.fuzzer_path or not self.docker_image:
            return {"vuln_type": None, "output": ""}

        fuzzer_dir = self.fuzzer_path.parent
        fuzzer_binary = self.fuzzer_path.name

        # Create work directory under fuzzer_dir (Docker can access this)
        work_dir = fuzzer_dir / "crash_verify"
        work_dir.mkdir(parents=True, exist_ok=True)

        # Write crash to work directory
        import hashlib

        crash_hash = hashlib.sha1(crash_data).hexdigest()[:16]
        temp_blob = work_dir / f"crash_{crash_hash}.bin"
        temp_blob.write_bytes(crash_data)

        try:
            # Build Docker command
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
                self.docker_image,
                f"/fuzzers/{fuzzer_binary}",
                "-timeout=30",
                f"/work/{temp_blob.name}",
            ]

            logger.debug(f"[CrashMonitor:{self.task_id}] Verifying: {' '.join(cmd)}")

            # Run verification
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            combined_output = result.stderr + "\n" + result.stdout

            # Check for crash and parse type
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
        finally:
            if temp_blob.exists():
                temp_blob.unlink()

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
        return crash_hash in self.known_crashes

    def get_crash_count(self) -> int:
        """Get total number of unique crashes found."""
        return len(self.crash_records)

    def get_crashes_by_source(self, source: str) -> List[CrashRecord]:
        """
        Get crashes from a specific source.

        Args:
            source: "global" or sp_id

        Returns:
            List of crash records
        """
        expected_source = "global_fuzzer" if source == "global" else "sp_fuzzer"
        return [
            r
            for r in self.crash_records
            if r.source == expected_source and (source == "global" or r.sp_id == source)
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        by_source = {}
        by_vuln_type = {}

        for record in self.crash_records:
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
            "by_source": by_source,
            "by_vuln_type": by_vuln_type,
            "is_running": self._running,
        }
