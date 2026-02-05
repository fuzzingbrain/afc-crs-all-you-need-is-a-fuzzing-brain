"""
Fuzzer Manager

Top-level manager for all fuzzer instances within a worker.
Manages Global Fuzzer and SP Fuzzer Pool.
"""

import hashlib
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from loguru import logger

from .models import (
    CrashRecord,
    FuzzerType,
    GlobalFuzzerConfig,
    SPFuzzerConfig,
    SeedInfo,
)
from .instance import FuzzerInstance
from .monitor import CrashMonitor


class FuzzerManager:
    """
    Fuzzer Manager.

    Responsibilities:
    - Manage Global Fuzzer
    - Manage SP Fuzzer Pool
    - Unified crash monitoring and reporting
    - Seed routing (Direction/FP -> Global, POV blob -> SP)
    """

    def __init__(
        self,
        task_id: str,
        worker_id: str,
        fuzzer_path: Path,
        docker_image: str,
        workspace_path: Path,
        fuzzer_name: str = "",
        sanitizer: str = "address",
        global_config: Optional[GlobalFuzzerConfig] = None,
        sp_config: Optional[SPFuzzerConfig] = None,
        on_crash: Optional[Callable[[CrashRecord], None]] = None,
    ):
        """
        Initialize FuzzerManager.

        Args:
            task_id: Parent task ID
            worker_id: Worker identifier
            fuzzer_path: Path to fuzzer binary
            docker_image: Docker image for running fuzzers
            workspace_path: Worker workspace path
            fuzzer_name: Fuzzer binary name
            sanitizer: Sanitizer type
            global_config: Configuration for Global Fuzzer
            sp_config: Configuration for SP Fuzzers
            on_crash: Callback when crash is found
        """
        self.task_id = task_id
        self.worker_id = worker_id
        self.fuzzer_path = Path(fuzzer_path)
        self.docker_image = docker_image
        self.workspace_path = Path(workspace_path)
        self.fuzzer_name = fuzzer_name or self.fuzzer_path.name
        self.sanitizer = sanitizer

        # Configurations
        self.global_config = global_config or GlobalFuzzerConfig()
        self.sp_config = sp_config or SPFuzzerConfig()

        # Global Fuzzer
        self.global_fuzzer: Optional[FuzzerInstance] = None

        # SP Fuzzer Pool: sp_id -> FuzzerInstance
        self.sp_fuzzers: Dict[str, FuzzerInstance] = {}

        # Crash Monitor
        self.crash_monitor = CrashMonitor(
            task_id=task_id,
            on_crash=on_crash,
        )
        # Set verification context
        self.crash_monitor.fuzzer_path = self.fuzzer_path
        self.crash_monitor.docker_image = docker_image

        # Directories
        self.fuzzer_workspace = workspace_path / "fuzzer_worker"
        self.global_corpus_dir = self.fuzzer_workspace / "global" / "corpus"
        self.global_crashes_dir = self.fuzzer_workspace / "global" / "crashes"
        self.sp_base_dir = self.fuzzer_workspace / "sp_fuzzers"

        # Ensure directories exist
        self.global_corpus_dir.mkdir(parents=True, exist_ok=True)
        self.global_crashes_dir.mkdir(parents=True, exist_ok=True)
        self.sp_base_dir.mkdir(parents=True, exist_ok=True)

        # Seed tracking
        self.direction_seeds: List[SeedInfo] = []
        self.fp_seeds: List[SeedInfo] = []

        logger.info(
            f"[{worker_id}] ╔══════════════════════════════════════════════════════════════╗"
        )
        logger.info(
            f"[{worker_id}] ║              FUZZER WORKER INITIALIZED                       ║"
        )
        logger.info(
            f"[{worker_id}] ╠══════════════════════════════════════════════════════════════╣"
        )
        logger.info(f"[{worker_id}] ║  Fuzzer: {self.fuzzer_name:<50} ║")
        logger.info(f"[{worker_id}] ║  Sanitizer: {sanitizer:<47} ║")
        logger.info(
            f"[{worker_id}] ╚══════════════════════════════════════════════════════════════╝"
        )

    # =========================================================================
    # Global Fuzzer Management
    # =========================================================================

    async def start_global_fuzzer(self, initial_seeds: List[bytes] = None) -> bool:
        """
        Start the Global Fuzzer.

        Args:
            initial_seeds: Optional initial seeds to add to corpus

        Returns:
            True if started successfully
        """
        if self.global_fuzzer and self.global_fuzzer.is_running():
            logger.warning(
                f"[FuzzerManager:{self.worker_id}] Global fuzzer already running"
            )
            return False

        # Create instance
        self.global_fuzzer = FuzzerInstance(
            instance_id="global",
            fuzzer_path=self.fuzzer_path,
            docker_image=self.docker_image,
            corpus_dir=self.global_corpus_dir,
            crashes_dir=self.global_crashes_dir,
            fuzzer_type=FuzzerType.GLOBAL,
            config=self.global_config,
        )

        # Add initial seeds
        if initial_seeds:
            for i, seed in enumerate(initial_seeds):
                self.global_fuzzer.add_seed(seed, f"initial_{i:04d}")

        # Register crash directory for monitoring
        self.crash_monitor.add_watch_dir(
            crash_dir=self.global_crashes_dir,
            source="global",
            fuzzer_name=self.fuzzer_name,
            sanitizer=self.sanitizer,
        )

        # Start monitoring if not already running
        if not self.crash_monitor._running:
            await self.crash_monitor.start_monitoring()

        # Start fuzzer
        success = await self.global_fuzzer.start()
        if success:
            logger.info(
                f"[{self.worker_id}] ┌─────────────────────────────────────────┐"
            )
            logger.info(
                f"[{self.worker_id}] │  🚀 GLOBAL FUZZER STARTED (fork={self.global_config.fork_level})     │"
            )
            logger.info(
                f"[{self.worker_id}] └─────────────────────────────────────────┘"
            )
        else:
            logger.error(f"[{self.worker_id}] ❌ GLOBAL FUZZER FAILED TO START")

        return success

    async def stop_global_fuzzer(self) -> None:
        """Stop the Global Fuzzer."""
        if self.global_fuzzer:
            await self.global_fuzzer.stop()
            self.crash_monitor.remove_watch_dir("global")
            logger.info(f"[FuzzerManager:{self.worker_id}] Global fuzzer stopped")

    def add_direction_seed(self, seed: bytes, direction_id: str) -> Path:
        """
        Add a Direction seed to Global Fuzzer.

        Args:
            seed: Raw seed bytes
            direction_id: Direction ID that generated this seed

        Returns:
            Path to saved seed file
        """
        if not self.global_fuzzer:
            # Save to corpus dir even if fuzzer not started yet
            seed_hash = hashlib.sha1(seed).hexdigest()[:16]
            seed_path = (
                self.global_corpus_dir / f"direction_{direction_id[:8]}_{seed_hash}"
            )
            seed_path.write_bytes(seed)
        else:
            seed_path = self.global_fuzzer.add_seed(
                seed,
                f"direction_{direction_id[:8]}_{hashlib.sha1(seed).hexdigest()[:8]}",
            )

        # Track seed
        seed_info = SeedInfo(
            seed_path=str(seed_path),
            seed_hash=hashlib.sha1(seed).hexdigest(),
            seed_size=len(seed),
            source="direction",
            direction_id=direction_id,
        )
        self.direction_seeds.append(seed_info)

        logger.debug(
            f"[FuzzerManager:{self.worker_id}] Added direction seed: "
            f"direction={direction_id[:8]}, size={len(seed)}"
        )
        return seed_path

    def add_fp_seed(self, seed: bytes, sp_id: str) -> Path:
        """
        Add an FP (False Positive) seed to Global Fuzzer.

        Args:
            seed: Raw seed bytes
            sp_id: SP ID that was determined to be FP

        Returns:
            Path to saved seed file
        """
        if not self.global_fuzzer:
            seed_hash = hashlib.sha1(seed).hexdigest()[:16]
            seed_path = self.global_corpus_dir / f"fp_{sp_id[:8]}_{seed_hash}"
            seed_path.write_bytes(seed)
        else:
            seed_path = self.global_fuzzer.add_seed(
                seed, f"fp_{sp_id[:8]}_{hashlib.sha1(seed).hexdigest()[:8]}"
            )

        # Track seed
        seed_info = SeedInfo(
            seed_path=str(seed_path),
            seed_hash=hashlib.sha1(seed).hexdigest(),
            seed_size=len(seed),
            source="fp",
            sp_id=sp_id,
        )
        self.fp_seeds.append(seed_info)

        logger.debug(
            f"[FuzzerManager:{self.worker_id}] Added FP seed: "
            f"sp={sp_id[:8]}, size={len(seed)}"
        )
        return seed_path

    # =========================================================================
    # SP Fuzzer Management
    # =========================================================================

    async def start_sp_fuzzer(self, sp_id: str) -> bool:
        """
        Start an SP Fuzzer for a specific suspicious point.

        Args:
            sp_id: Suspicious point ID

        Returns:
            True if started successfully
        """
        if sp_id in self.sp_fuzzers and self.sp_fuzzers[sp_id].is_running():
            logger.warning(
                f"[FuzzerManager:{self.worker_id}] SP fuzzer already running: {sp_id[:8]}"
            )
            return False

        # Create directories for this SP
        sp_corpus_dir = self.sp_base_dir / sp_id / "corpus"
        sp_crashes_dir = self.sp_base_dir / sp_id / "crashes"
        sp_corpus_dir.mkdir(parents=True, exist_ok=True)
        sp_crashes_dir.mkdir(parents=True, exist_ok=True)

        # Create instance
        sp_fuzzer = FuzzerInstance(
            instance_id=sp_id,
            fuzzer_path=self.fuzzer_path,
            docker_image=self.docker_image,
            corpus_dir=sp_corpus_dir,
            crashes_dir=sp_crashes_dir,
            fuzzer_type=FuzzerType.SP,
            config=self.sp_config,
        )

        # Register crash directory
        self.crash_monitor.add_watch_dir(
            crash_dir=sp_crashes_dir,
            source=sp_id,
            fuzzer_name=self.fuzzer_name,
            sanitizer=self.sanitizer,
        )

        # Start monitoring if not already running
        if not self.crash_monitor._running:
            await self.crash_monitor.start_monitoring()

        # Start fuzzer
        success = await sp_fuzzer.start()
        if success:
            self.sp_fuzzers[sp_id] = sp_fuzzer
            logger.info(
                f"[{self.worker_id}] ▶ SP FUZZER STARTED: {sp_id[:8]} (total: {len(self.sp_fuzzers)})"
            )
        else:
            logger.error(f"[{self.worker_id}] ❌ SP FUZZER FAILED: {sp_id[:8]}")

        return success

    async def stop_sp_fuzzer(self, sp_id: str) -> None:
        """
        Stop an SP Fuzzer.

        Args:
            sp_id: Suspicious point ID
        """
        if sp_id not in self.sp_fuzzers:
            return

        await self.sp_fuzzers[sp_id].stop()
        self.crash_monitor.remove_watch_dir(sp_id)
        del self.sp_fuzzers[sp_id]

        logger.info(f"[{self.worker_id}] ■ SP FUZZER STOPPED: {sp_id[:8]}")

    def add_pov_blob(
        self,
        blob: bytes,
        sp_id: str,
        attempt: int = 0,
        variant: int = 0,
    ) -> Optional[Path]:
        """
        Add a POV blob to the corresponding SP Fuzzer's corpus.

        Args:
            blob: Raw POV blob bytes
            sp_id: Suspicious point ID
            attempt: POV attempt number
            variant: POV variant number

        Returns:
            Path to saved blob file, or None if SP fuzzer not found
        """
        if sp_id not in self.sp_fuzzers:
            # SP fuzzer not started yet, save to directory anyway
            sp_corpus_dir = self.sp_base_dir / sp_id / "corpus"
            sp_corpus_dir.mkdir(parents=True, exist_ok=True)

            blob_hash = hashlib.sha1(blob).hexdigest()[:8]
            blob_path = sp_corpus_dir / f"pov_a{attempt}_v{variant}_{blob_hash}"
            blob_path.write_bytes(blob)

            logger.debug(
                f"[FuzzerManager:{self.worker_id}] Saved POV blob (SP fuzzer not started): "
                f"sp={sp_id[:8]}, attempt={attempt}, variant={variant}"
            )
            return blob_path

        # Add to running SP fuzzer
        blob_path = self.sp_fuzzers[sp_id].add_seed(
            blob, f"pov_a{attempt}_v{variant}_{hashlib.sha1(blob).hexdigest()[:8]}"
        )

        logger.debug(
            f"[FuzzerManager:{self.worker_id}] Added POV blob to SP fuzzer: "
            f"sp={sp_id[:8]}, attempt={attempt}, variant={variant}"
        )
        return blob_path

    # =========================================================================
    # Status and Management
    # =========================================================================

    def get_status(self) -> Dict[str, Any]:
        """
        Get status of all fuzzers.

        Returns:
            Status dictionary
        """
        status = {
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "fuzzer_name": self.fuzzer_name,
            "sanitizer": self.sanitizer,
            "global_fuzzer": None,
            "sp_fuzzers": {},
            "crash_monitor": self.crash_monitor.get_stats(),
            "seed_counts": {
                "direction_seeds": len(self.direction_seeds),
                "fp_seeds": len(self.fp_seeds),
            },
        }

        # Global fuzzer status
        if self.global_fuzzer:
            status["global_fuzzer"] = self.global_fuzzer.get_stats()

        # SP fuzzer statuses
        for sp_id, sp_fuzzer in self.sp_fuzzers.items():
            status["sp_fuzzers"][sp_id] = sp_fuzzer.get_stats()

        return status

    def get_active_sp_fuzzers(self) -> List[str]:
        """Get list of active SP fuzzer IDs."""
        return [
            sp_id for sp_id, fuzzer in self.sp_fuzzers.items() if fuzzer.is_running()
        ]

    def get_total_crashes(self) -> int:
        """Get total number of crashes found by all fuzzers."""
        return self.crash_monitor.get_crash_count()

    def get_crashes_for_sp(self, sp_id: str) -> List[CrashRecord]:
        """
        Get crashes found by a specific SP Fuzzer.

        Args:
            sp_id: Suspicious point ID

        Returns:
            List of crash records
        """
        return self.crash_monitor.get_crashes_by_source(sp_id)

    async def restart_global_fuzzer(self) -> bool:
        """
        Restart the Global Fuzzer.

        Called when Global Fuzzer finds a crash and is stopped.

        Returns:
            True if restarted successfully
        """
        logger.info(f"[FuzzerManager:{self.worker_id}] Restarting global fuzzer")
        await self.stop_global_fuzzer()
        return await self.start_global_fuzzer()

    async def shutdown(self) -> None:
        """
        Shutdown all fuzzers and monitoring.

        Called when FuzzingBrain ends or worker is killed.
        """
        logger.info(f"[FuzzerManager:{self.worker_id}] Shutting down...")

        # Stop all SP fuzzers
        for sp_id in list(self.sp_fuzzers.keys()):
            await self.stop_sp_fuzzer(sp_id)

        # Stop global fuzzer
        await self.stop_global_fuzzer()

        # Stop crash monitor
        await self.crash_monitor.stop_monitoring()

        logger.info(f"[FuzzerManager:{self.worker_id}] Shutdown complete")

    def __repr__(self) -> str:
        return (
            f"FuzzerManager(worker_id={self.worker_id}, "
            f"global={'running' if self.global_fuzzer and self.global_fuzzer.is_running() else 'stopped'}, "
            f"sp_count={len(self.sp_fuzzers)})"
        )


# =============================================================================
# Global Manager Registry (for cross-module access)
# =============================================================================

_fuzzer_managers: Dict[str, FuzzerManager] = {}


def register_fuzzer_manager(worker_id: str, manager: FuzzerManager) -> None:
    """Register a FuzzerManager for cross-module access."""
    _fuzzer_managers[worker_id] = manager


def get_fuzzer_manager(worker_id: str) -> Optional[FuzzerManager]:
    """Get FuzzerManager by worker_id."""
    return _fuzzer_managers.get(worker_id)


def unregister_fuzzer_manager(worker_id: str) -> None:
    """Unregister a FuzzerManager."""
    if worker_id in _fuzzer_managers:
        del _fuzzer_managers[worker_id]
