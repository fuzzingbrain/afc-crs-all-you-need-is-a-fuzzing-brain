# SPDX-License-Identifier: Apache-2.0
"""
Fuzzer Manager

Worker-level manager for fuzzer instances.
Manages Global Fuzzer and VH Fuzzer Pool.

Note: FuzzerMonitor is now Run-level (passed in from Dispatcher).
"""

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from .models import (
    CrashRecord,
    FuzzerType,
    GlobalFuzzerConfig,
    VHFuzzerConfig,
    SeedInfo,
)
from ..core.fuzzer_spec import is_no_oom
from .budget import DEFAULT_MAX_PARALLEL_FUZZERS, FuzzerBudget
from .instance import FuzzerInstance
from .monitor import FuzzerMonitor


class FuzzerManager:
    """
    Worker-level Fuzzer Manager.

    Responsibilities:
    - Manage Global Fuzzer for this worker
    - Manage VH Fuzzer Pool for this worker
    - Register/unregister crash directories with Run-level FuzzerMonitor
    - Seed routing (LogicGroup/FP -> Global, PoC blob -> VH)
    """

    def __init__(
        self,
        run_id: str,
        worker_id: str,
        fuzzer_path: Path,
        docker_image: str,
        workspace_path: Path,
        fuzzer_name: str = "",
        sanitizer: str = "address",
        global_config: Optional[GlobalFuzzerConfig] = None,
        vh_config: Optional[VHFuzzerConfig] = None,
        crash_monitor: Optional[FuzzerMonitor] = None,
        max_parallel_fuzzers: int = DEFAULT_MAX_PARALLEL_FUZZERS,
    ):
        """
        Initialize FuzzerManager.

        Args:
            run_id: Parent run ID
            worker_id: Worker identifier
            fuzzer_path: Path to fuzzer binary
            docker_image: Docker image for running fuzzers
            workspace_path: Worker workspace path
            fuzzer_name: Fuzzer binary name
            sanitizer: Sanitizer type
            global_config: Configuration for Global Fuzzer
            vh_config: Configuration for VH Fuzzers
            crash_monitor: Run-level FuzzerMonitor (shared across workers)
            max_parallel_fuzzers: run-wide ceiling on running fuzzers
        """
        self.run_id = run_id
        self.worker_id = worker_id
        self.fuzzer_path = Path(fuzzer_path)
        self.docker_image = docker_image
        self.workspace_path = Path(workspace_path)
        self.fuzzer_name = fuzzer_name or self.fuzzer_path.name
        self.sanitizer = sanitizer

        # Configurations
        self.global_config = global_config or GlobalFuzzerConfig()
        self.vh_config = vh_config or VHFuzzerConfig()

        # Global Fuzzer
        self.global_fuzzer: Optional[FuzzerInstance] = None

        # VH Fuzzer Pool: vh_id -> FuzzerInstance
        self.vh_fuzzers: Dict[str, FuzzerInstance] = {}

        # Run-level Crash Monitor (shared, passed from Dispatcher)
        # If not provided, create a worker-local one (for backward compatibility)
        if crash_monitor is not None:
            self.crash_monitor = crash_monitor
            self._owns_crash_monitor = False
        else:
            # Backward compatibility: create worker-local monitor
            self.crash_monitor = FuzzerMonitor(run_id=run_id)
            self._owns_crash_monitor = True

        # Directories
        self.fuzzer_workspace = workspace_path / "fuzzer_worker"
        self.global_corpus_dir = self.fuzzer_workspace / "global" / "corpus"
        self.global_crashes_dir = self.fuzzer_workspace / "global" / "crashes"
        self.vh_base_dir = self.fuzzer_workspace / "vh_fuzzers"

        # Ensure directories exist
        self.global_corpus_dir.mkdir(parents=True, exist_ok=True)
        self.global_crashes_dir.mkdir(parents=True, exist_ok=True)
        self.vh_base_dir.mkdir(parents=True, exist_ok=True)

        # Seed tracking
        self.logic_group_seeds: List[SeedInfo] = []
        self.fp_seeds: List[SeedInfo] = []
        self.probe_seeds: List[SeedInfo] = []

        # The run's allowance of concurrent fuzzers, shared with every other
        # worker through Redis. Slot names carry the worker id because every
        # worker calls its own global fuzzer "global".
        self.budget = FuzzerBudget(run_id=run_id, limit=max_parallel_fuzzers)

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

    def _slot(self, instance_id: str) -> str:
        """This fuzzer's name in the run-wide ledger.

        The worker id is part of it because every worker names its own global
        fuzzer "global", and two workers must not share one slot.
        """
        return f"{self.worker_id}:{instance_id}"

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

        # Take a slot before spending anything on setup. The global fuzzer is
        # started first, before this worker's PoC agents ask for theirs, so it
        # is the one that gets a slot when the run is near its ceiling.
        if not self.budget.acquire(self._slot("global"), kind="global fuzzer"):
            logger.warning(
                f"[{self.worker_id}] Global fuzzer not started: the run is at "
                f"its limit of {self.budget.limit} concurrent fuzzers"
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
            run_id=self.run_id,
            no_oom=is_no_oom(self.fuzzer_name),
            sanitizer=self.sanitizer,
        )

        # Add initial seeds
        if initial_seeds:
            for i, seed in enumerate(initial_seeds):
                self.global_fuzzer.add_seed(seed, f"initial_{i:04d}")

        # Register crash directory for monitoring (with worker_id)
        self.crash_monitor.add_watch_dir(
            crash_dir=self.global_crashes_dir,
            worker_id=self.worker_id,
            source="global",
            fuzzer_name=self.fuzzer_name,
            sanitizer=self.sanitizer,
            fuzzer_path=self.fuzzer_path,
            docker_image=self.docker_image,
        )

        # Start monitoring if we own the monitor and it's not running
        if self._owns_crash_monitor and not self.crash_monitor._running:
            self.crash_monitor.start_monitoring()

        # Start fuzzer
        success = await self.global_fuzzer.start()
        if success:
            # Create .active marker for auto-discovery
            active_marker = self.fuzzer_workspace / "global" / ".active"
            active_marker.touch()

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
            self.budget.release(self._slot("global"))
            logger.error(f"[{self.worker_id}] ❌ GLOBAL FUZZER FAILED TO START")

        return success

    async def stop_global_fuzzer(self) -> None:
        """Stop the Global Fuzzer."""
        if self.global_fuzzer:
            await self.global_fuzzer.stop()
            self.budget.release(self._slot("global"))
            self.crash_monitor.remove_watch_dir(self.worker_id, "global")

            # Remove .active marker
            active_marker = self.fuzzer_workspace / "global" / ".active"
            active_marker.unlink(missing_ok=True)

            logger.info(f"[FuzzerManager:{self.worker_id}] Global fuzzer stopped")

    def add_logic_group_seed(self, seed: bytes, lg_id: str) -> Path:
        """
        Add a Logic group seed to Global Fuzzer.

        Args:
            seed: Raw seed bytes
            lg_id: Logic group ID that generated this seed

        Returns:
            Path to saved seed file
        """
        if not self.global_fuzzer:
            # Save to corpus dir even if fuzzer not started yet
            seed_hash = hashlib.sha1(seed).hexdigest()[:16]
            seed_path = (
                self.global_corpus_dir / f"logic_group_{lg_id[:8]}_{seed_hash}"
            )
            seed_path.write_bytes(seed)
        else:
            seed_path = self.global_fuzzer.add_seed(
                seed,
                f"logic_group_{lg_id[:8]}_{hashlib.sha1(seed).hexdigest()[:8]}",
            )

        # Track seed
        seed_info = SeedInfo(
            seed_path=str(seed_path),
            seed_hash=hashlib.sha1(seed).hexdigest(),
            seed_size=len(seed),
            source="logic_group",
            lg_id=lg_id,
        )
        self.logic_group_seeds.append(seed_info)

        logger.debug(
            f"[FuzzerManager:{self.worker_id}] Added logic group seed: "
            f"logic group={lg_id[:8]}, size={len(seed)}"
        )
        return seed_path

    def add_fp_seed(self, seed: bytes, vh_id: str) -> Path:
        """
        Add an FP (False Positive) seed to Global Fuzzer.

        Args:
            seed: Raw seed bytes
            vh_id: VH ID that was determined to be FP

        Returns:
            Path to saved seed file
        """
        if not self.global_fuzzer:
            seed_hash = hashlib.sha1(seed).hexdigest()[:16]
            seed_path = self.global_corpus_dir / f"fp_{vh_id[:8]}_{seed_hash}"
            seed_path.write_bytes(seed)
        else:
            seed_path = self.global_fuzzer.add_seed(
                seed, f"fp_{vh_id[:8]}_{hashlib.sha1(seed).hexdigest()[:8]}"
            )

        # Track seed
        seed_info = SeedInfo(
            seed_path=str(seed_path),
            seed_hash=hashlib.sha1(seed).hexdigest(),
            seed_size=len(seed),
            source="fp",
            vh_id=vh_id,
        )
        self.fp_seeds.append(seed_info)

        logger.debug(
            f"[FuzzerManager:{self.worker_id}] Added FP seed: "
            f"vh={vh_id[:8]}, size={len(seed)}"
        )
        return seed_path

    def add_probe_seed(self, seed: bytes, vh_id: str, to_vh_fuzzer: bool) -> Path:
        """
        Add an input an agent built with reach_probe / check_clamp.

        A probe input is aimed at one VH and often reaches it, which makes it a
        good seed. `to_vh_fuzzer` puts it in that VH's fuzzer corpus (a PoC agent's
        probe, next to its create_poc variants); otherwise in the Global corpus (a
        verifier's probe: the VH fuzzer does not exist yet at verification time).
        A fuzzer that is not running yet picks the file up from its corpus
        directory when it starts.

        Args:
            seed: Raw input bytes
            vh_id: VH the probe was aimed at
            to_vh_fuzzer: VH fuzzer corpus instead of the Global one

        Returns:
            Path to saved seed file
        """
        seed_hash = hashlib.sha1(seed).hexdigest()
        name = f"probe_{vh_id[:8]}_{seed_hash[:8]}"
        if to_vh_fuzzer:
            if vh_id in self.vh_fuzzers:
                seed_path = self.vh_fuzzers[vh_id].add_seed(seed, name)
            else:
                vh_corpus_dir = self.vh_base_dir / vh_id / "corpus"
                vh_corpus_dir.mkdir(parents=True, exist_ok=True)
                seed_path = vh_corpus_dir / name
                seed_path.write_bytes(seed)
        elif self.global_fuzzer:
            seed_path = self.global_fuzzer.add_seed(seed, name)
        else:
            seed_path = self.global_corpus_dir / name
            seed_path.write_bytes(seed)

        self.probe_seeds.append(
            SeedInfo(
                seed_path=str(seed_path),
                seed_hash=seed_hash,
                seed_size=len(seed),
                source="probe",
                vh_id=vh_id,
            )
        )
        logger.debug(
            f"[FuzzerManager:{self.worker_id}] Added probe seed: vh={vh_id[:8]}, "
            f"{'VH' if to_vh_fuzzer else 'Global'} corpus, size={len(seed)}"
        )
        return seed_path

    # =========================================================================
    # VH Fuzzer Management
    # =========================================================================

    async def start_vh_fuzzer(self, vh_id: str) -> bool:
        """
        Start a VH Fuzzer for a specific vulnerability hypothesis.

        Args:
            vh_id: Vulnerability hypothesis ID

        Returns:
            True if started successfully
        """
        if vh_id in self.vh_fuzzers and self.vh_fuzzers[vh_id].is_running():
            logger.warning(
                f"[FuzzerManager:{self.worker_id}] VH fuzzer already running: {vh_id[:8]}"
            )
            return False

        running = sum(1 for f in self.vh_fuzzers.values() if f.is_running())
        if running >= self.vh_config.max_count:
            logger.info(
                f"[{self.worker_id}] VH fuzzer for {vh_id[:8]} skipped: this "
                f"worker already runs {running} of them"
            )
            return False

        # A VH fuzzer is a bonus alongside the PoC agent, not a requirement:
        # when the run is at its ceiling the agent runs without one, which is
        # why the caller treats False as "carry on" rather than as an error.
        if not self.budget.acquire(self._slot(vh_id), kind="VH fuzzer"):
            logger.info(
                f"[{self.worker_id}] VH fuzzer for {vh_id[:8]} skipped: the run "
                f"is at its limit of {self.budget.limit} concurrent fuzzers"
            )
            return False

        # Create directories for this VH
        vh_corpus_dir = self.vh_base_dir / vh_id / "corpus"
        vh_crashes_dir = self.vh_base_dir / vh_id / "crashes"
        vh_corpus_dir.mkdir(parents=True, exist_ok=True)
        vh_crashes_dir.mkdir(parents=True, exist_ok=True)

        # Create instance
        vh_fuzzer = FuzzerInstance(
            instance_id=vh_id,
            fuzzer_path=self.fuzzer_path,
            docker_image=self.docker_image,
            corpus_dir=vh_corpus_dir,
            crashes_dir=vh_crashes_dir,
            fuzzer_type=FuzzerType.VH,
            config=self.vh_config,
            run_id=self.run_id,
            no_oom=is_no_oom(self.fuzzer_name),
            sanitizer=self.sanitizer,
        )

        # Register crash directory (with worker_id)
        self.crash_monitor.add_watch_dir(
            crash_dir=vh_crashes_dir,
            worker_id=self.worker_id,
            source=vh_id,
            fuzzer_name=self.fuzzer_name,
            sanitizer=self.sanitizer,
            fuzzer_path=self.fuzzer_path,
            docker_image=self.docker_image,
        )

        # Start monitoring if we own the monitor and it's not running
        if self._owns_crash_monitor and not self.crash_monitor._running:
            self.crash_monitor.start_monitoring()

        # Start fuzzer
        success = await vh_fuzzer.start()
        if success:
            self.vh_fuzzers[vh_id] = vh_fuzzer

            # Create .active marker for auto-discovery
            active_marker = self.vh_base_dir / vh_id / ".active"
            active_marker.touch()

            logger.info(
                f"[{self.worker_id}] ▶ VH FUZZER STARTED: {vh_id[:8]} (total: {len(self.vh_fuzzers)})"
            )
        else:
            self.budget.release(self._slot(vh_id))
            logger.error(f"[{self.worker_id}] ❌ VH FUZZER FAILED: {vh_id[:8]}")

        return success

    def _pool_vh_corpus_into_global(self, vh_id: str) -> int:
        """Copy a stopped VH fuzzer's corpus (and crash inputs, the deepest
        seeds) into the global corpus, deduplicated by content.

        VH fuzzers keep separate corpora, so the seeds a VH fuzzer evolved to
        reach a specific sink die with it. The global fuzzer runs with -fork and
        libFuzzer's default -reload, so once these units land in the global
        corpus dir it picks them up and mutates them -- letting a seed that
        reached deep code become a springboard for a nearby bug no single VH
        fuzzer reaches. Verified on shadowsocks (json_parse_ex, 5 bugs): per-VH
        fuzzing found 2/5 lines, pooling every VH corpus surfaced all 5.

        Oversized inputs (e.g. a 1 GiB OOM attempt) are junk that only slows the
        fuzzer -- the real bugs trigger on tiny inputs -- so they are skipped.

        Returns the number of new seeds added to the global corpus.
        """
        import hashlib

        MAX_SEED_BYTES = 1_048_576
        added = 0
        vh_dir = self.vh_base_dir / vh_id
        for sub in ("corpus", "crashes"):
            src = vh_dir / sub
            if not src.is_dir():
                continue
            for f in src.iterdir():
                if not f.is_file():
                    continue
                try:
                    data = f.read_bytes()
                except Exception:
                    continue
                if not data or len(data) > MAX_SEED_BYTES:
                    continue
                dst = self.global_corpus_dir / f"vh_{hashlib.sha1(data).hexdigest()}"
                if dst.exists():
                    continue
                try:
                    dst.write_bytes(data)
                    added += 1
                except Exception:
                    pass
        return added

    async def stop_vh_fuzzer(self, vh_id: str) -> None:
        """
        Stop a VH Fuzzer.

        Args:
            vh_id: Vulnerability hypothesis ID
        """
        if vh_id not in self.vh_fuzzers:
            return

        await self.vh_fuzzers[vh_id].stop()
        self.budget.release(self._slot(vh_id))
        self.crash_monitor.remove_watch_dir(self.worker_id, vh_id)

        # Remove .active marker
        active_marker = self.vh_base_dir / vh_id / ".active"
        active_marker.unlink(missing_ok=True)

        # Pool this VH fuzzer's evolved seeds into the global corpus before it is
        # gone, so the still-running global fuzzer keeps mutating them. The VH
        # fuzzer process is already stopped, so its corpus is frozen and safe to
        # copy.
        try:
            pooled = self._pool_vh_corpus_into_global(vh_id)
            if pooled:
                logger.info(
                    f"[{self.worker_id}] Pooled {pooled} seeds from VH "
                    f"{vh_id[:8]} into global corpus"
                )
        except Exception as e:
            logger.warning(
                f"[{self.worker_id}] Failed to pool VH {vh_id[:8]} corpus: {e}"
            )

        del self.vh_fuzzers[vh_id]

        logger.info(f"[{self.worker_id}] ■ VH FUZZER STOPPED: {vh_id[:8]}")

    def add_poc_blob(
        self,
        blob: bytes,
        vh_id: str,
        attempt: int = 0,
        variant: int = 0,
    ) -> Optional[Path]:
        """
        Add a PoC blob to the corresponding VH Fuzzer's corpus.

        Args:
            blob: Raw PoC blob bytes
            vh_id: Vulnerability hypothesis ID
            attempt: PoC attempt number
            variant: PoC variant number

        Returns:
            Path to saved blob file, or None if VH fuzzer not found
        """
        if vh_id not in self.vh_fuzzers:
            # VH fuzzer not started yet, save to directory anyway
            vh_corpus_dir = self.vh_base_dir / vh_id / "corpus"
            vh_corpus_dir.mkdir(parents=True, exist_ok=True)

            blob_hash = hashlib.sha1(blob).hexdigest()[:8]
            blob_path = vh_corpus_dir / f"poc_a{attempt}_v{variant}_{blob_hash}"
            blob_path.write_bytes(blob)

            logger.debug(
                f"[FuzzerManager:{self.worker_id}] Saved PoC blob (VH fuzzer not started): "
                f"vh={vh_id[:8]}, attempt={attempt}, variant={variant}"
            )
            return blob_path

        # Add to running VH fuzzer
        blob_path = self.vh_fuzzers[vh_id].add_seed(
            blob, f"poc_a{attempt}_v{variant}_{hashlib.sha1(blob).hexdigest()[:8]}"
        )

        logger.debug(
            f"[FuzzerManager:{self.worker_id}] Added PoC blob to VH fuzzer: "
            f"vh={vh_id[:8]}, attempt={attempt}, variant={variant}"
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
            "run_id": self.run_id,
            "worker_id": self.worker_id,
            "fuzzer_name": self.fuzzer_name,
            "sanitizer": self.sanitizer,
            "global_fuzzer": None,
            "vh_fuzzers": {},
            "crash_monitor": self.crash_monitor.get_stats(),
            "seed_counts": {
                "logic_group_seeds": len(self.logic_group_seeds),
                "fp_seeds": len(self.fp_seeds),
                "probe_seeds": len(self.probe_seeds),
            },
        }

        # Global fuzzer status
        if self.global_fuzzer:
            status["global_fuzzer"] = self.global_fuzzer.get_stats()

        # VH fuzzer statuses
        for vh_id, vh_fuzzer in self.vh_fuzzers.items():
            status["vh_fuzzers"][vh_id] = vh_fuzzer.get_stats()

        return status

    def get_active_vh_fuzzers(self) -> List[str]:
        """Get list of active VH fuzzer IDs."""
        return [
            vh_id for vh_id, fuzzer in self.vh_fuzzers.items() if fuzzer.is_running()
        ]

    def get_total_crashes(self) -> int:
        """Get total number of crashes found by this worker's fuzzers."""
        return len(self.crash_monitor.get_crashes_by_worker(self.worker_id))

    def get_crashes_for_vh(self, vh_id: str) -> List[CrashRecord]:
        """
        Get crashes found by a specific VH Fuzzer.

        Args:
            vh_id: Vulnerability hypothesis ID

        Returns:
            List of crash records
        """
        return self.crash_monitor.get_crashes_by_source(self.worker_id, vh_id)

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

    async def shutdown_vh_fuzzers_only(self) -> None:
        """
        Shutdown only VH fuzzers, keep Global Fuzzer running.

        Called when Worker completes but Global Fuzzer should continue.
        """
        logger.info(
            f"[FuzzerManager:{self.worker_id}] Shutting down VH fuzzers only, "
            f"Global Fuzzer continues running..."
        )

        # Stop all VH fuzzers
        for vh_id in list(self.vh_fuzzers.keys()):
            await self.stop_vh_fuzzer(vh_id)

        logger.info(
            f"[FuzzerManager:{self.worker_id}] VH fuzzers stopped, "
            f"Global Fuzzer still running"
        )

    async def shutdown(self) -> None:
        """
        Shutdown all fuzzers for this worker.

        Note: Does NOT stop the FuzzerMonitor (that's Run-level, managed by Dispatcher).
        """
        logger.info(f"[FuzzerManager:{self.worker_id}] Shutting down...")

        # Stop all VH fuzzers
        for vh_id in list(self.vh_fuzzers.keys()):
            await self.stop_vh_fuzzer(vh_id)

        # Stop global fuzzer
        await self.stop_global_fuzzer()

        # Only stop monitor if we own it (backward compatibility)
        if self._owns_crash_monitor:
            self.crash_monitor.stop_monitoring()

        logger.info(f"[FuzzerManager:{self.worker_id}] Shutdown complete")

    def __repr__(self) -> str:
        return (
            f"FuzzerManager(worker_id={self.worker_id}, "
            f"global={'running' if self.global_fuzzer and self.global_fuzzer.is_running() else 'stopped'}, "
            f"vh_count={len(self.vh_fuzzers)})"
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
