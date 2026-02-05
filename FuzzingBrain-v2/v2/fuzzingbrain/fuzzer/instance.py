"""
Fuzzer Instance

Encapsulates a single libFuzzer process.
"""

import asyncio
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from loguru import logger

from .models import (
    FuzzerStatus,
    FuzzerType,
    FuzzerStats,
    GlobalFuzzerConfig,
    SPFuzzerConfig,
    SeedInfo,
)


class FuzzerInstance:
    """
    Single Fuzzer Instance.

    Encapsulates libFuzzer process startup, shutdown, and monitoring.
    Runs fuzzer in Docker container for isolation.
    """

    def __init__(
        self,
        instance_id: str,  # "global" or sp_id
        fuzzer_path: Path,
        docker_image: str,
        corpus_dir: Path,
        crashes_dir: Path,
        fuzzer_type: FuzzerType = FuzzerType.GLOBAL,
        config: Union[GlobalFuzzerConfig, SPFuzzerConfig] = None,
    ):
        """
        Initialize FuzzerInstance.

        Args:
            instance_id: Unique identifier ("global" or sp_id)
            fuzzer_path: Path to fuzzer binary
            docker_image: Docker image for running fuzzer
            corpus_dir: Directory for corpus seeds
            crashes_dir: Directory for crash outputs
            fuzzer_type: GLOBAL or SP
            config: Fuzzer configuration
        """
        self.instance_id = instance_id
        self.fuzzer_path = Path(fuzzer_path)
        self.docker_image = docker_image
        self.corpus_dir = Path(corpus_dir)
        self.crashes_dir = Path(crashes_dir)
        self.fuzzer_type = fuzzer_type

        # Configuration
        if config is None:
            if fuzzer_type == FuzzerType.GLOBAL:
                config = GlobalFuzzerConfig()
            else:
                config = SPFuzzerConfig()
        self.config = config

        # Process management
        self.process: Optional[asyncio.subprocess.Process] = None
        self.container_id: Optional[str] = None
        self.status = FuzzerStatus.IDLE

        # Statistics
        self.stats = FuzzerStats(
            instance_id=instance_id,
            fuzzer_type=fuzzer_type,
        )

        # Seed tracking
        self.seeds: List[SeedInfo] = []

        # Ensure directories exist
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

        logger.debug(
            f"[Fuzzer:{instance_id}] Initialized: type={fuzzer_type.value}, "
            f"corpus={corpus_dir}, crashes={crashes_dir}"
        )

    def _build_docker_command(self) -> List[str]:
        """
        Build Docker command for running fuzzer.

        Returns:
            List of command arguments
        """
        fuzzer_dir = self.fuzzer_path.parent
        fuzzer_name = self.fuzzer_path.name

        # Base command
        cmd = [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--entrypoint",
            "",  # Bypass base-runner's entrypoint
        ]

        # Environment variables
        cmd.extend(
            [
                "-e",
                "FUZZING_ENGINE=libfuzzer",
                "-e",
                "SANITIZER=address",
                "-e",
                "ARCHITECTURE=x86_64",
            ]
        )

        # Mount volumes
        cmd.extend(
            [
                "-v",
                f"{fuzzer_dir}:/fuzzers:ro",
                "-v",
                f"{self.corpus_dir}:/corpus",
                "-v",
                f"{self.crashes_dir}:/crashes",
            ]
        )

        # Docker image
        cmd.append(self.docker_image)

        # Fuzzer command
        cmd.append(f"/fuzzers/{fuzzer_name}")

        # libFuzzer arguments
        cmd.extend(
            [
                "/corpus",
                "-artifact_prefix=/crashes/",
                f"-fork={self.config.fork_level}",
                f"-rss_limit_mb={self.config.rss_limit_mb}",
                f"-timeout={self.config.timeout_per_input}",
                "-print_final_stats=1",
            ]
        )

        # Max time for global fuzzer only
        if self.fuzzer_type == FuzzerType.GLOBAL:
            if hasattr(self.config, "max_time") and self.config.max_time > 0:
                cmd.append(f"-max_total_time={self.config.max_time}")

        return cmd

    async def start(self) -> bool:
        """
        Start the fuzzer process.

        Returns:
            True if started successfully
        """
        if self.status in [FuzzerStatus.RUNNING, FuzzerStatus.STARTING]:
            logger.warning(f"[Fuzzer:{self.instance_id}] Already running")
            return False

        self.status = FuzzerStatus.STARTING
        self.stats.start_time = datetime.now()
        self.stats.stop_time = None

        try:
            # Build command
            cmd = self._build_docker_command()
            logger.info(
                f"[Fuzzer:{self.instance_id}] Starting: {' '.join(cmd[:10])}..."
            )

            # Start process
            self.process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            self.status = FuzzerStatus.RUNNING
            self.stats.status = FuzzerStatus.RUNNING

            logger.info(
                f"[Fuzzer:{self.instance_id}] Started (PID: {self.process.pid})"
            )
            return True

        except Exception as e:
            logger.error(f"[Fuzzer:{self.instance_id}] Failed to start: {e}")
            self.status = FuzzerStatus.ERROR
            self.stats.status = FuzzerStatus.ERROR
            return False

    async def stop(self, timeout: float = 10.0) -> None:
        """
        Stop the fuzzer process.

        Args:
            timeout: Seconds to wait before force kill
        """
        if self.process is None or self.status == FuzzerStatus.STOPPED:
            return

        logger.info(f"[Fuzzer:{self.instance_id}] Stopping...")

        try:
            # Try graceful termination first
            self.process.terminate()

            try:
                await asyncio.wait_for(self.process.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                # Force kill if not responding
                logger.warning(f"[Fuzzer:{self.instance_id}] Force killing...")
                self.process.kill()
                await self.process.wait()

        except ProcessLookupError:
            # Process already dead
            pass
        except Exception as e:
            logger.error(f"[Fuzzer:{self.instance_id}] Error stopping: {e}")

        self.status = FuzzerStatus.STOPPED
        self.stats.status = FuzzerStatus.STOPPED
        self.stats.stop_time = datetime.now()
        self.process = None

        logger.info(f"[Fuzzer:{self.instance_id}] Stopped")

    def add_seed(self, seed: bytes, name: str = None) -> Path:
        """
        Add a seed to the corpus directory.

        The fuzzer will automatically pick up new files (~2 seconds).

        Args:
            seed: Raw seed bytes
            name: Optional filename (auto-generated if None)

        Returns:
            Path to the saved seed file
        """
        # Generate filename from hash if not provided
        if name is None:
            seed_hash = hashlib.sha1(seed).hexdigest()[:16]
            name = f"seed_{seed_hash}"

        seed_path = self.corpus_dir / name

        # Write seed
        seed_path.write_bytes(seed)

        # Track seed
        seed_info = SeedInfo(
            seed_path=str(seed_path),
            seed_hash=hashlib.sha1(seed).hexdigest(),
            seed_size=len(seed),
        )
        self.seeds.append(seed_info)

        logger.debug(
            f"[Fuzzer:{self.instance_id}] Added seed: {name} ({len(seed)} bytes)"
        )
        return seed_path

    def add_seeds(self, seeds: List[bytes], prefix: str = "seed") -> List[Path]:
        """
        Add multiple seeds to corpus.

        Args:
            seeds: List of seed bytes
            prefix: Filename prefix

        Returns:
            List of saved seed paths
        """
        paths = []
        for i, seed in enumerate(seeds):
            name = f"{prefix}_{i:04d}"
            path = self.add_seed(seed, name)
            paths.append(path)
        return paths

    def get_crashes(self) -> List[Path]:
        """
        Get all crash files from crashes directory.

        Returns:
            List of crash file paths
        """
        crashes = []
        for f in self.crashes_dir.iterdir():
            if f.is_file() and f.name.startswith("crash-"):
                crashes.append(f)
        return sorted(crashes, key=lambda p: p.stat().st_mtime, reverse=True)

    def get_corpus_size(self) -> int:
        """Get number of files in corpus."""
        return sum(1 for f in self.corpus_dir.iterdir() if f.is_file())

    def is_running(self) -> bool:
        """Check if fuzzer is currently running."""
        if self.process is None:
            return False
        return self.process.returncode is None

    async def wait(self) -> int:
        """
        Wait for fuzzer process to complete.

        Returns:
            Process return code
        """
        if self.process is None:
            return -1

        return await self.process.wait()

    def get_stats(self) -> Dict[str, Any]:
        """
        Get fuzzer statistics.

        Returns:
            Statistics dictionary
        """
        self.stats.corpus_size = self.get_corpus_size()
        self.stats.crashes_found = len(self.get_crashes())

        return self.stats.to_dict()

    async def _parse_output(self) -> None:
        """Parse fuzzer output for statistics (background task)."""
        if self.process is None or self.process.stderr is None:
            return

        try:
            async for line in self.process.stderr:
                line_str = line.decode("utf-8", errors="replace").strip()

                # Parse coverage info
                cov_match = re.search(r"cov:\s*(\d+)", line_str)
                if cov_match:
                    self.stats.edge_coverage = int(cov_match.group(1))

                # Parse feature coverage
                ft_match = re.search(r"ft:\s*(\d+)", line_str)
                if ft_match:
                    self.stats.feature_coverage = int(ft_match.group(1))

                # Parse exec/s
                exec_match = re.search(r"exec/s:\s*(\d+)", line_str)
                if exec_match:
                    self.stats.execs_per_sec = float(exec_match.group(1))

                # Detect crash
                if "ERROR:" in line_str or "SUMMARY:" in line_str:
                    if self.status == FuzzerStatus.RUNNING:
                        self.status = FuzzerStatus.FOUND_CRASH
                        self.stats.status = FuzzerStatus.FOUND_CRASH

        except Exception as e:
            logger.debug(f"[Fuzzer:{self.instance_id}] Output parsing error: {e}")

    def __repr__(self) -> str:
        return (
            f"FuzzerInstance(id={self.instance_id}, "
            f"type={self.fuzzer_type.value}, status={self.status.value})"
        )
