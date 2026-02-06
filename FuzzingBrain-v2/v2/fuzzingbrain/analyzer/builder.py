"""
Analyzer Builder

Builds fuzzers with all sanitizers in parallel (resource-aware).
Output is organized as: out/{project}_{sanitizer}/

This replaces the old fuzzer_builder.py approach where Controller
and Workers would each build separately.
"""

import asyncio
import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import List, Tuple, Dict, Optional

import psutil
from loguru import logger as loguru_logger

from .models import FuzzerInfo


class ResourceMonitor:
    """
    Monitor system resources and control parallel build execution.

    Checks CPU and memory availability before starting new builds.
    """

    # Resource thresholds
    MAX_CPU_PERCENT = 85.0  # Don't start new build if CPU > 85%
    MIN_MEMORY_GB = 4.0  # Need at least 4GB free memory per build
    MIN_MEMORY_PERCENT = 15.0  # Keep at least 15% memory free

    # Estimated resource usage per Docker build
    MEMORY_PER_BUILD_GB = 4.0

    def __init__(self, max_parallel: int = None):
        """
        Initialize ResourceMonitor.

        Args:
            max_parallel: Maximum parallel builds (default: CPU cores / 4, min 2)
        """
        cpu_count = psutil.cpu_count() or 4
        self.max_parallel = max_parallel or max(2, cpu_count // 4)
        self.current_builds = 0
        self._state_lock = Lock()  # Lock for state changes

    def get_status(self) -> Dict:
        """Get current resource status."""
        cpu_percent = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        return {
            "cpu_percent": cpu_percent,
            "memory_available_gb": mem.available / (1024**3),
            "memory_percent_used": mem.percent,
            "current_builds": self.current_builds,
            "max_parallel": self.max_parallel,
        }

    def can_start_build(self) -> Tuple[bool, str]:
        """
        Check if a new build can be started.

        Returns:
            (can_start, reason)
        """
        # Check parallel limit (use state lock for current_builds)
        with self._state_lock:
            if self.current_builds >= self.max_parallel:
                return False, f"Max parallel builds reached ({self.max_parallel})"

        # Check CPU (no lock needed for read-only system calls)
        cpu_percent = psutil.cpu_percent(interval=0.1)
        if cpu_percent > self.MAX_CPU_PERCENT:
            return False, f"CPU too high ({cpu_percent:.1f}% > {self.MAX_CPU_PERCENT}%)"

        # Check memory
        mem = psutil.virtual_memory()
        mem_available_gb = mem.available / (1024**3)

        if mem_available_gb < self.MIN_MEMORY_GB:
            return (
                False,
                f"Not enough memory ({mem_available_gb:.1f}GB < {self.MIN_MEMORY_GB}GB)",
            )

        if mem.percent > (100 - self.MIN_MEMORY_PERCENT):
            return False, f"Memory usage too high ({mem.percent:.1f}%)"

        return True, "OK"

    def acquire_build_slot(self) -> bool:
        """Try to acquire a build slot. Returns True if successful."""
        with self._state_lock:
            # Re-check limit under lock
            if self.current_builds >= self.max_parallel:
                return False

            # Check resources (no lock needed)
            cpu_percent = psutil.cpu_percent(interval=0.1)
            if cpu_percent > self.MAX_CPU_PERCENT:
                return False

            mem = psutil.virtual_memory()
            if mem.available / (1024**3) < self.MIN_MEMORY_GB:
                return False

            self.current_builds += 1
            return True

    def release_build_slot(self):
        """Release a build slot."""
        with self._state_lock:
            self.current_builds = max(0, self.current_builds - 1)

    async def wait_for_slot(
        self, poll_interval: float = 2.0, timeout: float = 300.0
    ) -> bool:
        """
        Wait until a build slot is available.

        Args:
            poll_interval: Seconds between checks
            timeout: Maximum wait time in seconds

        Returns:
            True if slot acquired, False if timeout
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.acquire_build_slot():
                return True
            await asyncio.sleep(poll_interval)
        return False


class AnalyzerBuilder:
    """
    Builds all fuzzers with all sanitizers.

    Output structure:
        fuzz-tooling/build/out/
        ├── {project}_address/
        │   ├── fuzzer1
        │   ├── fuzzer2
        │   └── ...
        ├── {project}_memory/
        │   └── ...
        ├── {project}_undefined/
        │   └── ...
        ├── {project}_coverage/
        │   └── ...
        └── {project}_introspector/
            └── inspector/
                └── all-fuzz-introspector-functions.json
    """

    # Files to skip when scanning build output
    SKIP_FILES = {
        "llvm-symbolizer",
        "sancov",
        "clang",
        "clang++",
        "llvm-cov",
        "llvm-profdata",
        "llvm-ar",
    }

    # Extensions to skip
    SKIP_EXTENSIONS = {
        ".bin",
        ".log",
        ".dict",
        ".options",
        ".bc",
        ".json",
        ".o",
        ".a",
        ".so",
        ".h",
        ".c",
        ".cpp",
        ".cc",
        ".py",
        ".sh",
        ".txt",
        ".md",
        ".zip",
        ".tar",
        ".gz",
    }

    def __init__(
        self,
        task_path: str,
        project_name: str,
        sanitizers: List[str],
        ossfuzz_project_name: Optional[str] = None,
        log_callback=None,
        log_dir: Optional[str] = None,
        parallel: bool = True,
        max_parallel: int = None,
        skip_introspector: bool = False,
        analyzer_only_log_callback=None,
    ):
        """
        Initialize AnalyzerBuilder.

        Args:
            task_path: Path to task workspace (contains repo/, fuzz-tooling/)
            project_name: Project name
            sanitizers: List of sanitizers to build (e.g., ["address", "memory"])
            ossfuzz_project_name: OSS-Fuzz project name if different from project_name
            log_callback: Optional callback for logging (func(msg, level))
            log_dir: Directory for build logs (build output saved here, not to console)
            parallel: Enable parallel builds (default: True)
            max_parallel: Maximum parallel builds (default: auto based on CPU)
            skip_introspector: Skip introspector build (when using prebuild data)
            analyzer_only_log_callback: Optional callback for analyzer-only logging (not to main log)
        """
        self.task_path = Path(task_path)
        self.project_name = ossfuzz_project_name or project_name
        self.sanitizers = sanitizers
        self.skip_introspector = skip_introspector
        self.log_callback = log_callback or self._default_log
        self.analyzer_only_log_callback = analyzer_only_log_callback
        self.log_dir = Path(log_dir) if log_dir else None
        self.parallel = parallel

        self.repo_path = self.task_path / "repo"
        self.fuzz_tooling_path = self.task_path / "fuzz-tooling"
        self.build_out_base = self.fuzz_tooling_path / "build" / "out"

        # Resource monitor for parallel builds
        self.resource_monitor = ResourceMonitor(max_parallel=max_parallel)

        # Thread-safe lock for shared state
        self._lock = Lock()

        # Results
        self.fuzzers: List[FuzzerInfo] = []
        self.build_paths: Dict[str, str] = {}
        self.coverage_path: Optional[str] = None
        self.introspector_path: Optional[str] = None

    def _default_log(self, msg: str, level: str = "INFO"):
        """Default logging using loguru."""
        if level == "ERROR":
            loguru_logger.error(f"[Builder] {msg}")
        elif level == "WARN":
            loguru_logger.warning(f"[Builder] {msg}")
        else:
            loguru_logger.info(f"[Builder] {msg}")

    def log(self, msg: str, level: str = "INFO"):
        """Log a message."""
        self.log_callback(msg, level)

    def log_analyzer_only(self, msg: str, level: str = "INFO"):
        """Log a message only to analyzer log (not to FuzzingBrain.log)."""
        if self.analyzer_only_log_callback:
            self.analyzer_only_log_callback(msg, level)
        else:
            # Fallback to normal log if no analyzer-only callback
            self.log_callback(msg, level)

    def build_all(self) -> Tuple[bool, str]:
        """
        Build fuzzers with all sanitizers.

        Build order:
        1. Build with each user-specified sanitizer (parallel if enabled)
        2. Build with coverage (for C/C++)
        3. Build with introspector (for static analysis)

        Returns:
            (success, message)
        """
        if self.parallel:
            return self._build_all_parallel()
        else:
            return self._build_all_sequential()

    def _build_all_sequential(self) -> Tuple[bool, str]:
        """Sequential build (original implementation)."""
        start_time = time.time()

        # Validate paths
        if not self.fuzz_tooling_path.exists():
            return False, f"fuzz-tooling not found: {self.fuzz_tooling_path}"

        helper_path = self.fuzz_tooling_path / "infra" / "helper.py"
        if not helper_path.exists():
            return False, f"helper.py not found: {helper_path}"

        total_steps = (
            len(self.sanitizers) + 1 + (0 if self.skip_introspector else 1)
        )  # sanitizers + coverage + introspector
        current_step = 0

        # Step 1-N: Build with each sanitizer
        for sanitizer in self.sanitizers:
            current_step += 1
            self.log(
                f"[{current_step}/{total_steps}] Building with {sanitizer} sanitizer"
            )

            success, msg = self._build_sanitizer(sanitizer)
            if not success:
                self.log(f"Build failed for {sanitizer}: {msg}", "ERROR")
                # Continue with other sanitizers, don't fail completely
                continue

            # Collect fuzzers for this sanitizer
            self._collect_fuzzers(sanitizer)

        # Check if at least one sanitizer succeeded
        if not self.fuzzers:
            return False, "All sanitizer builds failed, no fuzzers available"

        # Step N+1: Build coverage
        current_step += 1
        self.log(f"[{current_step}/{total_steps}] Building with coverage sanitizer")
        coverage_success, _ = self._build_sanitizer("coverage")
        if coverage_success:
            self._move_build_output("coverage")
            self.coverage_path = str(
                self.build_out_base / f"{self.project_name}_coverage"
            )
        else:
            self.log("Coverage build failed, continuing without it", "WARN")

        # Step N+2: Build introspector (unless skipped)
        if not self.skip_introspector:
            current_step += 1
            self.log(f"[{current_step}/{total_steps}] Building with introspector")
            introspector_success, _ = self._build_sanitizer("introspector")
            if introspector_success:
                self._move_build_output("introspector")
                self.introspector_path = str(
                    self.build_out_base / f"{self.project_name}_introspector"
                )
            else:
                self.log(
                    "Introspector build failed, static analysis will be limited", "WARN"
                )
        else:
            self.log("Skipping introspector build (using prebuild data)")

        elapsed = time.time() - start_time
        self.log(
            f"Build completed in {elapsed:.1f}s. {len(self.fuzzers)} fuzzers available."
        )

        return True, f"Built {len(self.fuzzers)} fuzzers in {elapsed:.1f}s"

    def _build_all_parallel(self) -> Tuple[bool, str]:
        """
        Parallel build with resource-aware scheduling.

        Each sanitizer gets its own copy of fuzz-tooling to avoid conflicts:
        1. Copy fuzz-tooling → fuzz-tooling-{sanitizer}/
        2. Build in isolated directory
        3. Move output to fuzz-tooling/build/out/{project}_{sanitizer}/
        4. Delete temp directory
        """
        start_time = time.time()

        # Validate paths
        if not self.fuzz_tooling_path.exists():
            return False, f"fuzz-tooling not found: {self.fuzz_tooling_path}"

        helper_path = self.fuzz_tooling_path / "infra" / "helper.py"
        if not helper_path.exists():
            return False, f"helper.py not found: {helper_path}"

        # Pre-build Docker image once to avoid race condition in parallel builds.
        # Each parallel build calls `docker build` internally, which would race
        # when creating the same image tag simultaneously (containerd "already exists" error).
        self.log("Pre-building Docker image to avoid parallel build conflicts")
        prebuild_success = self._prebuild_docker_image()
        if not prebuild_success:
            self.log("Docker image pre-build failed", "ERROR")
            return False, "Docker image pre-build failed"

        # All builds: sanitizers + coverage + introspector (unless skipped)
        all_builds = self.sanitizers + ["coverage"]
        if not self.skip_introspector:
            all_builds.append("introspector")
        else:
            self.log("Skipping introspector build (using prebuild data)")
        total_builds = len(all_builds)

        self.log(
            f"Starting parallel build: {total_builds} builds, max {self.resource_monitor.max_parallel} parallel"
        )
        status = self.resource_monitor.get_status()
        self.log(
            f"System resources: CPU {status['cpu_percent']:.1f}%, Memory available {status['memory_available_gb']:.1f}GB"
        )

        # Track build results
        build_results: Dict[str, Tuple[bool, str]] = {}
        completed_count = 0

        def build_with_isolated_dir(sanitizer: str) -> Tuple[str, bool, str]:
            """Build a single sanitizer in isolated directory."""
            nonlocal completed_count

            # Wait for resource availability
            wait_start = time.time()
            while not self.resource_monitor.acquire_build_slot():
                time.sleep(2.0)
                if time.time() - wait_start > 600:  # 10 min timeout
                    return sanitizer, False, "Timeout waiting for resources"

            temp_fuzz_tooling = None
            temp_repo = None
            try:
                # Step 1: Copy fuzz-tooling and repo to temp directories
                temp_fuzz_tooling = self._create_temp_fuzz_tooling(sanitizer)
                if not temp_fuzz_tooling:
                    return sanitizer, False, "Failed to create temp fuzz-tooling"

                temp_repo = self._create_temp_repo(sanitizer)
                if not temp_repo:
                    return sanitizer, False, "Failed to create temp repo"

                self.log(f"[Building] {sanitizer} (parallel)")

                # Step 2: Build in isolated directory with isolated repo
                success, msg = self._build_sanitizer_in_dir(
                    sanitizer, temp_fuzz_tooling, temp_repo
                )

                if success:
                    # Step 3: Move output to main fuzz-tooling
                    self._move_temp_output_to_main(sanitizer, temp_fuzz_tooling)

                with self._lock:
                    completed_count += 1
                    self.log(
                        f"[{completed_count}/{total_builds}] {sanitizer}: {'OK' if success else 'FAILED'}"
                    )

                return sanitizer, success, msg

            except Exception as e:
                return sanitizer, False, str(e)
            finally:
                self.resource_monitor.release_build_slot()
                # Step 4: Cleanup temp directories
                for temp_dir in [temp_fuzz_tooling, temp_repo]:
                    if temp_dir and temp_dir.exists():
                        try:
                            shutil.rmtree(temp_dir)
                        except Exception:
                            pass

        # Run builds in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(
            max_workers=self.resource_monitor.max_parallel
        ) as executor:
            futures = {
                executor.submit(build_with_isolated_dir, san): san for san in all_builds
            }

            for future in as_completed(futures):
                sanitizer = futures[future]
                try:
                    san, success, msg = future.result()
                    build_results[san] = (success, msg)
                except Exception as e:
                    build_results[sanitizer] = (False, str(e))
                    self.log(f"Build exception for {sanitizer}: {e}", "ERROR")

        # Process results: collect fuzzers from successful sanitizer builds
        for sanitizer in self.sanitizers:
            success, msg = build_results.get(sanitizer, (False, "Not built"))
            if success:
                self._collect_fuzzers(sanitizer)
            else:
                self.log(f"Build failed for {sanitizer}: {msg}", "ERROR")

        # Check if at least one sanitizer succeeded
        if not self.fuzzers:
            return False, "All sanitizer builds failed, no fuzzers available"

        # Handle coverage result
        cov_success, _ = build_results.get("coverage", (False, "Not built"))
        if cov_success:
            self.coverage_path = str(
                self.build_out_base / f"{self.project_name}_coverage"
            )
        else:
            self.log("Coverage build failed, continuing without it", "WARN")

        # Handle introspector result
        intro_success, _ = build_results.get("introspector", (False, "Not built"))
        if intro_success:
            self.introspector_path = str(
                self.build_out_base / f"{self.project_name}_introspector"
            )
        else:
            self.log(
                "Introspector build failed, static analysis will be limited", "WARN"
            )

        elapsed = time.time() - start_time
        successful = sum(1 for s, _ in build_results.values() if s)
        self.log(
            f"Parallel build completed in {elapsed:.1f}s. {successful}/{total_builds} succeeded, {len(self.fuzzers)} fuzzers available."
        )

        return True, f"Built {len(self.fuzzers)} fuzzers in {elapsed:.1f}s (parallel)"

    def _prebuild_docker_image(self) -> bool:
        """
        Pre-build Docker image once before parallel builds.

        This avoids a race condition where multiple parallel builds try to
        create the same Docker image tag simultaneously, causing containerd
        "already exists" errors.
        """
        helper_path = self.fuzz_tooling_path / "infra" / "helper.py"
        cmd = [
            "python3",
            str(helper_path),
            "build_image",
            "--pull",  # Pull latest base images, skip interactive prompt
            self.project_name,
        ]
        try:
            start_time = time.time()
            # Force unbuffered output from helper.py
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,  # Line buffered for real-time output
                cwd=str(self.fuzz_tooling_path),
                env=env,
            )

            # Stream output to Analyzer log only (not to FuzzingBrain.log)
            line_count = 0
            for line in process.stdout:
                line = line.rstrip()
                line_count += 1
                # Log progress every 20 lines
                if line_count % 20 == 0:
                    elapsed = time.time() - start_time
                    self.log_analyzer_only(
                        f"[Docker build] {line_count} lines, {elapsed:.0f}s elapsed...",
                        "DEBUG",
                    )
                # Log important Docker build steps
                if any(
                    kw in line
                    for kw in ["Step ", "Successfully built", "Successfully tagged"]
                ):
                    self.log_analyzer_only(f"[Docker] {line}")
                # Log errors (also to main log for visibility)
                elif any(kw in line.lower() for kw in ["error", "failed"]):
                    self.log_analyzer_only(f"[Docker] {line}", "WARN")

            process.wait(timeout=600)
            elapsed = time.time() - start_time

            if process.returncode != 0:
                self.log(
                    f"Docker image pre-build failed (exit code {process.returncode})",
                    "ERROR",
                )
                return False

            self.log(f"Docker image pre-built successfully in {elapsed:.1f}s")
            return True
        except subprocess.TimeoutExpired:
            process.kill()
            self.log("Docker image pre-build timed out (10 minutes)", "ERROR")
            return False
        except Exception as e:
            self.log(f"Docker image pre-build exception: {e}", "ERROR")
            return False

    def _create_temp_fuzz_tooling(self, sanitizer: str) -> Optional[Path]:
        """
        Create a temporary copy of fuzz-tooling for isolated build.

        Args:
            sanitizer: Sanitizer name (used in directory name)

        Returns:
            Path to temp directory, or None if failed
        """
        temp_dir = self.task_path / f"fuzz-tooling-{sanitizer}"

        try:
            # Remove if exists
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

            # Copy fuzz-tooling
            shutil.copytree(self.fuzz_tooling_path, temp_dir)
            return temp_dir

        except Exception as e:
            self.log(
                f"Failed to create temp fuzz-tooling for {sanitizer}: {e}", "ERROR"
            )
            return None

    def _create_temp_repo(self, sanitizer: str) -> Optional[Path]:
        """
        Create a temporary copy of repo for isolated build.

        Args:
            sanitizer: Sanitizer name (used in directory name)

        Returns:
            Path to temp directory, or None if failed
        """
        temp_dir = self.task_path / f"repo-{sanitizer}"

        try:
            # Remove if exists
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

            # Copy repo (symlinks=True to avoid following self-referencing symlinks)
            shutil.copytree(self.repo_path, temp_dir, symlinks=True)
            return temp_dir

        except Exception as e:
            self.log(f"Failed to create temp repo for {sanitizer}: {e}", "ERROR")
            return None

    def _build_sanitizer_in_dir(
        self, sanitizer: str, fuzz_tooling_dir: Path, repo_dir: Path = None
    ) -> Tuple[bool, str]:
        """
        Build with a specific sanitizer in the given directory.

        Args:
            sanitizer: Sanitizer type
            fuzz_tooling_dir: Path to fuzz-tooling directory to use
            repo_dir: Path to repo directory to use (default: self.repo_path)

        Returns:
            (success, message)
        """
        helper_path = fuzz_tooling_dir / "infra" / "helper.py"
        repo_path = repo_dir if repo_dir else self.repo_path

        cmd = [
            "python3",
            str(helper_path),
            "build_fuzzers",
            "--sanitizer",
            sanitizer,
            "--engine",
            "libfuzzer",
            "--mount_path",
            f"/src/{self.project_name}",
            self.project_name,
            str(repo_path.absolute()),
        ]

        try:
            start_time = time.time()

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(fuzz_tooling_dir),
            )

            # Collect output
            build_output = []
            for line in process.stdout:
                line = line.replace("\r", "\n").rstrip("\n")
                if line:
                    build_output.append(line)

            process.wait(timeout=1800)  # 30 minutes
            elapsed = time.time() - start_time

            # Write build output to log file (new structure: build/{sanitizer}.log)
            if self.log_dir:
                build_dir = self.log_dir / "build"
                build_dir.mkdir(parents=True, exist_ok=True)
                build_log_file = build_dir / f"{sanitizer}.log"
                with open(build_log_file, "w", encoding="utf-8") as f:
                    f.write(f"# Build log for {sanitizer} sanitizer\n")
                    f.write(f"# Command: {' '.join(cmd)}\n")
                    f.write(f"# Duration: {elapsed:.1f}s\n")
                    f.write(f"# Return code: {process.returncode}\n")
                    f.write("=" * 80 + "\n\n")
                    f.write("\n".join(build_output))

            # Fix permissions
            self._fix_permissions_for_dir(fuzz_tooling_dir / "build" / "out")

            if process.returncode != 0:
                # Append error to build log (no separate error.log for builds)
                if self.log_dir:
                    build_dir = self.log_dir / "build"
                    build_dir.mkdir(parents=True, exist_ok=True)
                    with open(
                        build_dir / f"{sanitizer}.log", "a", encoding="utf-8"
                    ) as f:
                        f.write("\n" + "=" * 80 + "\n")
                        f.write(f"[BUILD ERROR] Exit code {process.returncode}\n")
                        f.write("=" * 80 + "\n")
                return False, f"Build failed with code {process.returncode}"

            self.log(f"Built {sanitizer} in {elapsed:.1f}s")
            return True, "Build successful"

        except subprocess.TimeoutExpired:
            process.kill()
            return False, "Build timed out (30 minutes)"
        except Exception as e:
            return False, str(e)

    def _move_temp_output_to_main(self, sanitizer: str, temp_dir: Path) -> bool:
        """
        Move build output from temp directory to main fuzz-tooling.

        Args:
            sanitizer: Sanitizer name
            temp_dir: Temp fuzz-tooling directory

        Returns:
            True if successful
        """
        src_dir = temp_dir / "build" / "out" / self.project_name
        dest_dir = self.build_out_base / f"{self.project_name}_{sanitizer}"

        if not src_dir.exists():
            self.log(f"Source directory not found: {src_dir}", "WARN")
            return False

        try:
            # Ensure output base exists
            self.build_out_base.mkdir(parents=True, exist_ok=True)

            # Remove destination if exists
            if dest_dir.exists():
                shutil.rmtree(dest_dir)

            # Move output
            shutil.move(str(src_dir), str(dest_dir))
            self.build_paths[sanitizer] = str(dest_dir)

            self.log(f"Moved {sanitizer} output to {dest_dir}")
            return True

        except Exception as e:
            self.log(f"Failed to move output for {sanitizer}: {e}", "ERROR")
            return False

    def _fix_permissions_for_dir(self, dir_path: Path) -> None:
        """Fix file permissions for a specific directory after Docker build."""
        if not dir_path or not dir_path.exists():
            return

        uid = os.getuid()
        gid = os.getgid()

        try:
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{dir_path.absolute()}:/fix_perms",
                    "alpine:latest",
                    "chown",
                    "-R",
                    f"{uid}:{gid}",
                    "/fix_perms",
                ],
                capture_output=True,
                timeout=120,
            )
        except Exception:
            pass

    def _build_sanitizer(self, sanitizer: str) -> Tuple[bool, str]:
        """
        Build with a specific sanitizer (used by sequential build).

        Args:
            sanitizer: Sanitizer type (address, memory, undefined, coverage, introspector)

        Returns:
            (success, message)
        """
        helper_path = self.fuzz_tooling_path / "infra" / "helper.py"

        cmd = [
            "python3",
            str(helper_path),
            "build_fuzzers",
            "--sanitizer",
            sanitizer,
            "--engine",
            "libfuzzer",
            "--mount_path",
            f"/src/{self.project_name}",
            self.project_name,
            str(self.repo_path.absolute()),
        ]

        try:
            start_time = time.time()

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(self.fuzz_tooling_path),
            )

            # Collect output - write to build log file, not console
            build_output = []
            for line in process.stdout:
                line = line.replace("\r", "\n").rstrip("\n")
                if line:
                    build_output.append(line)

            process.wait(timeout=1800)  # 30 minutes
            elapsed = time.time() - start_time

            # Write build output to separate log file (new structure: build/{sanitizer}.log)
            if self.log_dir:
                build_dir = self.log_dir / "build"
                build_dir.mkdir(parents=True, exist_ok=True)
                build_log_file = build_dir / f"{sanitizer}.log"
                with open(build_log_file, "w", encoding="utf-8") as f:
                    f.write(f"# Build log for {sanitizer} sanitizer\n")
                    f.write(f"# Command: {' '.join(cmd)}\n")
                    f.write(f"# Duration: {elapsed:.1f}s\n")
                    f.write(f"# Return code: {process.returncode}\n")
                    f.write("=" * 80 + "\n\n")
                    f.write("\n".join(build_output))

            # Fix permissions after Docker build
            self._fix_permissions()

            if process.returncode != 0:
                # Append error to build log (no separate error.log for builds)
                if self.log_dir:
                    build_dir = self.log_dir / "build"
                    build_dir.mkdir(parents=True, exist_ok=True)
                    with open(
                        build_dir / f"{sanitizer}.log", "a", encoding="utf-8"
                    ) as f:
                        f.write("\n" + "=" * 80 + "\n")
                        f.write(f"[BUILD ERROR] Exit code {process.returncode}\n")
                        f.write("=" * 80 + "\n")
                return False, f"Build failed with code {process.returncode}"

            self.log(f"Built {sanitizer} in {elapsed:.1f}s")
            return True, "Build successful"

        except subprocess.TimeoutExpired:
            process.kill()
            return False, "Build timed out (30 minutes)"
        except Exception as e:
            return False, str(e)

    def _move_build_output(self, sanitizer: str) -> bool:
        """
        Move build output to sanitizer-specific directory.

        Moves from: build/out/{project}/
        To:         build/out/{project}_{sanitizer}/

        Args:
            sanitizer: Sanitizer name

        Returns:
            True if successful
        """
        src_dir = self.build_out_base / self.project_name
        dest_dir = self.build_out_base / f"{self.project_name}_{sanitizer}"

        if not src_dir.exists():
            self.log(f"Source directory not found: {src_dir}", "WARN")
            return False

        # Remove destination if exists
        if dest_dir.exists():
            shutil.rmtree(dest_dir)

        # Move
        shutil.move(str(src_dir), str(dest_dir))
        self.build_paths[sanitizer] = str(dest_dir)

        self.log(f"Moved build output to {dest_dir}")
        return True

    def _collect_fuzzers(self, sanitizer: str) -> List[str]:
        """
        Collect successfully built fuzzers from sanitizer-specific dir.

        Args:
            sanitizer: Sanitizer that was used for build

        Returns:
            List of fuzzer names
        """
        out_dir = self.build_out_base / f"{self.project_name}_{sanitizer}"

        # Check if output already exists (parallel build moved it)
        if not out_dir.exists():
            # Try to move from default location (sequential build)
            if not self._move_build_output(sanitizer):
                return []

        # Verify output directory exists
        if not out_dir.exists():
            self.log(f"Output directory not found: {out_dir}", "WARN")
            return []

        fuzzer_names = []
        for f in out_dir.iterdir():
            # Skip known non-fuzzer files
            if f.name in self.SKIP_FILES:
                continue
            if f.suffix.lower() in self.SKIP_EXTENSIONS:
                continue
            if f.is_dir():
                continue
            if not os.access(f, os.X_OK):
                continue

            fuzzer_names.append(f.name)

            # Create FuzzerInfo
            self.fuzzers.append(
                FuzzerInfo(
                    name=f.name,
                    sanitizer=sanitizer,
                    binary_path=str(f),
                    source_path=None,  # TODO: find source file
                )
            )

        self.log(f"Found {len(fuzzer_names)} fuzzers with {sanitizer}: {fuzzer_names}")
        return fuzzer_names

    def _fix_permissions(self) -> None:
        """
        Fix file permissions after Docker build.

        Docker creates files as root, this fixes ownership.
        """
        dirs_to_fix = [
            self.build_out_base,
            self.repo_path,
        ]

        uid = os.getuid()
        gid = os.getgid()

        for dir_path in dirs_to_fix:
            if dir_path and dir_path.exists():
                try:
                    subprocess.run(
                        [
                            "docker",
                            "run",
                            "--rm",
                            "-v",
                            f"{dir_path.absolute()}:/fix_perms",
                            "alpine:latest",
                            "chown",
                            "-R",
                            f"{uid}:{gid}",
                            "/fix_perms",
                        ],
                        capture_output=True,
                        timeout=120,
                    )
                except Exception:
                    pass  # Best effort

    def get_fuzzers(self) -> List[FuzzerInfo]:
        """Get all built fuzzers."""
        return self.fuzzers

    def get_build_paths(self) -> Dict[str, str]:
        """Get paths to build output directories."""
        return self.build_paths

    def get_coverage_path(self) -> Optional[str]:
        """Get path to coverage fuzzer directory."""
        return self.coverage_path

    def get_introspector_path(self) -> Optional[str]:
        """Get path to introspector output directory."""
        return self.introspector_path

    def get_fuzzer_names(self) -> List[str]:
        """Get unique fuzzer names."""
        return list(set(f.name for f in self.fuzzers))
