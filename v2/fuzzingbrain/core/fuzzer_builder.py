# SPDX-License-Identifier: Apache-2.0
"""
Fuzzer Builder

Builds fuzzers using OSS-Fuzz helper.py and collects the results.
The purpose is to determine how many fuzzers can be successfully built.

Also builds a shared coverage-instrumented fuzzer for dynamic analysis.
This coverage fuzzer is shared by all Workers (built once by Controller).
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple, Optional

from .logging import logger, get_log_dir
from .config import Config
from .models import Task
from ..builder import BuildJob, collect_fuzzers, run_build, truncate_output
from ..builder.engine import DEFAULT_BUILD_TIMEOUT_S


class FuzzerBuilder:
    """
    Builds fuzzers and collects results.

    Uses OSS-Fuzz helper.py to build fuzzers with address sanitizer.
    The goal is simply to know how many fuzzers are successfully built.

    Also builds a shared coverage fuzzer that all Workers can use for
    dynamic analysis (e.g., verifying if POV reaches target functions).
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

    def __init__(self, task: Task, config: Config):
        """
        Initialize FuzzerBuilder.

        Args:
            task: Task object with paths
            config: Configuration object
        """
        self.task = task
        self.config = config
        self.project_name = config.ossfuzz_project_name or task.project_name

        # Shared coverage fuzzer path (accessible by all Workers)
        self.task_path = Path(task.task_path) if task.task_path else None
        self.coverage_fuzzer_path: Optional[Path] = None
        self.static_analysis_path: Optional[Path] = None
        if self.task_path:
            self.coverage_fuzzer_path = (
                self.task_path / "results" / "coverage_fuzzer" / self.project_name
            )
            self.static_analysis_path = self.task_path / "static_analysis"

    def build(self) -> Tuple[bool, List[str], str]:
        """
        Build fuzzers.

        Build order:
        1. Build with address sanitizer (to verify which fuzzers work)
        2. Build with coverage sanitizer (shared by all Workers)
        3. Build with emit-llvm (for static analysis - call graph generation)

        Returns:
            (success, fuzzer_list, message)
        """
        logger.info(f"Building fuzzers for project: {self.project_name}")

        # Validate paths
        if not self.task.fuzz_tooling_path:
            return False, [], "fuzz_tooling_path not set"

        if not self.task.src_path:
            return False, [], "src_path not set"

        # Step 1: Run helper.py to build fuzzers with address sanitizer
        logger.info("[1/3] Building with address sanitizer")
        success, msg = self._run_helper(sanitizer="address")
        if not success:
            return False, [], msg

        # Fix permissions after Docker build
        self._fix_build_permissions()

        # Collect built fuzzers
        fuzzers = self._collect_fuzzers()
        if not fuzzers:
            return False, [], "Build succeeded but no fuzzers found in output"

        # Step 2: Build shared coverage fuzzer
        logger.info("[2/3] Building shared coverage fuzzer")
        coverage_success = self._build_coverage_fuzzer()
        if not coverage_success:
            logger.warning("Coverage fuzzer build failed, continuing without it")
        else:
            logger.info(f"Coverage fuzzer available at: {self.coverage_fuzzer_path}")

        # Step 3: Build with introspector for static analysis
        logger.info("[3/3] Running introspector for static analysis")
        introspector_success = self._build_bitcode()
        if not introspector_success:
            logger.warning("Introspector build failed, static analysis will be limited")
        else:
            logger.info(
                f"Introspector data available at: {self.static_analysis_path / 'introspector'}"
            )

        return True, fuzzers, f"Built {len(fuzzers)} fuzzers successfully"

    def _run_helper(
        self, sanitizer: str = "address", log_suffix: str = ""
    ) -> Tuple[bool, str]:
        """
        Call OSS-Fuzz helper.py to build fuzzers (delegates to the shared engine).

        Output is streamed to the console in real time and written to
        build_fuzzer{log_suffix}.log. The actual invocation, carriage-return
        normalization, timeout and exit-code handling live in
        :mod:`fuzzingbrain.builder` so every build path behaves identically.
        """
        log_dir = get_log_dir()
        build_log_path = log_dir / f"build_fuzzer{log_suffix}.log" if log_dir else None

        job = BuildJob(
            fuzz_tooling_path=Path(self.task.fuzz_tooling_path),
            project=self.project_name,
            src_path=Path(self.task.src_path),
            sanitizer=sanitizer,
            log_path=build_log_path,
            timeout_s=DEFAULT_BUILD_TIMEOUT_S,
        )
        logger.info(f"Running build command: {' '.join(self._helper_argv(job))}")

        def _to_console(line: str) -> None:
            sys.stdout.write(line)
            sys.stdout.flush()

        result = run_build(job, on_line=_to_console)

        if not result.ok:
            logger.error(result.message)
            if build_log_path:
                logger.error(f"See full log: {build_log_path}")
            return False, result.message

        logger.info("Build completed successfully")
        if build_log_path:
            logger.info(f"Build log: {build_log_path}")
        return True, result.message

    @staticmethod
    def _helper_argv(job: BuildJob) -> List[str]:
        from ..builder import helper_command

        return helper_command(job)

    def _collect_fuzzers(self) -> List[str]:
        """Scan build/out and collect built fuzzers (delegates to the engine)."""
        fuzzers = collect_fuzzers(
            Path(self.task.fuzz_tooling_path), self.project_name
        )
        logger.info(f"Collected {len(fuzzers)} fuzzers")
        return fuzzers

    def _truncate_output(self, text: str, max_lines: int = 30) -> str:
        """Truncate long output to its first 10 + last 20 lines (shared engine)."""
        return truncate_output(text)

    def get_fuzzer_binary_path(self, fuzzer_name: str) -> str:
        """
        Get the full path to a built fuzzer binary.

        Args:
            fuzzer_name: Name of the fuzzer

        Returns:
            Full path to the fuzzer binary
        """
        return str(
            Path(self.task.fuzz_tooling_path)
            / "build"
            / "out"
            / self.project_name
            / fuzzer_name
        )

    def get_coverage_fuzzer_dir(self) -> Optional[Path]:
        """
        Get the path to the shared coverage fuzzer directory.

        Returns:
            Path to coverage fuzzer directory, or None if not built
        """
        if self.coverage_fuzzer_path and self.coverage_fuzzer_path.exists():
            return self.coverage_fuzzer_path
        return None

    def _build_coverage_fuzzer(self) -> bool:
        """
        Build coverage-instrumented fuzzer and copy to shared location.

        Returns:
            True if successful, False otherwise
        """
        if not self.coverage_fuzzer_path:
            logger.warning("Coverage fuzzer path not set")
            return False

        # Build with coverage sanitizer
        success, msg = self._run_helper(sanitizer="coverage", log_suffix="_coverage")

        # Fix permissions after Docker build
        self._fix_build_permissions()

        if not success:
            logger.error(f"Coverage build failed: {msg}")
            return False

        # Copy to shared location
        self._copy_build_output(self.coverage_fuzzer_path)
        return True

    def _copy_build_output(self, dest_path: Path) -> None:
        """
        Copy build output to destination directory.

        Args:
            dest_path: Destination directory
        """
        out_dir = (
            Path(self.task.fuzz_tooling_path) / "build" / "out" / self.project_name
        )

        if not out_dir.exists():
            logger.warning(f"Build output not found: {out_dir}")
            return

        # Clear destination if exists
        if dest_path.exists():
            shutil.rmtree(dest_path)

        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Copy all files
        shutil.copytree(out_dir, dest_path)

        # Fix permissions after copy
        self._fix_permissions(dest_path)

        logger.info(f"Copied build output to {dest_path}")

    def _fix_build_permissions(self) -> None:
        """
        Fix permissions for build-related directories.

        Docker creates files as root, which causes permission issues.
        This method uses a Docker container to chown the files.
        """
        # Directories that Docker may have created with root ownership
        dirs_to_fix = [
            Path(self.task.fuzz_tooling_path) / "build",
            Path(self.task.src_path) if self.task.src_path else None,
        ]

        for dir_path in dirs_to_fix:
            if dir_path and dir_path.exists():
                self._fix_permissions(dir_path)

    def _fix_permissions(self, path: Path) -> None:
        """
        Fix file permissions to current user using Docker.

        Args:
            path: Directory to fix permissions for
        """
        if not path.exists():
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
                    f"{path.absolute()}:/fix_perms",
                    "alpine:latest",
                    "chown",
                    "-R",
                    f"{uid}:{gid}",
                    "/fix_perms",
                ],
                capture_output=True,
                timeout=120,
            )
            logger.debug(f"Fixed permissions for {path}")
        except Exception as e:
            logger.warning(f"Could not fix permissions for {path}: {e}")

    def _build_bitcode(self) -> bool:
        """
        Build with introspector to get static analysis data.

        Uses OSS-Fuzz introspector sanitizer which generates function
        reachability data in JSON format. This provides:
        - All functions reachable from each fuzzer
        - Call depth information
        - Source file and line numbers
        - Call graph edges (callsites)

        Returns:
            True if successful, False otherwise
        """
        if not self.static_analysis_path:
            logger.warning("Static analysis path not set")
            return False

        # Create static_analysis directory structure
        introspector_dir = self.static_analysis_path / "introspector"
        reachable_dir = self.static_analysis_path / "reachable"

        for d in [introspector_dir, reachable_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # Build with introspector sanitizer
        success, msg = self._run_helper(
            sanitizer="introspector", log_suffix="_introspector"
        )

        # Fix permissions after Docker build
        self._fix_build_permissions()

        if not success:
            logger.error(f"Introspector build failed: {msg}")
            return False

        # Collect introspector output files
        collected = self._collect_introspector_files(introspector_dir)
        if not collected:
            logger.warning("No introspector files generated")
            return False

        logger.info(f"Collected {len(collected)} introspector files")
        return True

    def _collect_introspector_files(self, dest_dir: Path) -> List[Path]:
        """
        Collect introspector output files from build output.

        Copies the key introspector JSON files that contain function
        reachability and call graph information.

        Args:
            dest_dir: Destination directory for introspector files

        Returns:
            List of collected file paths
        """
        out_dir = (
            Path(self.task.fuzz_tooling_path) / "build" / "out" / self.project_name
        )
        inspector_dir = out_dir / "inspector"

        if not inspector_dir.exists():
            logger.warning(f"Inspector directory not found: {inspector_dir}")
            return []

        collected = []

        # Key files to collect
        key_files = [
            "all-fuzz-introspector-functions.json",  # All reachable functions
            "summary.json",  # Summary statistics
            "all_debug_info.json",  # Debug info
        ]

        for filename in key_files:
            src_file = inspector_dir / filename
            if src_file.exists():
                dest_file = dest_dir / filename
                try:
                    shutil.copy2(src_file, dest_file)
                    collected.append(dest_file)
                    logger.debug(f"Collected introspector file: {filename}")
                except Exception as e:
                    logger.warning(f"Failed to copy {filename}: {e}")

        # Also copy fuzzer-specific YAML files
        for yaml_file in inspector_dir.glob("fuzzerLogFile-*.data.yaml"):
            dest_file = dest_dir / yaml_file.name
            try:
                shutil.copy2(yaml_file, dest_file)
                collected.append(dest_file)
            except Exception as e:
                logger.warning(f"Failed to copy {yaml_file.name}: {e}")

        return collected

    def get_introspector_dir(self) -> Optional[Path]:
        """
        Get the path to the introspector output directory.

        Returns:
            Path to introspector directory, or None if not available
        """
        if self.static_analysis_path:
            introspector_dir = self.static_analysis_path / "introspector"
            if introspector_dir.exists():
                return introspector_dir
        return None

    def get_bitcode_dir(self) -> Optional[Path]:
        """
        Get the path to the bitcode directory.

        Deprecated: Use get_introspector_dir() instead.
        Returns introspector directory for backwards compatibility.
        """
        return self.get_introspector_dir()

    def get_static_analysis_path(self) -> Optional[Path]:
        """
        Get the path to the static analysis directory.

        Returns:
            Path to static_analysis directory, or None if not set
        """
        return self.static_analysis_path

    def get_callgraph_dir(self) -> Optional[Path]:
        """
        Get the path to the call graph directory.

        Returns:
            Path to callgraph directory, or None if not available
        """
        if self.static_analysis_path:
            callgraph_dir = self.static_analysis_path / "callgraph"
            if callgraph_dir.exists():
                return callgraph_dir
        return None

    def get_reachable_dir(self) -> Optional[Path]:
        """
        Get the path to the reachable functions directory.

        Returns:
            Path to reachable directory, or None if not available
        """
        if self.static_analysis_path:
            reachable_dir = self.static_analysis_path / "reachable"
            if reachable_dir.exists():
                return reachable_dir
        return None
