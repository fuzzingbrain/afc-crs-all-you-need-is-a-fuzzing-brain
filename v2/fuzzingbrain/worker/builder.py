# SPDX-License-Identifier: Apache-2.0
"""
Worker Builder

Builds fuzzer with a specific sanitizer in the worker's workspace.
This is different from the Controller's build - each worker builds
its own copy with its assigned sanitizer.

Note: Coverage fuzzer is built once by Controller and shared by all Workers.
Workers access the shared coverage fuzzer via the coverage tool.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Tuple, List

from ..core import logger
from ..builder import BuildJob, run_build
from ..builder.engine import DEFAULT_BUILD_TIMEOUT_S


class WorkerBuilder:
    """
    Builds fuzzer with a specific sanitizer.

    Each worker has its own workspace copy and builds with its assigned sanitizer.
    Coverage fuzzer is shared (built by Controller, not here).
    """

    def __init__(self, workspace_path: str, project_name: str, sanitizer: str):
        """
        Initialize WorkerBuilder.

        Args:
            workspace_path: Path to worker's workspace
            project_name: OSS-Fuzz project name
            sanitizer: Sanitizer to build with (address, memory, undefined)
        """
        self.workspace_path = Path(workspace_path)
        self.project_name = project_name
        self.sanitizer = sanitizer

        self.repo_path = self.workspace_path / "repo"
        self.fuzz_tooling_path = self.workspace_path / "fuzz-tooling"

        # Output directories
        self.results_path = self.workspace_path / "results"
        self.fuzzers_path = self.results_path / "fuzzers" / self.project_name

        # OSS-Fuzz build output directory
        self.build_out_path = (
            self.fuzz_tooling_path / "build" / "out" / self.project_name
        )

    def build(self) -> Tuple[bool, str]:
        """
        Build fuzzer with the specified sanitizer.

        Note: Coverage fuzzer is built once by Controller and shared.
        Workers access the shared coverage fuzzer via the coverage tool.

        Returns:
            (success, message)
        """
        helper_path = self.fuzz_tooling_path / "infra" / "helper.py"

        if not helper_path.exists():
            return False, f"helper.py not found: {helper_path}"

        # Ensure output directory exists
        self.fuzzers_path.mkdir(parents=True, exist_ok=True)

        # Build with specified sanitizer
        logger.info(f"Building fuzzer with {self.sanitizer} sanitizer")
        success, msg = self._build_with_sanitizer(
            helper_path, self.sanitizer, self.results_path / "build.log"
        )

        # Fix permissions after Docker build
        self._fix_build_permissions()

        if not success:
            return False, f"Build failed: {msg}"

        # Copy fuzzer to results/fuzzers/
        self._copy_build_output(self.fuzzers_path)
        logger.info(f"Fuzzer copied to {self.fuzzers_path}")

        return True, "Build successful"

    def _build_with_sanitizer(
        self, helper_path: Path, sanitizer: str, log_path: Path
    ) -> Tuple[bool, str]:
        """Build with one sanitizer (delegates to the shared build engine).

        Streams to the console and writes the per-worker build.log; the helper.py
        invocation, \\r normalization, timeout and exit-code handling all live in
        :mod:`fuzzingbrain.builder` so workers and the controller behave alike.
        """
        log_path.parent.mkdir(parents=True, exist_ok=True)
        job = BuildJob(
            fuzz_tooling_path=self.fuzz_tooling_path,
            project=self.project_name,
            src_path=self.repo_path,
            sanitizer=sanitizer,
            log_path=log_path,
            timeout_s=DEFAULT_BUILD_TIMEOUT_S,
            label=self.project_name,
        )
        from ..builder import helper_command

        logger.info(f"Build command: {' '.join(helper_command(job))}")

        def _to_console(line: str) -> None:
            sys.stdout.write(line)
            sys.stdout.flush()

        result = run_build(job, on_line=_to_console)
        if not result.ok:
            logger.error(result.message)
            return False, result.message
        logger.info(f"Build with {sanitizer} completed successfully")
        return True, result.message

    def _copy_build_output(self, dest_path: Path) -> None:
        """
        Copy build output to destination directory.

        Args:
            dest_path: Destination directory
        """
        if not self.build_out_path.exists():
            logger.warning(f"Build output not found: {self.build_out_path}")
            return

        # Clear destination if exists
        if dest_path.exists():
            shutil.rmtree(dest_path)

        # Copy all files
        shutil.copytree(self.build_out_path, dest_path)

        # Fix permissions after copy
        self._fix_permissions(dest_path)

    def _fix_permissions(self, path: Path) -> None:
        """
        Fix file permissions to current user.

        Docker creates files as root, which causes permission issues.
        This method changes ownership to the current user.

        Args:
            path: Directory to fix permissions for
        """
        if not path.exists():
            return

        uid = os.getuid()
        gid = os.getgid()

        try:
            # Try using docker to fix permissions (works without sudo)
            # This runs a container that chowns the mounted directory
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
                timeout=60,
            )
            logger.debug(f"Fixed permissions for {path}")
        except Exception as e:
            logger.warning(f"Could not fix permissions for {path}: {e}")

    def _fix_build_permissions(self) -> None:
        """
        Fix permissions for all build-related directories.

        Should be called after Docker-based builds complete.
        """
        # Directories that Docker may have created with root ownership
        dirs_to_fix = [
            self.build_out_path,
            self.fuzz_tooling_path / "build",
            self.repo_path,
        ]

        uid = os.getuid()
        gid = os.getgid()

        for dir_path in dirs_to_fix:
            if dir_path.exists():
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
                    logger.debug(f"Fixed permissions for {dir_path}")
                except Exception as e:
                    logger.warning(f"Could not fix permissions for {dir_path}: {e}")

    def get_fuzzer_path(self, fuzzer_name: str) -> Path:
        """
        Get path to built fuzzer binary (main sanitizer version).

        Args:
            fuzzer_name: Name of the fuzzer

        Returns:
            Path to fuzzer binary
        """
        return self.fuzzers_path / fuzzer_name

    def list_fuzzers(self) -> List[str]:
        """
        List all built fuzzer binaries.

        Returns:
            List of fuzzer names
        """
        if not self.fuzzers_path.exists():
            return []

        fuzzers = []
        for f in self.fuzzers_path.iterdir():
            # Skip non-executable files and common non-fuzzer files
            if f.is_file() and not f.suffix and f.name not in ["llvm-symbolizer"]:
                fuzzers.append(f.name)

        return fuzzers
