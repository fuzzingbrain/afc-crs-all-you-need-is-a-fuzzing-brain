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
        self.build_out_path = self.fuzz_tooling_path / "build" / "out" / self.project_name

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
            helper_path,
            self.sanitizer,
            self.results_path / "build.log"
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
        self,
        helper_path: Path,
        sanitizer: str,
        log_path: Path
    ) -> Tuple[bool, str]:
        """
        Build fuzzer with a specific sanitizer.

        Args:
            helper_path: Path to helper.py
            sanitizer: Sanitizer type (address, memory, undefined, coverage)
            log_path: Path to write build log

        Returns:
            (success, message)
        """
        cmd = [
            "python3", str(helper_path),
            "build_fuzzers",
            "--sanitizer", sanitizer,
            "--engine", "libfuzzer",
            self.project_name,
            str(self.repo_path.absolute()),
        ]

        logger.info(f"Build command: {' '.join(cmd)}")

        log_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(log_path, "w", encoding="utf-8") as log_file:
                log_file.write(f"Build Command: {' '.join(cmd)}\n")
                log_file.write(f"Sanitizer: {sanitizer}\n")
                log_file.write("=" * 80 + "\n\n")

                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=str(self.fuzz_tooling_path),
                )

                ended_with_newline = True
                for raw_line in process.stdout:
                    # Docker/oss-fuzz often emits carriage-return updates; normalize to newlines to avoid smashed console output
                    line = raw_line.replace("\r", "\n")
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    log_file.write(line)
                    ended_with_newline = line.endswith("\n")

                # Ensure the next log line starts cleanly
                if not ended_with_newline:
                    sys.stdout.write("\n")
                    log_file.write("\n")

                process.wait(timeout=1800)  # 30 minutes

                log_file.write("\n" + "=" * 80 + "\n")
                log_file.write(f"Exit code: {process.returncode}\n")

            if process.returncode != 0:
                logger.error(f"Build failed with code {process.returncode}")
                return False, f"Build failed (code {process.returncode})"

            logger.info(f"Build with {sanitizer} completed successfully")
            return True, "Build successful"

        except subprocess.TimeoutExpired:
            process.kill()
            logger.error("Build timed out")
            return False, "Build timed out (30 minutes)"
        except Exception as e:
            logger.exception(f"Build failed: {e}")
            return False, str(e)

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
                    "docker", "run", "--rm",
                    "-v", f"{path.absolute()}:/fix_perms",
                    "alpine:latest",
                    "chown", "-R", f"{uid}:{gid}", "/fix_perms"
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
                            "docker", "run", "--rm",
                            "-v", f"{dir_path.absolute()}:/fix_perms",
                            "alpine:latest",
                            "chown", "-R", f"{uid}:{gid}", "/fix_perms"
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
