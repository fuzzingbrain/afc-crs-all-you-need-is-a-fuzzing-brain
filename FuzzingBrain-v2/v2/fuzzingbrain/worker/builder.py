"""
Worker Builder

Builds fuzzer with a specific sanitizer in the worker's workspace.
This is different from the Controller's build - each worker builds
its own copy with its assigned sanitizer.
"""

import subprocess
import sys
from pathlib import Path
from typing import Tuple

from ..core import logger


class WorkerBuilder:
    """
    Builds fuzzer with a specific sanitizer.

    Each worker has its own workspace copy and builds with its assigned sanitizer.
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

    def build(self) -> Tuple[bool, str]:
        """
        Build fuzzer with the specified sanitizer.

        Returns:
            (success, message)
        """
        logger.info(f"Building fuzzer with {self.sanitizer} sanitizer")

        helper_path = self.fuzz_tooling_path / "infra" / "helper.py"

        if not helper_path.exists():
            return False, f"helper.py not found: {helper_path}"

        cmd = [
            "python3", str(helper_path),
            "build_fuzzers",
            "--sanitizer", self.sanitizer,
            "--engine", "libfuzzer",
            self.project_name,
            str(self.repo_path.absolute()),
        ]

        logger.info(f"Build command: {' '.join(cmd)}")

        # Setup build log
        build_log_path = self.workspace_path / "results" / "build.log"
        build_log_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(build_log_path, "w", encoding="utf-8") as log_file:
                log_file.write(f"Build Command: {' '.join(cmd)}\n")
                log_file.write(f"Sanitizer: {self.sanitizer}\n")
                log_file.write("=" * 80 + "\n\n")

                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=str(self.fuzz_tooling_path),
                )

                for line in process.stdout:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    log_file.write(line)

                process.wait(timeout=1800)  # 30 minutes

                log_file.write("\n" + "=" * 80 + "\n")
                log_file.write(f"Exit code: {process.returncode}\n")

            if process.returncode != 0:
                logger.error(f"Build failed with code {process.returncode}")
                return False, f"Build failed (code {process.returncode})"

            logger.info("Build completed successfully")
            return True, "Build successful"

        except subprocess.TimeoutExpired:
            process.kill()
            logger.error("Build timed out")
            return False, "Build timed out (30 minutes)"
        except Exception as e:
            logger.exception(f"Build failed: {e}")
            return False, str(e)

    def get_fuzzer_path(self, fuzzer_name: str) -> Path:
        """Get path to built fuzzer binary."""
        return self.fuzz_tooling_path / "build" / "out" / self.project_name / fuzzer_name
