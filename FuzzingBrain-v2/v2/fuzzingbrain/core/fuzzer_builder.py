"""
Fuzzer Builder

Builds fuzzers using OSS-Fuzz helper.py and collects the results.
The purpose is to determine how many fuzzers can be successfully built.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

from .logging import logger, get_log_dir
from .config import Config
from .models import Task


class FuzzerBuilder:
    """
    Builds fuzzers and collects results.

    Uses OSS-Fuzz helper.py to build fuzzers with address sanitizer.
    The goal is simply to know how many fuzzers are successfully built.
    """

    # Files to skip when scanning build output
    SKIP_FILES = {
        "llvm-symbolizer", "sancov", "clang", "clang++",
        "llvm-cov", "llvm-profdata", "llvm-ar",
    }

    # Extensions to skip
    SKIP_EXTENSIONS = {
        ".bin", ".log", ".dict", ".options", ".bc", ".json",
        ".o", ".a", ".so", ".h", ".c", ".cpp", ".cc", ".py",
        ".sh", ".txt", ".md", ".zip", ".tar", ".gz",
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
        self.project_name = config.ossfuzz_project or task.project_name

    def build(self) -> Tuple[bool, List[str], str]:
        """
        Build fuzzers.

        Returns:
            (success, fuzzer_list, message)
        """
        logger.info(f"Building fuzzers for project: {self.project_name}")

        # Validate paths
        if not self.task.fuzz_tooling_path:
            return False, [], "fuzz_tooling_path not set"

        if not self.task.src_path:
            return False, [], "src_path not set"

        # 1. Run helper.py to build fuzzers
        success, msg = self._run_helper()
        if not success:
            return False, [], msg

        # 2. Collect built fuzzers
        fuzzers = self._collect_fuzzers()
        if not fuzzers:
            return False, [], "Build succeeded but no fuzzers found in output"

        return True, fuzzers, f"Built {len(fuzzers)} fuzzers successfully"

    def _run_helper(self) -> Tuple[bool, str]:
        """
        Call OSS-Fuzz helper.py to build fuzzers.

        Output is:
        - Streamed to console in real-time
        - Written to build_fuzzer.log in the log directory

        Returns:
            (success, message)
        """
        helper_path = Path(self.task.fuzz_tooling_path) / "infra" / "helper.py"

        if not helper_path.exists():
            return False, f"helper.py not found: {helper_path}"

        # Build command
        cmd = [
            "python3", str(helper_path),
            "build_fuzzers",
            "--sanitizer", "address",
            "--engine", "libfuzzer",
            self.project_name,
            str(Path(self.task.src_path).absolute()),
        ]

        logger.info(f"Running build command: {' '.join(cmd)}")

        # Setup build log file
        log_dir = get_log_dir()
        build_log_path = log_dir / "build_fuzzer.log" if log_dir else None

        try:
            # Open log file if available
            build_log_file = open(build_log_path, "w", encoding="utf-8") if build_log_path else None

            if build_log_file:
                build_log_file.write(f"Build Command: {' '.join(cmd)}\n")
                build_log_file.write("=" * 80 + "\n\n")

            # Run with real-time output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(Path(self.task.fuzz_tooling_path)),
            )

            # Stream output to console and log file
            output_lines = []
            for line in process.stdout:
                # Write to console
                sys.stdout.write(line)
                sys.stdout.flush()

                # Write to log file
                if build_log_file:
                    build_log_file.write(line)

                output_lines.append(line)

            process.wait(timeout=1800)  # 30 minutes

            if build_log_file:
                build_log_file.write("\n" + "=" * 80 + "\n")
                build_log_file.write(f"Exit code: {process.returncode}\n")
                build_log_file.close()

            if process.returncode != 0:
                error = self._truncate_output("".join(output_lines[-50:]))
                logger.error(f"Build failed with code {process.returncode}")
                if build_log_path:
                    logger.error(f"See full log: {build_log_path}")
                return False, f"Build failed (code {process.returncode})"

            logger.info("Build completed successfully")
            if build_log_path:
                logger.info(f"Build log: {build_log_path}")
            return True, "Build successful"

        except subprocess.TimeoutExpired:
            process.kill()
            logger.error("Build timed out after 30 minutes")
            return False, "Build timed out (30 minutes)"
        except Exception as e:
            logger.exception(f"Build failed with exception: {e}")
            return False, str(e)
        finally:
            if build_log_file and not build_log_file.closed:
                build_log_file.close()

    def _collect_fuzzers(self) -> List[str]:
        """
        Scan build/out directory and collect successfully built fuzzers.

        Returns:
            List of fuzzer names
        """
        out_dir = Path(self.task.fuzz_tooling_path) / "build" / "out" / self.project_name

        if not out_dir.exists():
            logger.warning(f"Output directory not found: {out_dir}")
            return []

        fuzzers = []
        for f in out_dir.iterdir():
            # Skip known non-fuzzer files
            if f.name in self.SKIP_FILES:
                continue

            # Skip by extension
            if f.suffix.lower() in self.SKIP_EXTENSIONS:
                continue

            # Skip directories
            if f.is_dir():
                continue

            # Must be executable
            if not os.access(f, os.X_OK):
                continue

            fuzzers.append(f.name)
            logger.debug(f"Found fuzzer: {f.name}")

        logger.info(f"Collected {len(fuzzers)} fuzzers from {out_dir}")
        return fuzzers

    def _truncate_output(self, text: str, max_lines: int = 30) -> str:
        """
        Truncate long output, keeping first 10 and last 20 lines.

        Args:
            text: Text to truncate
            max_lines: Maximum lines to keep

        Returns:
            Truncated text
        """
        if not text:
            return ""

        lines = text.strip().split('\n')
        if len(lines) <= max_lines:
            return text

        first = lines[:10]
        last = lines[-20:]
        truncated = len(lines) - 30

        return '\n'.join(first + [f"\n... [{truncated} lines truncated] ...\n"] + last)

    def get_fuzzer_binary_path(self, fuzzer_name: str) -> str:
        """
        Get the full path to a built fuzzer binary.

        Args:
            fuzzer_name: Name of the fuzzer

        Returns:
            Full path to the fuzzer binary
        """
        return str(
            Path(self.task.fuzz_tooling_path) / "build" / "out" / self.project_name / fuzzer_name
        )
