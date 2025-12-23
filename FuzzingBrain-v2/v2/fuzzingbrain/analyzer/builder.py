"""
Analyzer Builder

Builds fuzzers with all sanitizers in a single pass.
Output is organized as: out/{project}_{sanitizer}/

This replaces the old fuzzer_builder.py approach where Controller
and Workers would each build separately.
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Tuple, Dict, Optional

from loguru import logger as loguru_logger

from .models import FuzzerInfo


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
        "llvm-symbolizer", "sancov", "clang", "clang++",
        "llvm-cov", "llvm-profdata", "llvm-ar",
    }

    # Extensions to skip
    SKIP_EXTENSIONS = {
        ".bin", ".log", ".dict", ".options", ".bc", ".json",
        ".o", ".a", ".so", ".h", ".c", ".cpp", ".cc", ".py",
        ".sh", ".txt", ".md", ".zip", ".tar", ".gz",
    }

    def __init__(
        self,
        task_path: str,
        project_name: str,
        sanitizers: List[str],
        ossfuzz_project: Optional[str] = None,
        log_callback=None,
    ):
        """
        Initialize AnalyzerBuilder.

        Args:
            task_path: Path to task workspace (contains repo/, fuzz-tooling/)
            project_name: Project name
            sanitizers: List of sanitizers to build (e.g., ["address", "memory"])
            ossfuzz_project: OSS-Fuzz project name if different from project_name
            log_callback: Optional callback for logging (func(msg, level))
        """
        self.task_path = Path(task_path)
        self.project_name = ossfuzz_project or project_name
        self.sanitizers = sanitizers
        self.log_callback = log_callback or self._default_log

        self.repo_path = self.task_path / "repo"
        self.fuzz_tooling_path = self.task_path / "fuzz-tooling"
        self.build_out_base = self.fuzz_tooling_path / "build" / "out"

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

    def build_all(self) -> Tuple[bool, str]:
        """
        Build fuzzers with all sanitizers.

        Build order:
        1. Build with each user-specified sanitizer
        2. Build with coverage (for C/C++)
        3. Build with introspector (for static analysis)

        Returns:
            (success, message)
        """
        start_time = time.time()

        # Validate paths
        if not self.fuzz_tooling_path.exists():
            return False, f"fuzz-tooling not found: {self.fuzz_tooling_path}"

        helper_path = self.fuzz_tooling_path / "infra" / "helper.py"
        if not helper_path.exists():
            return False, f"helper.py not found: {helper_path}"

        total_steps = len(self.sanitizers) + 2  # sanitizers + coverage + introspector
        current_step = 0

        # Step 1-N: Build with each sanitizer
        for sanitizer in self.sanitizers:
            current_step += 1
            self.log(f"[{current_step}/{total_steps}] Building with {sanitizer} sanitizer")

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
            self.coverage_path = str(self.build_out_base / f"{self.project_name}_coverage")
        else:
            self.log("Coverage build failed, continuing without it", "WARN")

        # Step N+2: Build introspector
        current_step += 1
        self.log(f"[{current_step}/{total_steps}] Building with introspector")
        introspector_success, _ = self._build_sanitizer("introspector")
        if introspector_success:
            self._move_build_output("introspector")
            self.introspector_path = str(self.build_out_base / f"{self.project_name}_introspector")
        else:
            self.log("Introspector build failed, static analysis will be limited", "WARN")

        elapsed = time.time() - start_time
        self.log(f"Build completed in {elapsed:.1f}s. {len(self.fuzzers)} fuzzers available.")

        return True, f"Built {len(self.fuzzers)} fuzzers in {elapsed:.1f}s"

    def _build_sanitizer(self, sanitizer: str) -> Tuple[bool, str]:
        """
        Build with a specific sanitizer.

        Args:
            sanitizer: Sanitizer type (address, memory, undefined, coverage, introspector)

        Returns:
            (success, message)
        """
        helper_path = self.fuzz_tooling_path / "infra" / "helper.py"

        cmd = [
            "python3", str(helper_path),
            "build_fuzzers",
            "--sanitizer", sanitizer,
            "--engine", "libfuzzer",
            self.project_name,
            str(self.repo_path.absolute()),
        ]

        self.log(f"Running: {' '.join(cmd)}")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(self.fuzz_tooling_path),
            )

            # Stream output
            for line in process.stdout:
                # Normalize carriage returns
                line = line.replace("\r", "\n").rstrip("\n")
                if line:
                    sys.stdout.write(line + "\n")
                    sys.stdout.flush()

            process.wait(timeout=1800)  # 30 minutes

            # Fix permissions after Docker build
            self._fix_permissions()

            if process.returncode != 0:
                return False, f"Build failed with code {process.returncode}"

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
        Collect successfully built fuzzers and move to sanitizer-specific dir.

        Args:
            sanitizer: Sanitizer that was used for build

        Returns:
            List of fuzzer names
        """
        # First move the build output
        if not self._move_build_output(sanitizer):
            return []

        out_dir = self.build_out_base / f"{self.project_name}_{sanitizer}"

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
            self.fuzzers.append(FuzzerInfo(
                name=f.name,
                sanitizer=sanitizer,
                binary_path=str(f),
                source_path=None,  # TODO: find source file
            ))

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
                            "docker", "run", "--rm",
                            "-v", f"{dir_path.absolute()}:/fix_perms",
                            "alpine:latest",
                            "chown", "-R", f"{uid}:{gid}", "/fix_perms"
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
