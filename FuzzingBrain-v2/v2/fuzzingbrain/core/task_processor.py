"""
Task Processor

Core business logic for processing FuzzingBrain tasks.
This module handles:
1. Workspace setup and validation
2. Repository cloning/setup
3. Fuzzer discovery and building
4. Task dispatch to workers
"""

import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple

from bson import ObjectId

from .logging import logger, create_final_summary, WorkerColors, get_log_dir
from .config import Config
from .models import Task, TaskStatus, Fuzzer, FuzzerStatus
from ..db import RepositoryManager


class WorkspaceSetup:
    """Handles workspace creation and validation"""

    def __init__(self, config: Config, task: Task):
        self.config = config
        self.task = task

    def setup(self) -> Tuple[bool, str]:
        """
        Setup workspace for the task.

        When --workspace is provided (from FuzzingBrain.sh), use it directly.
        Otherwise, create a new workspace under ./workspace/

        Returns:
            (success, message)
        """
        try:
            if self.config.workspace:
                # Workspace already created by shell script, use it directly
                task_workspace = Path(self.config.workspace)
                logger.info(f"Using existing workspace: {task_workspace}")
            else:
                # Create new workspace (API/MCP mode)
                workspace_root = Path("workspace")
                project_name = self.task.project_name or "unknown"
                task_workspace = (
                    workspace_root / f"{project_name}_{self.task.task_id[:8]}"
                )
                task_workspace.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created workspace: {task_workspace}")

            # Ensure subdirectories exist
            (task_workspace / "repo").mkdir(exist_ok=True)
            (task_workspace / "results").mkdir(exist_ok=True)
            (task_workspace / "results" / "povs").mkdir(exist_ok=True)
            (task_workspace / "results" / "patches").mkdir(exist_ok=True)
            (task_workspace / "logs").mkdir(exist_ok=True)

            # Update task paths
            self.task.task_path = str(task_workspace)
            self.task.src_path = str(task_workspace / "repo")

            logger.info(f"Workspace setup complete: {task_workspace}")
            return True, str(task_workspace)

        except Exception as e:
            logger.error(f"Failed to setup workspace: {e}")
            return False, str(e)

    def clone_repository(self) -> Tuple[bool, str]:
        """
        Clone the repository if repo_url is provided.

        Returns:
            (success, message)
        """
        if not self.config.repo_url:
            # Repo already cloned by FuzzingBrain.sh or using existing workspace
            logger.info("Repository already available, skipping clone")
            return True, "Skipped"

        repo_path = Path(self.task.src_path)

        # Check if already cloned
        if (repo_path / ".git").exists():
            logger.info(f"Repository already exists at {repo_path}")
            return True, "Already exists"

        try:
            logger.info(f"Cloning {self.config.repo_url} to {repo_path}")
            result = subprocess.run(
                ["git", "clone", "--depth", "1", self.config.repo_url, str(repo_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                logger.error(f"Git clone failed: {result.stderr}")
                return False, result.stderr

            logger.info("Repository cloned successfully")
            return True, "Cloned"

        except subprocess.TimeoutExpired:
            logger.error("Git clone timed out")
            return False, "Clone timed out"
        except Exception as e:
            logger.error(f"Failed to clone repository: {e}")
            return False, str(e)

    def setup_fuzz_tooling(self) -> Tuple[bool, str]:
        """
        Setup fuzz-tooling directory.

        Returns:
            (success, message)
        """
        task_workspace = Path(self.task.task_path)
        fuzz_tooling_path = task_workspace / "fuzz-tooling"

        if self.config.fuzz_tooling_url:
            # Clone fuzz-tooling from URL (or use existing)
            try:
                if fuzz_tooling_path.exists():
                    # Check if .git exists - if not, remove and re-clone
                    if not (fuzz_tooling_path / ".git").exists():
                        logger.warning(
                            "Fuzz-tooling missing .git directory, re-cloning..."
                        )
                        shutil.rmtree(fuzz_tooling_path)
                    else:
                        logger.info("Fuzz-tooling directory exists, skipping clone")

                if not fuzz_tooling_path.exists():
                    logger.info(
                        f"Cloning fuzz-tooling from {self.config.fuzz_tooling_url}"
                    )
                    result = subprocess.run(
                        [
                            "git",
                            "clone",
                            "--depth",
                            "1",
                            self.config.fuzz_tooling_url,
                            str(fuzz_tooling_path),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=300,
                    )

                    if result.returncode != 0:
                        logger.error(f"Fuzz-tooling clone failed: {result.stderr}")
                        return False, result.stderr

                # Checkout to specific ref if provided
                fuzz_tooling_ref = getattr(self.config, "fuzz_tooling_ref", None)
                if fuzz_tooling_ref:
                    logger.info(f"Checking out fuzz-tooling to ref: {fuzz_tooling_ref}")
                    # Fetch the ref first (needed for shallow clones)
                    subprocess.run(
                        ["git", "fetch", "--depth", "1", "origin", fuzz_tooling_ref],
                        cwd=str(fuzz_tooling_path),
                        capture_output=True,
                        timeout=120,
                    )
                    # Force checkout FETCH_HEAD (shallow clone may have different files on default branch)
                    result = subprocess.run(
                        ["git", "checkout", "-f", "FETCH_HEAD"],
                        cwd=str(fuzz_tooling_path),
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    if result.returncode != 0:
                        logger.warning(
                            f"Fuzz-tooling checkout warning: {result.stderr}"
                        )

                self.task.fuzz_tooling_path = str(fuzz_tooling_path)
                self.task.is_fuzz_tooling_provided = True
                return True, "Ready"

            except Exception as e:
                logger.error(f"Failed to setup fuzz-tooling: {e}")
                return False, str(e)

        elif self.config.fuzz_tooling_path:
            # Copy from local path
            try:
                source = Path(self.config.fuzz_tooling_path)
                if source.exists():
                    shutil.copytree(source, fuzz_tooling_path, dirs_exist_ok=True)
                    self.task.fuzz_tooling_path = str(fuzz_tooling_path)
                    self.task.is_fuzz_tooling_provided = True
                    return True, "Copied"
                else:
                    return False, f"Fuzz-tooling path not found: {source}"

            except Exception as e:
                logger.error(f"Failed to copy fuzz-tooling: {e}")
                return False, str(e)

        else:
            # Check if fuzz-tooling exists in workspace (set up by FuzzingBrain.sh)
            if fuzz_tooling_path.exists() and (fuzz_tooling_path / "projects").exists():
                self.task.fuzz_tooling_path = str(fuzz_tooling_path)
                self.task.is_fuzz_tooling_provided = True
                return True, "Found existing"

            # No fuzz-tooling provided
            logger.warning(
                "No fuzz-tooling found. Current version only supports OSS-Fuzz based projects."
            )
            logger.warning(
                "Please ensure the project exists in OSS-Fuzz or provide --fuzz-tooling-url"
            )
            return True, "Not provided"


class FuzzerDiscovery:
    """
    Multi-layer fuzzer discovery.

    Layer 1: Pattern matching (fuzz_*.c, *_fuzzer.c, etc.)
    Layer 2: LLVMFuzzerTestOneInput function search
    Layer 3: Analyzer result fallback (handled in TaskProcessor)
    """

    # Common fuzzer file patterns
    FUZZER_PATTERNS = [
        "fuzz_*.c",
        "fuzz_*.cc",
        "fuzz_*.cpp",
        "*_fuzzer.c",
        "*_fuzzer.cc",
        "*_fuzzer.cpp",
        "fuzzer_*.c",
        "fuzzer_*.cc",
        "fuzzer_*.cpp",
    ]

    def __init__(self, task: Task, config: Config, repos: RepositoryManager):
        self.task = task
        self.config = config
        self.repos = repos

    def discover_fuzzers(self) -> List[Fuzzer]:
        """
        Discover fuzzer source files using multi-layer approach.

        Layer 1: Pattern matching on filenames
        Layer 2: Search for LLVMFuzzerTestOneInput function

        Returns:
            List of Fuzzer objects
        """
        fuzzers = []
        seen_names = set()

        # Layer 1: Pattern matching
        logger.info("Layer 1: Pattern matching for fuzzers")
        self._discover_by_pattern(fuzzers, seen_names)

        if fuzzers:
            logger.info(f"Layer 1 found {len(fuzzers)} fuzzers")
            return fuzzers

        # Layer 2: LLVMFuzzerTestOneInput search
        logger.info(
            "Layer 1 found nothing, trying Layer 2: LLVMFuzzerTestOneInput search"
        )
        self._discover_by_entry_point(fuzzers, seen_names)

        if fuzzers:
            logger.info(f"Layer 2 found {len(fuzzers)} fuzzers")

        return fuzzers

    def _discover_by_pattern(self, fuzzers: List[Fuzzer], seen_names: set):
        """Layer 1: Pattern matching on filenames"""
        # Search in OSS-Fuzz project directory
        if self.task.fuzz_tooling_path:
            fuzz_tooling = Path(self.task.fuzz_tooling_path)
            ossfuzz_project = self.config.ossfuzz_project_name or self.task.project_name
            if ossfuzz_project:
                project_dir = fuzz_tooling / "projects" / ossfuzz_project
                if project_dir.exists():
                    for pattern in self.FUZZER_PATTERNS:
                        for fuzzer_file in project_dir.glob(pattern):
                            self._add_fuzzer(
                                fuzzers, seen_names, fuzzer_file, project_dir
                            )

        # Search in source repo
        if self.task.src_path:
            repo_path = Path(self.task.src_path)
            if repo_path.exists():
                for pattern in self.FUZZER_PATTERNS:
                    for fuzzer_file in repo_path.glob(f"**/{pattern}"):
                        self._add_fuzzer(fuzzers, seen_names, fuzzer_file, repo_path)

    def _discover_by_entry_point(self, fuzzers: List[Fuzzer], seen_names: set):
        """Layer 2: Search for LLVMFuzzerTestOneInput function"""
        import subprocess

        search_paths = []

        # Add OSS-Fuzz project directory
        if self.task.fuzz_tooling_path:
            fuzz_tooling = Path(self.task.fuzz_tooling_path)
            ossfuzz_project = self.config.ossfuzz_project_name or self.task.project_name
            if ossfuzz_project:
                project_dir = fuzz_tooling / "projects" / ossfuzz_project
                if project_dir.exists():
                    search_paths.append(project_dir)

        # Add source repo
        if self.task.src_path:
            repo_path = Path(self.task.src_path)
            if repo_path.exists():
                search_paths.append(repo_path)

        for search_path in search_paths:
            try:
                # Use grep to find files containing LLVMFuzzerTestOneInput
                result = subprocess.run(
                    [
                        "grep",
                        "-rl",
                        "--include=*.c",
                        "--include=*.cc",
                        "--include=*.cpp",
                        "LLVMFuzzerTestOneInput",
                        str(search_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().split("\n"):
                        fuzzer_file = Path(line.strip())
                        if fuzzer_file.exists():
                            self._add_fuzzer(
                                fuzzers, seen_names, fuzzer_file, search_path
                            )

            except subprocess.TimeoutExpired:
                logger.warning(f"Grep timeout searching in {search_path}")
            except Exception as e:
                logger.warning(f"Grep failed in {search_path}: {e}")

    def _add_fuzzer(
        self,
        fuzzers: List[Fuzzer],
        seen_names: set,
        fuzzer_file: Path,
        search_path: Path,
    ):
        """Add a fuzzer to the list if not already seen"""
        fuzzer_name = fuzzer_file.stem
        if fuzzer_name in seen_names:
            return
        seen_names.add(fuzzer_name)

        try:
            rel_path = str(fuzzer_file.relative_to(search_path))
        except ValueError:
            rel_path = str(fuzzer_file)

        fuzzer = Fuzzer(
            task_id=self.task.task_id,
            fuzzer_name=fuzzer_name,
            source_path=rel_path,
            repo_name=self.task.project_name,
            status=FuzzerStatus.PENDING,
        )
        fuzzers.append(fuzzer)
        logger.info(f"Discovered fuzzer: {fuzzer_name} ({fuzzer_file})")

    def save_fuzzers(self, fuzzers: List[Fuzzer]):
        """Save discovered fuzzers to database"""
        for fuzzer in fuzzers:
            self.repos.fuzzers.save(fuzzer)
            logger.debug(f"Saved fuzzer: {fuzzer.fuzzer_name}")


class TaskProcessor:
    """
    Main task processor.

    Orchestrates the task processing pipeline:
    1. Setup workspace
    2. Clone repository
    3. Discover fuzzers
    4. Build fuzzers (TODO)
    5. Dispatch workers (TODO)
    """

    def __init__(self, config: Config, repos: RepositoryManager):
        """
        Initialize task processor

        Args:
            config: Configuration object
            repos: RepositoryManager instance (passed from main.py)
        """
        self.config = config
        self.repos = repos

    def _get_commit_hash(self) -> Optional[str]:
        """
        Get the current commit hash from the repo directory.

        Returns:
            Commit hash string or None if not available
        """
        try:
            # Try to get commit from workspace repo
            repo_path = None
            if self.config.workspace:
                repo_path = Path(self.config.workspace) / "repo"
            elif self.config.repo_path:
                repo_path = Path(self.config.repo_path)

            if repo_path and (repo_path / ".git").exists():
                result = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    return result.stdout.strip()

            # Try fuzz-tooling repo as fallback (for OSS-Fuzz projects)
            if self.config.workspace:
                fuzz_tooling = Path(self.config.workspace) / "fuzz-tooling"
                if (fuzz_tooling / ".git").exists():
                    result = subprocess.run(
                        ["git", "rev-parse", "HEAD"],
                        cwd=fuzz_tooling,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if result.returncode == 0:
                        return result.stdout.strip()

            return None

        except Exception as e:
            logger.debug(f"Failed to get commit hash: {e}")
            return None

    def _log_fuzzer_summary(self, fuzzers: List[Fuzzer], project_name: str):
        """Log a formatted summary of fuzzer build results"""
        success_count = sum(1 for f in fuzzers if f.status == FuzzerStatus.SUCCESS)
        total_count = len(fuzzers)

        # Calculate box width
        lines = []
        for f in fuzzers:
            lines.append(f"  Binary Path:  {f.binary_path or 'N/A'}")
            lines.append(f"  Source Path:  {f.source_path or 'N/A'}")
            lines.append(f"  Status:       {f.status.value}")

        width = max(len(line) for line in lines) + 4 if lines else 60
        width = max(width, 60)

        # Build the box
        box_lines = []
        box_lines.append("")
        box_lines.append("┌" + "─" * width + "┐")

        # Header
        header = f" {project_name} - Built {success_count}/{total_count} fuzzers "
        box_lines.append("│" + header.center(width) + "│")
        box_lines.append("├" + "─" * width + "┤")

        # Each fuzzer
        for i, f in enumerate(fuzzers):
            status_icon = "✓" if f.status == FuzzerStatus.SUCCESS else "✗"
            fuzzer_header = f" {status_icon} {f.fuzzer_name} "
            box_lines.append("│" + fuzzer_header.ljust(width) + "│")
            box_lines.append(
                "│" + f"  Binary Path:  {f.binary_path or 'N/A'}".ljust(width) + "│"
            )
            box_lines.append(
                "│" + f"  Source Path:  {f.source_path or 'N/A'}".ljust(width) + "│"
            )
            box_lines.append(
                "│" + f"  Status:       {f.status.value}".ljust(width) + "│"
            )

            # Separator between fuzzers (except last)
            if i < len(fuzzers) - 1:
                box_lines.append("│" + "─" * width + "│")

        box_lines.append("└" + "─" * width + "┘")
        box_lines.append("")

        # Log the box
        for line in box_lines:
            logger.info(line)

    def _log_dispatch_summary(self, jobs: List[dict], project_name: str):
        """Log a formatted summary of dispatched workers as a table"""
        if not jobs:
            logger.info("No workers dispatched")
            return

        # Column widths
        col_worker = 12
        col_fuzzer = 28
        col_sanitizer = 12
        col_status = 10
        col_worker_id = 45

        # Total width = sum of columns + 4 internal separators (┬/┼)
        total_width = (
            col_worker + col_fuzzer + col_sanitizer + col_status + col_worker_id + 4
        )

        # Build header lines (no color)
        header_lines = []
        header_lines.append("")
        header_lines.append("┌" + "─" * total_width + "┐")
        header = f" {project_name} - Dispatched {len(jobs)} Workers "
        header_lines.append("│" + header.center(total_width) + "│")
        header_lines.append(
            "├"
            + "─" * col_worker
            + "┬"
            + "─" * col_fuzzer
            + "┬"
            + "─" * col_sanitizer
            + "┬"
            + "─" * col_status
            + "┬"
            + "─" * col_worker_id
            + "┤"
        )
        header_row = (
            "│"
            + " Worker".center(col_worker)
            + "│"
            + " Fuzzer".ljust(col_fuzzer)
            + "│"
            + " Sanitizer".ljust(col_sanitizer)
            + "│"
            + " Status".ljust(col_status)
            + "│"
            + " Worker ID".ljust(col_worker_id)
            + "│"
        )
        header_lines.append(header_row)
        header_lines.append(
            "├"
            + "─" * col_worker
            + "┼"
            + "─" * col_fuzzer
            + "┼"
            + "─" * col_sanitizer
            + "┼"
            + "─" * col_status
            + "┼"
            + "─" * col_worker_id
            + "┤"
        )

        # Build data rows (colored and plain versions)
        colored_rows = []
        plain_rows = []

        for i, job in enumerate(jobs, 1):
            fuzzer_name = (
                job["fuzzer"][: col_fuzzer - 2]
                if len(job["fuzzer"]) > col_fuzzer - 2
                else job["fuzzer"]
            )
            display_name = job.get(
                "display_name", f"{job['fuzzer']}_{job['sanitizer']}"
            )
            worker_id = (
                display_name[: col_worker_id - 2]
                if len(display_name) > col_worker_id - 2
                else display_name
            )

            # Build cell content
            worker_cell = f" Worker {i}".ljust(col_worker)
            fuzzer_cell = " " + fuzzer_name.ljust(col_fuzzer - 1)
            sanitizer_cell = " " + job["sanitizer"].ljust(col_sanitizer - 1)
            status_cell = " " + "PENDING".ljust(col_status - 1)
            id_cell = " " + worker_id.ljust(col_worker_id - 1)

            # Plain row (for log file)
            plain_row = (
                "│"
                + worker_cell
                + "│"
                + fuzzer_cell
                + "│"
                + sanitizer_cell
                + "│"
                + status_cell
                + "│"
                + id_cell
                + "│"
            )
            plain_rows.append(plain_row)

            # Colored row (for console)
            color = WorkerColors.get(i - 1)
            reset = WorkerColors.RESET
            colored_row = (
                "│"
                + color
                + worker_cell
                + reset
                + "│"
                + color
                + fuzzer_cell
                + reset
                + "│"
                + color
                + sanitizer_cell
                + reset
                + "│"
                + color
                + status_cell
                + reset
                + "│"
                + color
                + id_cell
                + reset
                + "│"
            )
            colored_rows.append(colored_row)

        # Footer
        footer = (
            "└"
            + "─" * col_worker
            + "┴"
            + "─" * col_fuzzer
            + "┴"
            + "─" * col_sanitizer
            + "┴"
            + "─" * col_status
            + "┴"
            + "─" * col_worker_id
            + "┘"
        )

        # Output table - separate handling for console (colored) and file (plain)
        import sys

        # Print colored version to console
        for line in header_lines:
            sys.stderr.write(line + "\n")
        for row in colored_rows:
            sys.stderr.write(row + "\n")
        sys.stderr.write(footer + "\n")
        sys.stderr.write("\n")
        sys.stderr.flush()

        # Write plain version to log file
        log_dir = get_log_dir()
        if log_dir:
            log_file = log_dir / "fuzzingbrain.log"
            with open(log_file, "a", encoding="utf-8") as f:
                for line in header_lines:
                    f.write(line + "\n")
                for row in plain_rows:
                    f.write(row + "\n")
                f.write(footer + "\n")
                f.write("\n")

    def process(self, task: Task) -> dict:
        """
        Process a task.

        Args:
            task: Task to process

        Returns:
            Result dictionary with task_id, status, message
        """
        logger.info(f"Processing task: {task.task_id}")

        # Task/Worker/Agent context is now handled via WorkerContext/AgentContext
        # which persist to MongoDB directly - no reporter needed

        # Save task to database
        task.mark_running()
        self.repos.tasks.save(task)

        # Cache disabled - only using prebuild for static analysis
        cache_restored = False
        cache_commit = None

        try:
            # Step 1: Setup workspace
            logger.info("Step 1: Setting up workspace")
            workspace_setup = WorkspaceSetup(self.config, task)

            success, msg = workspace_setup.setup()
            if not success:
                raise Exception(f"Workspace setup failed: {msg}")

            # Cache disabled - always do fresh setup
            if True:
                # Step 2: Clone repository
                logger.info("Step 2: Cloning repository")
                success, msg = workspace_setup.clone_repository()
                if not success:
                    raise Exception(f"Repository clone failed: {msg}")

                # Get commit hash after clone (if not already have it)
                if not cache_commit:
                    cache_commit = self._get_commit_hash()

                # Step 3: Setup fuzz-tooling
                logger.info("Step 3: Setting up fuzz-tooling")
                success, msg = workspace_setup.setup_fuzz_tooling()
                if not success:
                    raise Exception(f"Fuzz-tooling setup failed: {msg}")

            # Update task in database with new paths
            self.repos.tasks.save(task)

            # Step 3.5: Generate diff for delta scan (before build to fail fast)
            if self.config.scan_mode == "delta" and self.config.base_commit:
                diff_path = Path(task.task_path) / "diff"
                diff_file = diff_path / "ref.diff"

                if not diff_file.exists():
                    logger.info("Generating diff for delta scan...")
                    diff_path.mkdir(parents=True, exist_ok=True)

                    repo_path = Path(task.task_path) / "repo"
                    delta_commit = self.config.delta_commit or "HEAD"

                    try:
                        import subprocess

                        result = subprocess.run(
                            [
                                "git",
                                "diff",
                                f"{self.config.base_commit}..{delta_commit}",
                                "--",
                                ".",
                                ":!.aixcc",
                                ":!*/.aixcc",
                            ],
                            cwd=str(repo_path),
                            capture_output=True,
                            text=True,
                        )
                        if result.returncode == 0:
                            diff_content = result.stdout
                            if diff_content.strip():
                                diff_file.write_text(diff_content)
                                logger.info(
                                    f"Generated diff: {self.config.base_commit[:8]}..{delta_commit[:8] if delta_commit != 'HEAD' else 'HEAD'}"
                                )
                            else:
                                raise Exception(
                                    f"No changes between {self.config.base_commit[:8]} and {delta_commit[:8] if delta_commit != 'HEAD' else 'HEAD'}"
                                )
                        else:
                            raise Exception(f"git diff failed: {result.stderr}")
                    except Exception as e:
                        raise Exception(f"Failed to generate diff for delta scan: {e}")

            # Step 4: Discover fuzzers
            if cache_restored:
                # Load fuzzers from database (already restored from cache)
                logger.info("Step 4: Loading fuzzers from cache")
                fuzzers = self.repos.fuzzers.find_by_task(task.task_id)
                logger.info(f"Loaded {len(fuzzers)} fuzzers from cache")
            elif self.config.fuzzer_filter:
                # Use explicitly specified fuzzers from config
                logger.info(
                    f"Step 4: Using {len(self.config.fuzzer_filter)} fuzzers from config"
                )
                fuzzers = []
                for fuzzer_name in self.config.fuzzer_filter:
                    fuzzer = Fuzzer(
                        task_id=task.task_id,
                        fuzzer_name=fuzzer_name,
                        repo_name=task.project_name,
                        status=FuzzerStatus.PENDING,
                    )
                    fuzzers.append(fuzzer)
                    self.repos.fuzzers.save(fuzzer)
                    logger.info(f"  - {fuzzer_name}")
            else:
                logger.info("Step 4: Discovering fuzzers")
                fuzzer_discovery = FuzzerDiscovery(task, self.config, self.repos)
                fuzzers = fuzzer_discovery.discover_fuzzers()

                if not fuzzers:
                    logger.warning("No fuzzers found in workspace")
                else:
                    logger.info(f"Found {len(fuzzers)} fuzzers")
                    fuzzer_discovery.save_fuzzers(fuzzers)

            # Step 5: Run Code Analyzer (build + static analysis)
            from ..analyzer import AnalyzeRequest, AnalyzeResult
            from ..analyzer.tasks import run_analyzer

            project_name = self.config.ossfuzz_project_name or task.project_name
            analyze_result = None

            if cache_restored:
                # Start Analysis Server with skip_build mode (skip build, just start server)
                logger.info(
                    "Step 5: Starting Analysis Server (skip build, data from cache)"
                )

                log_dir = get_log_dir()
                analyze_request = AnalyzeRequest(
                    task_id=task.task_id,
                    task_path=task.task_path,
                    project_name=project_name,
                    sanitizers=self.config.sanitizers,
                    language="c",
                    ossfuzz_project_name=self.config.ossfuzz_project_name,
                    log_dir=str(log_dir) if log_dir else None,
                    skip_build=True,  # Skip build, use cached data
                    prebuild_dir=self.config.prebuild_dir,
                    work_id=self.config.work_id,
                    fuzzer_sources=self.config.fuzzer_sources,
                )

                # Run analyzer with skip_build
                if self.config.api_mode:
                    celery_result = run_analyzer.delay(analyze_request.to_dict())
                    result_dict = celery_result.get(
                        timeout=300
                    )  # 5 min timeout for skip_build
                else:
                    result_dict = run_analyzer(analyze_request.to_dict())

                analyze_result = AnalyzeResult.from_dict(result_dict)

                if not analyze_result.success:
                    raise Exception(
                        f"Analysis Server failed to start: {analyze_result.error_msg}"
                    )

                # Get function count from database
                db_functions = self.repos.functions.find_by_task(task.task_id)
                reachable_count = len(db_functions)

                logger.info(
                    f"Analysis Server ready: {len(analyze_result.fuzzers)} fuzzers, {reachable_count} functions"
                )

            else:
                logger.info("Step 5: Running Code Analyzer")

                # Create analyze request
                log_dir = get_log_dir()
                analyze_request = AnalyzeRequest(
                    task_id=task.task_id,
                    task_path=task.task_path,
                    project_name=project_name,
                    sanitizers=self.config.sanitizers,
                    language="c",  # TODO: detect language
                    ossfuzz_project_name=self.config.ossfuzz_project_name,
                    log_dir=str(log_dir) if log_dir else None,
                    prebuild_dir=self.config.prebuild_dir,
                    work_id=self.config.work_id,
                    fuzzer_sources=self.config.fuzzer_sources,
                )

                logger.info(f"Analyzer request: sanitizers={self.config.sanitizers}")
                logger.info(
                    "Waiting for Analyzer to complete (this may take a while)..."
                )

                # Run analyzer (synchronously for now, can be made async with Celery)
                # In CLI mode, run directly; in API mode, use Celery task
                if self.config.api_mode:
                    # Dispatch to Celery and wait
                    celery_result = run_analyzer.delay(analyze_request.to_dict())
                    result_dict = celery_result.get(timeout=3600)  # 1 hour timeout
                else:
                    # Run directly in same process
                    result_dict = run_analyzer(analyze_request.to_dict())

                analyze_result = AnalyzeResult.from_dict(result_dict)

                if not analyze_result.success:
                    raise Exception(f"Code Analyzer failed: {analyze_result.error_msg}")

                logger.info(
                    f"Analyzer completed: {len(analyze_result.fuzzers)} fuzzers built"
                )
                logger.info(
                    f"Build duration: {analyze_result.build_duration_seconds:.1f}s"
                )
                logger.info(
                    f"Static analysis: {analyze_result.reachable_functions_count} functions"
                )

                # Cache disabled - skip saving

            # Set shared coverage fuzzer path for tools
            if analyze_result.coverage_fuzzer_path:
                from ..tools.coverage import set_coverage_fuzzer_path

                set_coverage_fuzzer_path(analyze_result.coverage_fuzzer_path)
                logger.info(
                    f"Coverage fuzzer path set: {analyze_result.coverage_fuzzer_path}"
                )

            # Update fuzzer status in database based on Analyzer result
            # Skip this when restored from cache (fuzzers already have correct status)
            if not cache_restored:
                built_fuzzer_names = analyze_result.get_fuzzer_names()

                # Layer 3: If discovery (Layer 1 & 2) found nothing, create from analyzer results
                if not fuzzers and analyze_result.fuzzers:
                    logger.info("Layer 3: Creating fuzzers from analyzer build results")
                    seen_names = set()
                    for fi in analyze_result.fuzzers:
                        if fi.name in seen_names:
                            continue
                        seen_names.add(fi.name)
                        fuzzer = Fuzzer(
                            task_id=task.task_id,
                            fuzzer_name=fi.name,
                            source_path="",  # Unknown from build output
                            repo_name=task.project_name,
                            status=FuzzerStatus.SUCCESS,
                            binary_path=fi.binary_path,
                        )
                        fuzzers.append(fuzzer)
                        self.repos.fuzzers.save(fuzzer)
                    logger.info(f"Layer 3 created {len(fuzzers)} fuzzers from analyzer")
                else:
                    # Normal path: update discovered fuzzers with build status
                    for fuzzer in fuzzers:
                        if fuzzer.fuzzer_name in built_fuzzer_names:
                            fuzzer.status = FuzzerStatus.SUCCESS
                            for fi in analyze_result.fuzzers:
                                if fi.name == fuzzer.fuzzer_name:
                                    fuzzer.binary_path = fi.binary_path
                                    break
                        else:
                            fuzzer.status = FuzzerStatus.FAILED
                            fuzzer.error_msg = "Not found in build output"
                        self.repos.fuzzers.save(fuzzer)

            successful_fuzzers = [
                f for f in fuzzers if f.status == FuzzerStatus.SUCCESS
            ]

            # Log fuzzer build summary
            self._log_fuzzer_summary(fuzzers, project_name)

            # Store analyze_result for dispatcher to use
            self._analyze_result = analyze_result

            # Step 6: Start infrastructure (CLI mode only)
            logger.info("Step 6: Starting infrastructure")
            from .infrastructure import InfrastructureManager

            infra = None
            if not self.config.api_mode:
                log_dir = get_log_dir()

                infra = InfrastructureManager(
                    redis_url=self.config.redis_url,
                    concurrency=15,
                )
                if not infra.start(log_dir=str(log_dir) if log_dir else None):
                    raise Exception("Failed to start infrastructure (Redis/Celery)")

            try:
                # Step 7: Dispatch workers
                logger.info("Step 7: Dispatching workers")
                from .dispatcher import WorkerDispatcher

                dispatcher = WorkerDispatcher(
                    task,
                    self.config,
                    self.repos,
                    analyze_result=self._analyze_result,
                )
                jobs = dispatcher.dispatch(fuzzers)

                if not jobs:
                    raise Exception("No workers were dispatched")

                # Log dispatch summary
                self._log_dispatch_summary(jobs, project_name)

                # Mark task as running
                task.status = TaskStatus.RUNNING
                task.updated_at = datetime.now()
                self.repos.tasks.save(task)

                # Step 8: Wait for completion (CLI mode) or return (API mode)
                if not self.config.api_mode:
                    logger.info("Step 8: Waiting for workers to complete")
                    timeout = self.config.timeout_minutes or 60
                    result = dispatcher.wait_for_completion(timeout_minutes=timeout)

                    # Mark task as complete
                    if result["status"] == "completed":
                        if result["failed"] == 0:
                            task.mark_completed()
                        else:
                            task.mark_error(f"{result['failed']} workers failed")
                    elif result["status"] == "pov_target_reached":
                        task.mark_completed()
                        logger.info(
                            f"Task completed: POV target reached ({result.get('pov_count', 0)} POVs)"
                        )
                    elif result["status"] == "budget_exceeded":
                        task.mark_error(result.get("error", "Budget limit exceeded"))
                        logger.warning(
                            f"Task stopped: {result.get('error', 'Budget limit exceeded')}"
                        )
                    else:
                        task.mark_error(f"Timeout after {timeout} minutes")

                    # Use update() instead of save() to avoid overwriting
                    # llm_cost/llm_calls fields that buffer.$inc has accumulated
                    updates = {
                        "status": task.status.value,
                        "updated_at": task.updated_at,
                    }
                    if task.error_msg:
                        updates["error_msg"] = task.error_msg
                    self.repos.tasks.update(task.task_id, updates)

                    # Redis counter cleanup is handled by WorkerContext.__exit__

                    # Get worker results for summary
                    worker_results = dispatcher.get_results()

                    # Count merged duplicates for dedup stats
                    dedup_count = 0
                    try:
                        sps_with_merges = (
                            self.repos.suspicious_points.find_with_merged_duplicates(
                                task.task_id
                            )
                        )
                        for sp in sps_with_merges:
                            dedup_count += len(sp.merged_duplicates)
                    except Exception as e:
                        logger.warning(f"Failed to count merged duplicates: {e}")

                    # Read cost from database
                    task_doc = self.repos.tasks.collection.find_one(
                        {"_id": ObjectId(task.task_id)},
                        {"llm_cost": 1},
                    )
                    total_cost = (task_doc or {}).get("llm_cost", 0.0)

                    # Create and output final summary with worker colors via loguru
                    summary = create_final_summary(
                        project_name=project_name,
                        task_id=task.task_id,
                        workers=worker_results,
                        total_elapsed_minutes=result.get("elapsed_minutes", 0),
                        use_color=True,
                        dedup_count=dedup_count,
                        total_cost=total_cost,
                        budget_limit=self.config.budget_limit,
                        exit_reason=result.get("status", "completed"),
                    )
                    # Reset terminal settings before output (subprocess may have changed them)
                    os.system("stty sane 2>/dev/null")

                    # Print clean summary to console without log prefixes to avoid wrapping
                    # Add ANSI reset at the end to ensure terminal state is restored
                    sys.stdout.write("\n" + summary + "\n\033[0m")
                    sys.stdout.flush()

                    # Append plain summary (no ANSI codes) to log file for record
                    log_dir = get_log_dir()
                    if log_dir:
                        plain_summary = WorkerColors.strip(summary)
                        with open(
                            Path(log_dir) / "fuzzingbrain.log", "a", encoding="utf-8"
                        ) as f:
                            f.write("\n" + plain_summary + "\n")

                    logger.info("Final summary written to console and log file")

                    return {
                        "task_id": task.task_id,
                        "status": result["status"],
                        "message": f"Completed {result['completed']}/{result['total']} workers",
                        "workspace": task.task_path,
                        "fuzzers": [f.fuzzer_name for f in successful_fuzzers],
                        "workers": worker_results,
                        "elapsed_minutes": result.get("elapsed_minutes", 0),
                    }
                else:
                    # API mode: return immediately
                    return {
                        "task_id": task.task_id,
                        "status": "running",
                        "message": f"Dispatched {len(jobs)} workers.",
                        "workspace": task.task_path,
                        "fuzzers": [f.fuzzer_name for f in successful_fuzzers],
                        "workers": [
                            j.get("display_name", f"{j['fuzzer']}_{j['sanitizer']}")
                            for j in jobs
                        ],
                    }

            finally:
                # Stop Analysis Server
                if task and task.task_path:
                    from ..analyzer.tasks import stop_analysis_server

                    logger.info("Stopping Analysis Server...")
                    stop_analysis_server(task.task_path)

                # Stop infrastructure (CLI mode only)
                if infra:
                    infra.stop()

        except Exception as e:
            logger.exception(f"Task processing failed: {e}")
            task.mark_error(str(e))
            self.repos.tasks.update(
                task.task_id,
                {
                    "status": task.status.value,
                    "error_msg": task.error_msg,
                    "updated_at": task.updated_at,
                },
            )

            return {
                "task_id": task.task_id,
                "status": "error",
                "message": str(e),
            }


def process_task(task: Task, config: Config, repos: RepositoryManager = None) -> dict:
    """
    Process a task - main entry point.

    Args:
        task: Task to process
        config: Configuration
        repos: RepositoryManager instance (optional, gets global instance from main.py if not provided)

    Returns:
        Result dictionary
    """
    # Get from global if repos not provided
    if repos is None:
        from ..main import get_repos

        repos = get_repos()

    processor = TaskProcessor(config, repos)
    return processor.process(task)
