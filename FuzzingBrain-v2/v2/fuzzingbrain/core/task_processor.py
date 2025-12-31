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
                task_workspace = workspace_root / f"{project_name}_{self.task.task_id[:8]}"
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
            # Clone fuzz-tooling from URL
            try:
                logger.info(f"Cloning fuzz-tooling from {self.config.fuzz_tooling_url}")
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", self.config.fuzz_tooling_url, str(fuzz_tooling_path)],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )

                if result.returncode != 0:
                    logger.error(f"Fuzz-tooling clone failed: {result.stderr}")
                    return False, result.stderr

                self.task.fuzz_tooling_path = str(fuzz_tooling_path)
                self.task.is_fuzz_tooling_provided = True
                return True, "Cloned"

            except Exception as e:
                logger.error(f"Failed to clone fuzz-tooling: {e}")
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
            logger.warning("No fuzz-tooling found. Current version only supports OSS-Fuzz based projects.")
            logger.warning("Please ensure the project exists in OSS-Fuzz or provide --fuzz-tooling-url")
            return True, "Not provided"


class FuzzerDiscovery:
    """Discovers and builds fuzzers in the workspace"""

    # Common fuzzer file patterns (search in direct children, not recursively in infra/)
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
        Discover fuzzer source files in the workspace.

        Search paths:
        1. fuzz-tooling/projects/{ossfuzz_project}/ - OSS-Fuzz project fuzzers (shallow search)
        2. repo/ - fuzzers in the source repository (recursive search)

        Returns:
            List of Fuzzer objects
        """
        fuzzers = []
        seen_names = set()

        # Search in OSS-Fuzz project directory (shallow - only top level)
        if self.task.fuzz_tooling_path:
            fuzz_tooling = Path(self.task.fuzz_tooling_path)
            ossfuzz_project = self.config.ossfuzz_project or self.task.project_name
            if ossfuzz_project:
                project_dir = fuzz_tooling / "projects" / ossfuzz_project
                if project_dir.exists():
                    logger.info(f"Searching for fuzzers in: {project_dir}")
                    for pattern in self.FUZZER_PATTERNS:
                        for fuzzer_file in project_dir.glob(pattern):
                            self._add_fuzzer(fuzzers, seen_names, fuzzer_file, project_dir)
                else:
                    logger.warning(f"OSS-Fuzz project directory not found: {project_dir}")

        # Search in source repo (recursive - fuzzers can be anywhere)
        if self.task.src_path:
            repo_path = Path(self.task.src_path)
            if repo_path.exists():
                logger.info(f"Searching for fuzzers in repo: {repo_path}")
                for pattern in self.FUZZER_PATTERNS:
                    for fuzzer_file in repo_path.glob(f"**/{pattern}"):
                        self._add_fuzzer(fuzzers, seen_names, fuzzer_file, repo_path)

        return fuzzers

    def _add_fuzzer(self, fuzzers: List[Fuzzer], seen_names: set, fuzzer_file: Path, search_path: Path):
        """Add a fuzzer to the list if not already seen"""
        fuzzer_name = fuzzer_file.stem
        if fuzzer_name in seen_names:
            return
        seen_names.add(fuzzer_name)

        fuzzer = Fuzzer(
            task_id=self.task.task_id,
            fuzzer_name=fuzzer_name,
            source_path=str(fuzzer_file.relative_to(search_path)),
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
            box_lines.append("│" + f"  Binary Path:  {f.binary_path or 'N/A'}".ljust(width) + "│")
            box_lines.append("│" + f"  Source Path:  {f.source_path or 'N/A'}".ljust(width) + "│")
            box_lines.append("│" + f"  Status:       {f.status.value}".ljust(width) + "│")

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
        total_width = col_worker + col_fuzzer + col_sanitizer + col_status + col_worker_id + 4

        # Build header lines (no color)
        header_lines = []
        header_lines.append("")
        header_lines.append("┌" + "─" * total_width + "┐")
        header = f" {project_name} - Dispatched {len(jobs)} Workers "
        header_lines.append("│" + header.center(total_width) + "│")
        header_lines.append("├" + "─" * col_worker + "┬" + "─" * col_fuzzer + "┬" + "─" * col_sanitizer + "┬" + "─" * col_status + "┬" + "─" * col_worker_id + "┤")
        header_row = (
            "│" + " Worker".center(col_worker) +
            "│" + " Fuzzer".ljust(col_fuzzer) +
            "│" + " Sanitizer".ljust(col_sanitizer) +
            "│" + " Status".ljust(col_status) +
            "│" + " Worker ID".ljust(col_worker_id) + "│"
        )
        header_lines.append(header_row)
        header_lines.append("├" + "─" * col_worker + "┼" + "─" * col_fuzzer + "┼" + "─" * col_sanitizer + "┼" + "─" * col_status + "┼" + "─" * col_worker_id + "┤")

        # Build data rows (colored and plain versions)
        colored_rows = []
        plain_rows = []

        for i, job in enumerate(jobs, 1):
            fuzzer_name = job['fuzzer'][:col_fuzzer-2] if len(job['fuzzer']) > col_fuzzer-2 else job['fuzzer']
            worker_id = job['worker_id'][:col_worker_id-2] if len(job['worker_id']) > col_worker_id-2 else job['worker_id']

            # Build cell content
            worker_cell = f" Worker {i}".ljust(col_worker)
            fuzzer_cell = " " + fuzzer_name.ljust(col_fuzzer-1)
            sanitizer_cell = " " + job['sanitizer'].ljust(col_sanitizer-1)
            status_cell = " " + "PENDING".ljust(col_status-1)
            id_cell = " " + worker_id.ljust(col_worker_id-1)

            # Plain row (for log file)
            plain_row = (
                "│" + worker_cell +
                "│" + fuzzer_cell +
                "│" + sanitizer_cell +
                "│" + status_cell +
                "│" + id_cell + "│"
            )
            plain_rows.append(plain_row)

            # Colored row (for console)
            color = WorkerColors.get(i - 1)
            reset = WorkerColors.RESET
            colored_row = (
                "│" + color + worker_cell + reset +
                "│" + color + fuzzer_cell + reset +
                "│" + color + sanitizer_cell + reset +
                "│" + color + status_cell + reset +
                "│" + color + id_cell + reset + "│"
            )
            colored_rows.append(colored_row)

        # Footer
        footer = "└" + "─" * col_worker + "┴" + "─" * col_fuzzer + "┴" + "─" * col_sanitizer + "┴" + "─" * col_status + "┴" + "─" * col_worker_id + "┘"

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

        # Save task to database
        task.mark_running()
        self.repos.tasks.save(task)

        try:
            # Step 1: Setup workspace
            logger.info("Step 1: Setting up workspace")
            workspace_setup = WorkspaceSetup(self.config, task)

            success, msg = workspace_setup.setup()
            if not success:
                raise Exception(f"Workspace setup failed: {msg}")

            # Step 2: Clone repository
            logger.info("Step 2: Cloning repository")
            success, msg = workspace_setup.clone_repository()
            if not success:
                raise Exception(f"Repository clone failed: {msg}")

            # Step 3: Setup fuzz-tooling
            logger.info("Step 3: Setting up fuzz-tooling")
            success, msg = workspace_setup.setup_fuzz_tooling()
            if not success:
                raise Exception(f"Fuzz-tooling setup failed: {msg}")

            # Update task in database with new paths
            self.repos.tasks.save(task)

            # Step 4: Discover fuzzers
            logger.info("Step 4: Discovering fuzzers")
            fuzzer_discovery = FuzzerDiscovery(task, self.config, self.repos)
            fuzzers = fuzzer_discovery.discover_fuzzers()

            if not fuzzers:
                logger.warning("No fuzzers found in workspace")
            else:
                logger.info(f"Found {len(fuzzers)} fuzzers")
                fuzzer_discovery.save_fuzzers(fuzzers)

            # Step 5: Run Code Analyzer (build + static analysis)
            logger.info("Step 5: Running Code Analyzer")
            from ..analyzer import AnalyzeRequest, AnalyzeResult
            from ..analyzer.tasks import run_analyzer

            project_name = self.config.ossfuzz_project or task.project_name

            # Create analyze request
            log_dir = get_log_dir()
            analyze_request = AnalyzeRequest(
                task_id=task.task_id,
                task_path=task.task_path,
                project_name=project_name,
                sanitizers=self.config.sanitizers,
                language="c",  # TODO: detect language
                ossfuzz_project=self.config.ossfuzz_project,
                log_dir=str(log_dir) if log_dir else None,
            )

            logger.info(f"Analyzer request: sanitizers={self.config.sanitizers}")
            logger.info("Waiting for Analyzer to complete (this may take a while)...")

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

            logger.info(f"Analyzer completed: {len(analyze_result.fuzzers)} fuzzers built")
            logger.info(f"Build duration: {analyze_result.build_duration_seconds:.1f}s")
            logger.info(f"Static analysis: {analyze_result.reachable_functions_count} functions")

            # Set shared coverage fuzzer path for tools
            if analyze_result.coverage_fuzzer_path:
                from ..tools.coverage import set_coverage_fuzzer_path
                set_coverage_fuzzer_path(analyze_result.coverage_fuzzer_path)
                logger.info(f"Coverage fuzzer path set: {analyze_result.coverage_fuzzer_path}")

            # Update fuzzer status in database based on Analyzer result
            built_fuzzer_names = analyze_result.get_fuzzer_names()
            for fuzzer in fuzzers:
                if fuzzer.fuzzer_name in built_fuzzer_names:
                    fuzzer.status = FuzzerStatus.SUCCESS
                    # Get binary path for first sanitizer (they all have the same fuzzer name)
                    for fi in analyze_result.fuzzers:
                        if fi.name == fuzzer.fuzzer_name:
                            fuzzer.binary_path = fi.binary_path
                            break
                else:
                    fuzzer.status = FuzzerStatus.FAILED
                    fuzzer.error_msg = "Not found in build output"
                self.repos.fuzzers.save(fuzzer)

            successful_fuzzers = [f for f in fuzzers if f.status == FuzzerStatus.SUCCESS]

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
                    concurrency=8,
                )
                if not infra.start(log_dir=str(log_dir) if log_dir else None):
                    raise Exception("Failed to start infrastructure (Redis/Celery)")

            try:
                # Step 7: Dispatch workers
                logger.info("Step 7: Dispatching workers")
                from .dispatcher import WorkerDispatcher

                dispatcher = WorkerDispatcher(
                    task, self.config, self.repos,
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
                    else:
                        task.mark_error(f"Timeout after {timeout} minutes")

                    self.repos.tasks.save(task)

                    # Get worker results for summary
                    worker_results = dispatcher.get_results()

                    # Count merged duplicates for dedup stats
                    dedup_count = 0
                    try:
                        sps_with_merges = self.repos.suspicious_points.find_with_merged_duplicates(task.task_id)
                        for sp in sps_with_merges:
                            dedup_count += len(sp.merged_duplicates)
                    except Exception as e:
                        logger.warning(f"Failed to count merged duplicates: {e}")

                    # Create and output final summary with worker colors via loguru
                    summary = create_final_summary(
                        project_name=project_name,
                        task_id=task.task_id,
                        workers=worker_results,
                        total_elapsed_minutes=result.get("elapsed_minutes", 0),
                        use_color=True,
                        dedup_count=dedup_count,
                    )
                    # Reset terminal settings before output (subprocess may have changed them)
                    os.system('stty sane 2>/dev/null')

                    # Print clean summary to console without log prefixes to avoid wrapping
                    # Add ANSI reset at the end to ensure terminal state is restored
                    sys.stdout.write("\n" + summary + "\n\033[0m")
                    sys.stdout.flush()

                    # Append plain summary (no ANSI codes) to log file for record
                    log_dir = get_log_dir()
                    if log_dir:
                        plain_summary = WorkerColors.strip(summary)
                        with open(Path(log_dir) / "fuzzingbrain.log", "a", encoding="utf-8") as f:
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
                        "workers": [j["worker_id"] for j in jobs],
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
            self.repos.tasks.save(task)

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
