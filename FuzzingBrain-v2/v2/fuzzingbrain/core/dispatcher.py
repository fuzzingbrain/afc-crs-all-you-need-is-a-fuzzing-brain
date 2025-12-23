"""
Worker Dispatcher

Handles worker task dispatch:
1. Generate {fuzzer, sanitizer} pairs
2. Create worker workspaces
3. Dispatch Celery tasks
4. Monitor progress
"""

import shutil
from pathlib import Path
from typing import List, Dict, Any, Tuple

from .logging import logger
from .config import Config
from .models import Task, Fuzzer, FuzzerStatus, Worker, WorkerStatus
from ..db import RepositoryManager
from ..analyzer import AnalyzeResult


class WorkerDispatcher:
    """
    Dispatches worker tasks for fuzzing.

    For each {fuzzer, sanitizer} pair:
    1. Create isolated worker workspace
    2. Dispatch Celery task (with pre-built fuzzer path)
    3. Track worker status
    """

    def __init__(
        self,
        task: Task,
        config: Config,
        repos: RepositoryManager,
        analyze_result: AnalyzeResult = None,
    ):
        """
        Initialize WorkerDispatcher.

        Args:
            task: Task object
            config: Configuration
            repos: Database repository manager
            analyze_result: Result from Code Analyzer (contains pre-built fuzzer paths)
        """
        self.task = task
        self.config = config
        self.repos = repos
        self.project_name = config.ossfuzz_project or task.project_name
        self.analyze_result = analyze_result

    def dispatch(self, fuzzers: List[Fuzzer]) -> List[Dict[str, Any]]:
        """
        Dispatch worker tasks for all {fuzzer, sanitizer} pairs.

        Args:
            fuzzers: List of successfully built fuzzers

        Returns:
            List of dispatched job info
        """
        # Filter to only successful fuzzers
        successful_fuzzers = [f for f in fuzzers if f.status == FuzzerStatus.SUCCESS]

        if not successful_fuzzers:
            logger.warning("No successful fuzzers to dispatch")
            return []

        # Get sanitizers from config (default: ["address"])
        sanitizers = self.config.sanitizers or ["address"]

        # Generate {fuzzer, sanitizer} pairs
        pairs = self._generate_pairs(successful_fuzzers, sanitizers)
        logger.info(f"Generated {len(pairs)} worker assignments")

        # Create worker workspaces and dispatch tasks
        jobs = []
        for pair in pairs:
            try:
                # Create workspace
                workspace_path = self._create_worker_workspace(pair)

                # Dispatch Celery task
                job_info = self._dispatch_celery_task(pair, workspace_path)
                jobs.append(job_info)

            except Exception as e:
                logger.exception(f"Failed to dispatch {pair}: {e}")
                # Continue with other pairs

        logger.info(f"Dispatched {len(jobs)} worker tasks")
        return jobs

    def _generate_pairs(
        self, fuzzers: List[Fuzzer], sanitizers: List[str]
    ) -> List[Dict[str, str]]:
        """
        Generate {fuzzer, sanitizer} pairs.

        Args:
            fuzzers: List of fuzzers
            sanitizers: List of sanitizers

        Returns:
            List of pair dictionaries
        """
        pairs = []
        for fuzzer in fuzzers:
            for sanitizer in sanitizers:
                pairs.append({
                    "fuzzer": fuzzer.fuzzer_name,
                    "sanitizer": sanitizer,
                })
        return pairs

    def _create_worker_workspace(self, pair: Dict[str, str]) -> str:
        """
        Create isolated workspace for a worker.

        Copies repo, fuzz-tooling, and diff (if exists) to worker workspace.

        Args:
            pair: {fuzzer, sanitizer} pair

        Returns:
            Path to worker workspace
        """
        fuzzer = pair["fuzzer"]
        sanitizer = pair["sanitizer"]

        # Worker workspace path
        task_workspace = Path(self.task.task_path)
        worker_workspace = task_workspace / "worker_workspace" / f"{self.project_name}_{fuzzer}_{sanitizer}"

        # Remove if exists
        if worker_workspace.exists():
            shutil.rmtree(worker_workspace)

        worker_workspace.mkdir(parents=True, exist_ok=True)

        # Copy repo
        src_repo = task_workspace / "repo"
        if src_repo.exists():
            shutil.copytree(src_repo, worker_workspace / "repo")
            logger.debug(f"Copied repo to {worker_workspace / 'repo'}")

        # Copy fuzz-tooling
        src_fuzz_tooling = task_workspace / "fuzz-tooling"
        if src_fuzz_tooling.exists():
            shutil.copytree(src_fuzz_tooling, worker_workspace / "fuzz-tooling")
            logger.debug(f"Copied fuzz-tooling to {worker_workspace / 'fuzz-tooling'}")

        # Copy diff (if exists)
        src_diff = task_workspace / "diff"
        if src_diff.exists():
            shutil.copytree(src_diff, worker_workspace / "diff")
            logger.debug(f"Copied diff to {worker_workspace / 'diff'}")

        # Create results directory
        (worker_workspace / "results").mkdir(exist_ok=True)

        logger.info(f"Created worker workspace: {worker_workspace}")
        return str(worker_workspace)

    def _dispatch_celery_task(
        self, pair: Dict[str, str], workspace_path: str
    ) -> Dict[str, Any]:
        """
        Dispatch a Celery task for the worker.

        Args:
            pair: {fuzzer, sanitizer} pair
            workspace_path: Path to worker workspace

        Returns:
            Job info dictionary
        """
        from ..worker.tasks import run_worker

        fuzzer = pair["fuzzer"]
        sanitizer = pair["sanitizer"]
        worker_id = f"{self.task.task_id}__{fuzzer}__{sanitizer}"

        # Create Worker record in database
        worker = Worker(
            worker_id=worker_id,
            task_id=self.task.task_id,
            job_type=self.task.task_type.value,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            workspace_path=workspace_path,
            status=WorkerStatus.PENDING,
        )
        self.repos.workers.save(worker)

        # Get log directory from current logging config
        from .logging import get_log_dir
        log_dir = get_log_dir()

        # Get pre-built fuzzer path from analyze_result
        fuzzer_binary_path = None
        build_dir = None
        if self.analyze_result:
            fuzzer_binary_path = self.analyze_result.get_fuzzer_path(fuzzer, sanitizer)
            build_dir = self.analyze_result.build_paths.get(sanitizer)

        # Prepare assignment
        assignment = {
            "task_id": self.task.task_id,
            "fuzzer": fuzzer,
            "sanitizer": sanitizer,
            "job_type": self.task.task_type.value,
            "workspace_path": workspace_path,
            "project_name": self.project_name,
            "log_dir": str(log_dir) if log_dir else None,
            # Pre-built fuzzer info from Analyzer
            "fuzzer_binary_path": fuzzer_binary_path,
            "build_dir": build_dir,
            "coverage_fuzzer_path": self.analyze_result.coverage_fuzzer_path if self.analyze_result else None,
        }

        # Dispatch Celery task
        result = run_worker.delay(assignment)

        # Update worker with Celery job ID
        worker.celery_job_id = result.id
        self.repos.workers.save(worker)

        logger.info(f"Dispatched worker: {worker_id} (celery_id: {result.id})")

        return {
            "worker_id": worker_id,
            "celery_id": result.id,
            "fuzzer": fuzzer,
            "sanitizer": sanitizer,
            "workspace_path": workspace_path,
        }

    def get_status(self) -> Dict[str, Any]:
        """
        Get status of all workers for this task.

        Also checks Celery task status to detect workers that failed
        before updating the database.

        Returns:
            Status summary dictionary
        """
        from celery.result import AsyncResult
        from ..celery_app import app

        workers = self.repos.workers.find_by_task(self.task.task_id)

        status = {
            "total": len(workers),
            "pending": 0,
            "building": 0,
            "running": 0,
            "completed": 0,
            "failed": 0,
        }

        for worker in workers:
            worker_status = worker.status.value

            # If worker is still pending/building/running, check Celery task status
            if worker_status in ["pending", "building", "running"] and worker.celery_job_id:
                try:
                    result = AsyncResult(worker.celery_job_id, app=app)
                    if result.failed():
                        # Celery task failed but DB not updated - mark as failed
                        worker.status = WorkerStatus.FAILED
                        worker.error_msg = str(result.result) if result.result else "Task failed"
                        self.repos.workers.save(worker)
                        worker_status = "failed"
                        logger.warning(f"Worker {worker.worker_id} failed (detected via Celery)")
                except Exception:
                    pass  # Ignore Celery check errors

            if worker_status in status:
                status[worker_status] += 1

        return status

    def is_complete(self) -> bool:
        """Check if all workers have completed (success or failed)."""
        status = self.get_status()
        finished = status["completed"] + status["failed"]
        return finished == status["total"] and status["total"] > 0

    def wait_for_completion(
        self,
        timeout_minutes: int = 60,
        poll_interval: int = 5,
        on_progress: callable = None,
    ) -> Dict[str, Any]:
        """
        Wait for all workers to complete (CLI mode).

        Args:
            timeout_minutes: Maximum time to wait in minutes
            poll_interval: Seconds between status checks
            on_progress: Optional callback for progress updates

        Returns:
            Final status summary
        """
        import time
        from datetime import datetime, timedelta

        start_time = datetime.now()
        timeout_delta = timedelta(minutes=timeout_minutes)
        last_status = None

        logger.info(f"Waiting for workers to complete (timeout: {timeout_minutes}min)")

        while True:
            # Check timeout
            elapsed = datetime.now() - start_time
            if elapsed > timeout_delta:
                logger.warning(f"Timeout reached after {timeout_minutes} minutes")
                return {
                    "status": "timeout",
                    "elapsed_minutes": elapsed.total_seconds() / 60,
                    **self.get_status(),
                }

            # Get current status
            status = self.get_status()

            # Log progress if changed
            if status != last_status:
                logger.info(
                    f"Progress: {status['completed']}/{status['total']} completed, "
                    f"{status['failed']} failed, {status['running']} running"
                )
                last_status = status

                if on_progress:
                    on_progress(status)

            # Check if all complete
            if self.is_complete():
                logger.info("All workers completed")
                return {
                    "status": "completed",
                    "elapsed_minutes": elapsed.total_seconds() / 60,
                    **status,
                }

            # Wait before next poll
            time.sleep(poll_interval)

    def get_results(self) -> List[Dict[str, Any]]:
        """
        Get results from all completed workers.

        Returns:
            List of worker results
        """
        workers = self.repos.workers.find_by_task(self.task.task_id)
        results = []

        for worker in workers:
            result = {
                "worker_id": worker.worker_id,
                "fuzzer": worker.fuzzer,
                "sanitizer": worker.sanitizer,
                "status": worker.status.value,
                "povs_found": worker.povs_found or 0,
                "patches_found": worker.patches_found or 0,
                "error_msg": worker.error_msg,
            }
            results.append(result)

        return results
