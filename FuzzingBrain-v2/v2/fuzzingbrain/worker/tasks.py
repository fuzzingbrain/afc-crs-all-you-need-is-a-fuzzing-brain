"""
Celery Task Definitions

Defines the tasks that can be executed by Celery workers.
"""

import sys
import traceback
from datetime import datetime
from typing import Dict, Any

from loguru import logger

from ..celery_app import app
from ..core.models import Worker, WorkerStatus
from ..core.logging import (
    set_log_dir,
    setup_worker_logging,
    create_worker_summary,
)
from ..db import MongoDB, init_repos
from ..eval import BudgetExceededError


# Capture any uncaught exceptions at module level
def _log_uncaught_exception(exc_type, exc_value, exc_tb):
    """Log uncaught exceptions to both stderr and file."""
    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    logger.error(f"Uncaught exception in worker:\n{error_msg}")
    # Also ensure it goes to stderr
    sys.stderr.write(f"[WORKER ERROR] {error_msg}\n")
    sys.stderr.flush()


sys.excepthook = _log_uncaught_exception


@app.task(bind=True, name="fuzzingbrain.worker.tasks.run_worker")
def run_worker(self, assignment: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a worker task for a {fuzzer, sanitizer} pair.

    Args:
        assignment: Dictionary containing:
            - task_id: str
            - fuzzer: str
            - sanitizer: str
            - task_type: str (pov | patch | pov-patch | harness)
            - workspace_path: str
            - project_name: str
            - log_dir: str (optional)

    Returns:
        Result dictionary with status and findings
    """
    task_id = assignment["task_id"]
    fuzzer = assignment["fuzzer"]
    sanitizer = assignment["sanitizer"]
    workspace_path = assignment["workspace_path"]
    task_type = assignment["task_type"]
    project_name = assignment["project_name"]
    log_dir = assignment.get("log_dir")

    # Pre-built fuzzer info from Analyzer (new architecture)
    fuzzer_binary_path = assignment.get("fuzzer_binary_path")
    build_dir = assignment.get("build_dir")
    coverage_fuzzer_path = assignment.get("coverage_fuzzer_path")
    analysis_socket_path = assignment.get("analysis_socket_path")

    # Scan mode and diff path (for delta mode)
    scan_mode = assignment.get("scan_mode", "full")
    diff_path = assignment.get("diff_path")

    # Evaluation server for cost tracking
    eval_server = assignment.get("eval_server")
    budget_limit = assignment.get("budget_limit", 0.0)
    pov_count = assignment.get("pov_count", 1)

    worker_id = f"{task_id}__{fuzzer}__{sanitizer}"

    # Build worker metadata for logging
    worker_metadata = {
        "Worker ID": worker_id,
        "Task ID": task_id,
        "Project": project_name,
        "Fuzzer": fuzzer,
        "Sanitizer": sanitizer,
        "Job Type": task_type,
        "Scan Mode": scan_mode,
        "Start Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Workspace": workspace_path,
        "Celery ID": self.request.id,
    }

    # Setup worker-specific logging with new directory structure
    # worker/{fuzzer}_{sanitizer}/worker.log and error.log
    if log_dir:
        # Remove default handlers (no console output for workers)
        logger.remove()
        # Set log directory for this worker process
        set_log_dir(log_dir)
        # Setup worker logging with new structure
        setup_worker_logging(fuzzer, sanitizer, worker_metadata)
        # Bind logger to this worker for filtering
        logger.configure(extra={"worker": f"{fuzzer}_{sanitizer}"})

    logger.info("Worker starting")
    start_time = datetime.now()

    # Worker context is now handled by WorkerExecutor using WorkerContext
    # which persists to MongoDB directly - no reporter needed

    # Initialize database connection for this worker process
    try:
        from ..core import Config

        config = Config.from_env()
        db = MongoDB.connect(config.mongodb_url, config.mongodb_db)
        repos = init_repos(db)
    except Exception as e:
        logger.exception(f"Failed to initialize worker: {e}")
        return {
            "worker_id": worker_id,
            "status": "failed",
            "error": f"Initialization failed: {e}",
        }

    # Create worker record with started_at timestamp
    worker = Worker(
        worker_id=worker_id,
        celery_job_id=self.request.id,
        task_id=task_id,
        task_type=task_type,
        fuzzer=fuzzer,
        sanitizer=sanitizer,
        workspace_path=workspace_path,
        status=WorkerStatus.BUILDING,
        started_at=start_time,
    )
    repos.workers.save(worker)

    try:
        # Step 1: Setup fuzzer binary
        # If pre-built fuzzer path is provided (new architecture), skip building
        # Otherwise fall back to building (legacy mode)
        build_start = datetime.now()
        if fuzzer_binary_path:
            logger.info(f"Using pre-built fuzzer from Analyzer: {fuzzer_binary_path}")
            worker.status = WorkerStatus.RUNNING
            worker.phase_build = 0.0  # Pre-built, no build time
            repos.workers.save(worker)

            # Set coverage fuzzer path if provided
            if coverage_fuzzer_path:
                from ..tools.coverage import set_coverage_fuzzer_path

                set_coverage_fuzzer_path(coverage_fuzzer_path)
        else:
            # Legacy mode: build fuzzer in worker
            logger.info(f"Building fuzzer with {sanitizer} sanitizer (legacy mode)")
            worker.status = WorkerStatus.BUILDING
            repos.workers.save(worker)

            from .builder import WorkerBuilder

            builder = WorkerBuilder(workspace_path, project_name, sanitizer)
            build_success, build_msg = builder.build()

            if not build_success:
                raise Exception(f"Build failed: {build_msg}")

            # Get fuzzer path from builder
            fuzzer_binary_path = str(builder.get_fuzzer_path(fuzzer))

            # Record build time
            worker.phase_build = (datetime.now() - build_start).total_seconds()
            repos.workers.save(worker)

        # Step 2: Run fuzzing strategies
        logger.info("Running fuzzing strategies")
        worker.status = WorkerStatus.RUNNING
        repos.workers.save(worker)

        from .executor import WorkerExecutor

        executor = WorkerExecutor(
            workspace_path=workspace_path,
            project_name=project_name,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            task_type=task_type,
            repos=repos,
            task_id=task_id,
            scan_mode=scan_mode,
            fuzzer_binary_path=fuzzer_binary_path,
            analysis_socket_path=analysis_socket_path,
            diff_path=diff_path,
            log_dir=log_dir,
        )
        result = executor.run()

        # Clean up analysis client
        executor.close()

        # Step 3: Mark completed and save phase timing from strategy result
        worker.status = WorkerStatus.COMPLETED
        worker.povs_found = result.get("povs_found", 0)
        worker.patches_found = result.get("patches_found", 0)
        worker.finished_at = datetime.now()
        # Copy phase timing from strategy result
        worker.phase_reachability = result.get("phase_reachability", 0.0)
        worker.phase_find_sp = result.get("phase_find_sp", 0.0)
        worker.phase_verify = result.get("phase_verify", 0.0)
        worker.phase_pov = result.get("phase_pov", 0.0)
        worker.phase_save = result.get("phase_save", 0.0)
        repos.workers.save(worker)

        # Calculate elapsed time
        elapsed_seconds = (datetime.now() - start_time).total_seconds()

        # Log worker completion summary
        summary = create_worker_summary(
            worker_id=worker_id,
            status="completed",
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            povs_found=result.get("povs_found", 0),
            patches_found=result.get("patches_found", 0),
            elapsed_seconds=elapsed_seconds,
        )
        for line in summary.split("\n"):
            logger.info(line)

        # Step 4: Cleanup workspace (keep results)
        from .cleanup import cleanup_worker_workspace

        cleanup_worker_workspace(workspace_path)

        return {
            "worker_id": worker_id,
            "status": "completed",
            "fuzzer": fuzzer,
            "sanitizer": sanitizer,
            "povs_found": result.get("povs_found", 0),
            "patches_found": result.get("patches_found", 0),
        }

    except BudgetExceededError as e:
        # Budget limit reached - graceful shutdown
        logger.warning(f"Budget limit exceeded: {e}")

        # Clean up executor
        try:
            if "executor" in dir() and executor is not None:
                executor.close()
        except Exception as cleanup_err:
            logger.warning(f"Error during cleanup: {cleanup_err}")

        worker.status = WorkerStatus.FAILED
        worker.error_msg = f"Budget limit exceeded: {e}"
        worker.finished_at = datetime.now()
        repos.workers.save(worker)

        # Calculate elapsed time
        elapsed_seconds = (datetime.now() - start_time).total_seconds()

        # Log worker summary
        summary = create_worker_summary(
            worker_id=worker_id,
            status="budget_exceeded",
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            elapsed_seconds=elapsed_seconds,
            error_msg=str(e),
        )
        for line in summary.split("\n"):
            logger.info(line)

        return {
            "worker_id": worker_id,
            "status": "budget_exceeded",
            "fuzzer": fuzzer,
            "sanitizer": sanitizer,
            "error": str(e),
        }

    except Exception as e:
        logger.exception(f"Failed: {e}")

        # Clean up FuzzerManager on error
        try:
            if "executor" in dir() and executor is not None:
                executor.close()
        except Exception as cleanup_err:
            logger.warning(f"Error during cleanup: {cleanup_err}")

        worker.status = WorkerStatus.FAILED
        worker.error_msg = str(e)
        worker.finished_at = datetime.now()
        repos.workers.save(worker)

        # Calculate elapsed time
        elapsed_seconds = (datetime.now() - start_time).total_seconds()

        # Log worker failure summary
        summary = create_worker_summary(
            worker_id=worker_id,
            status="failed",
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            elapsed_seconds=elapsed_seconds,
            error_msg=str(e),
        )
        for line in summary.split("\n"):
            logger.info(line)

        return {
            "worker_id": worker_id,
            "status": "failed",
            "fuzzer": fuzzer,
            "sanitizer": sanitizer,
            "error": str(e),
        }
