"""
Celery Task Definitions

Defines the tasks that can be executed by Celery workers.

Worker record creation and persistence is handled by WorkerContext
(via WorkerExecutor.run()), NOT by this file.
"""

import sys
import traceback
from datetime import datetime
from typing import Dict, Any

from loguru import logger

from ..celery_app import app
from ..core.logging import (
    set_log_dir,
    setup_worker_logging,
    create_worker_summary,
)
from ..db import MongoDB, init_repos


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

    Note: Worker record creation and persistence is handled by WorkerContext
    (via WorkerExecutor.run()), NOT by this function.

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
    coverage_fuzzer_path = assignment.get("coverage_fuzzer_path")
    analysis_socket_path = assignment.get("analysis_socket_path")

    # Scan mode and diff path (for delta mode)
    scan_mode = assignment.get("scan_mode", "full")
    diff_path = assignment.get("diff_path")

    # Display name for logging (not ObjectId)
    display_name = f"{fuzzer}_{sanitizer}"

    # Build worker metadata for logging
    worker_metadata = {
        "Display Name": display_name,
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
        logger.configure(extra={"worker": display_name})

    logger.info("Worker starting")
    start_time = datetime.now()

    # Initialize database connection for this worker process
    try:
        from ..core import Config

        config = Config.from_env()
        db = MongoDB.connect(config.mongodb_url, config.mongodb_db)
        repos = init_repos(db)
    except Exception as e:
        logger.exception(f"Failed to initialize worker: {e}")
        return {
            "display_name": display_name,
            "status": "failed",
            "error": f"Initialization failed: {e}",
        }

    try:
        # Setup coverage fuzzer path if provided
        if coverage_fuzzer_path:
            from ..tools.coverage import set_coverage_fuzzer_path

            set_coverage_fuzzer_path(coverage_fuzzer_path)

        # Run fuzzing strategies via WorkerExecutor
        # WorkerContext (inside executor.run()) handles Worker record creation
        logger.info("Running fuzzing strategies")

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
            # Pass celery_job_id for WorkerContext
            celery_job_id=self.request.id,
        )
        result = executor.run()

        # Clean up analysis client
        executor.close()

        # Calculate elapsed time
        elapsed_seconds = (datetime.now() - start_time).total_seconds()

        # Log worker completion summary
        summary = create_worker_summary(
            worker_id=display_name,
            status="completed",
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            pov_generated=result.get("pov_generated", 0),
            patch_generated=result.get("patch_generated", 0),
            elapsed_seconds=elapsed_seconds,
        )
        for line in summary.split("\n"):
            logger.info(line)

        # Cleanup workspace (keep results)
        from .cleanup import cleanup_worker_workspace

        cleanup_worker_workspace(workspace_path)

        return {
            "display_name": display_name,
            "worker_id": result.get("worker_id"),  # ObjectId from WorkerContext
            "status": "completed",
            "fuzzer": fuzzer,
            "sanitizer": sanitizer,
            "pov_generated": result.get("pov_generated", 0),
            "patch_generated": result.get("patch_generated", 0),
        }

    except Exception as e:
        logger.exception(f"Failed: {e}")

        # Clean up FuzzerManager on error
        try:
            if "executor" in dir() and executor is not None:
                executor.close()
        except Exception as cleanup_err:
            logger.warning(f"Error during cleanup: {cleanup_err}")

        # Calculate elapsed time
        elapsed_seconds = (datetime.now() - start_time).total_seconds()

        # Log worker failure summary
        summary = create_worker_summary(
            worker_id=display_name,
            status="failed",
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            elapsed_seconds=elapsed_seconds,
            error_msg=str(e),
        )
        for line in summary.split("\n"):
            logger.info(line)

        return {
            "display_name": display_name,
            "status": "failed",
            "fuzzer": fuzzer,
            "sanitizer": sanitizer,
            "error": str(e),
        }
