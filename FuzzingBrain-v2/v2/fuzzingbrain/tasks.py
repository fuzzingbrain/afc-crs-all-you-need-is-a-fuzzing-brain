"""
Celery Task Definitions

Defines the tasks that can be executed by Celery workers.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from loguru import logger

from .celery_app import app
from .core.models import Worker, WorkerStatus
from .core.logging import get_worker_banner_and_header
from .db import MongoDB, init_repos


def setup_worker_logging(log_dir: str, worker_id: str, metadata: Dict[str, Any]):
    """
    Setup logging for a worker process.

    Configures logger to write to both:
    1. Main task log file (fuzzingbrain.log)
    2. Worker-specific log file (worker_{worker_id}.log)

    Also writes the worker banner and metadata header to the log file.
    """
    logger.remove()

    log_path = Path(log_dir)
    safe_worker_id = worker_id.replace("__", "_")
    worker_log_file = log_path / f"worker_{safe_worker_id}.log"

    # Write banner and header to worker log file
    banner = get_worker_banner_and_header(metadata)
    with open(worker_log_file, "w", encoding="utf-8") as f:
        f.write(banner)
        f.write("\n")

    # Also print banner to console
    print(banner, file=sys.stderr)

    # Console output
    logger.add(
        sys.stderr,
        level="INFO",
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>" + worker_id + "</cyan> - <level>{message}</level>",
        colorize=True,
    )

    # Main log file (append)
    logger.add(
        log_path / "fuzzingbrain.log",
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | [" + worker_id + "] {message}",
        encoding="utf-8",
        mode="a",
    )

    # Worker-specific log file (append mode since we already wrote the header)
    logger.add(
        worker_log_file,
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {message}",
        encoding="utf-8",
        mode="a",
    )

    return logger


@app.task(bind=True, name="fuzzingbrain.tasks.run_worker")
def run_worker(self, assignment: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a worker task for a {fuzzer, sanitizer} pair.

    Args:
        assignment: Dictionary containing:
            - task_id: str
            - fuzzer: str
            - sanitizer: str
            - job_type: str (pov | patch | pov-patch | harness)
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
    job_type = assignment["job_type"]
    project_name = assignment["project_name"]
    log_dir = assignment.get("log_dir")

    worker_id = f"{task_id}__{fuzzer}__{sanitizer}"

    # Build worker metadata for logging
    worker_metadata = {
        "Worker ID": worker_id,
        "Task ID": task_id,
        "Project": project_name,
        "Fuzzer": fuzzer,
        "Sanitizer": sanitizer,
        "Job Type": job_type,
        "Start Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Workspace": workspace_path,
        "Celery ID": self.request.id,
    }

    # Setup worker-specific logging with banner
    if log_dir:
        setup_worker_logging(log_dir, worker_id, worker_metadata)

    logger.info(f"Worker starting")

    # Initialize database connection for this worker process
    from .core import Config
    config = Config.from_env()
    db = MongoDB.connect(config.mongodb_url, config.mongodb_db)
    repos = init_repos(db)

    # Create worker record
    worker = Worker(
        worker_id=worker_id,
        celery_job_id=self.request.id,
        task_id=task_id,
        job_type=job_type,
        fuzzer=fuzzer,
        sanitizer=sanitizer,
        workspace_path=workspace_path,
        status=WorkerStatus.BUILDING,
    )
    repos.workers.save(worker)

    try:
        # Step 1: Build fuzzer with specific sanitizer
        logger.info(f"Building fuzzer with {sanitizer} sanitizer")
        worker.status = WorkerStatus.BUILDING
        repos.workers.save(worker)

        from .worker.builder import WorkerBuilder
        builder = WorkerBuilder(workspace_path, project_name, sanitizer)
        build_success, build_msg = builder.build()

        if not build_success:
            raise Exception(f"Build failed: {build_msg}")

        # Step 2: Run fuzzing strategies
        logger.info(f"Running fuzzing strategies")
        worker.status = WorkerStatus.RUNNING
        repos.workers.save(worker)

        from .worker.executor import WorkerExecutor
        executor = WorkerExecutor(
            workspace_path=workspace_path,
            project_name=project_name,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            job_type=job_type,
            repos=repos,
            task_id=task_id,
        )
        result = executor.run()

        # Step 3: Mark completed
        worker.status = WorkerStatus.COMPLETED
        worker.povs_found = result.get("povs_found", 0)
        worker.patches_found = result.get("patches_found", 0)
        worker.finished_at = datetime.now()
        repos.workers.save(worker)

        logger.info(f"Completed: POVs={result.get('povs_found', 0)}, Patches={result.get('patches_found', 0)}")

        # Step 4: Cleanup workspace (keep results)
        from .worker.cleanup import cleanup_worker_workspace
        cleanup_worker_workspace(workspace_path)

        return {
            "worker_id": worker_id,
            "status": "completed",
            "povs_found": result.get("povs_found", 0),
            "patches_found": result.get("patches_found", 0),
        }

    except Exception as e:
        logger.exception(f"Failed: {e}")

        worker.status = WorkerStatus.FAILED
        worker.error_msg = str(e)
        worker.finished_at = datetime.now()
        repos.workers.save(worker)

        return {
            "worker_id": worker_id,
            "status": "failed",
            "error": str(e),
        }
