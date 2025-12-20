"""
Celery Task Definitions

Defines the tasks that can be executed by Celery workers.
"""

from datetime import datetime
from typing import Dict, Any

from .celery_app import app
from .core import logger
from .core.models import Worker, WorkerStatus
from .db import MongoDB, init_repos


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

    Returns:
        Result dictionary with status and findings
    """
    task_id = assignment["task_id"]
    fuzzer = assignment["fuzzer"]
    sanitizer = assignment["sanitizer"]
    workspace_path = assignment["workspace_path"]
    job_type = assignment["job_type"]
    project_name = assignment["project_name"]

    worker_id = f"{task_id}__{fuzzer}__{sanitizer}"

    logger.info(f"Worker starting: {worker_id}")

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
        logger.info(f"[{worker_id}] Building fuzzer with {sanitizer} sanitizer")
        worker.status = WorkerStatus.BUILDING
        repos.workers.save(worker)

        from .worker.builder import WorkerBuilder
        builder = WorkerBuilder(workspace_path, project_name, sanitizer)
        build_success, build_msg = builder.build()

        if not build_success:
            raise Exception(f"Build failed: {build_msg}")

        # Step 2: Run fuzzing strategies
        logger.info(f"[{worker_id}] Running fuzzing strategies")
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

        logger.info(f"[{worker_id}] Completed: {result}")

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
        logger.exception(f"[{worker_id}] Failed: {e}")

        worker.status = WorkerStatus.FAILED
        worker.error_msg = str(e)
        worker.finished_at = datetime.now()
        repos.workers.save(worker)

        return {
            "worker_id": worker_id,
            "status": "failed",
            "error": str(e),
        }
