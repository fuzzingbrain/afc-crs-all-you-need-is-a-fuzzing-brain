# SPDX-License-Identifier: Apache-2.0
"""
Celery task: one worker, one harness.

The dispatcher has already inserted the worker row; the assignment carries
its id, the harness id and the harness's binaries. The row's lifecycle is
WorkerContext's (via WorkerExecutor.run()).
"""

import sys
import traceback
from datetime import datetime
from typing import Dict, Any

from loguru import logger

from ..celery_app import app
from ..core.config import DEFAULT_MAX_PARALLEL_FUZZERS
from ..core.logging import (
    set_log_dir,
    setup_worker_logging,
)
from ..db.store import get_store
from .scope import WorkerScope, set_scope


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
    Run one worker (one harness).

    Args:
        assignment: Dictionary containing:
            - run_id, worker_id, harness_id: str
            - fuzzer: str (the harness)
            - sanitizers: [str], binaries: {sanitizer: path}
            - sanitizer: str (the default, sanitizers[0])
            - task_type: str (poc | patch | poc-patch | harness)
            - workspace_path: str
            - project_name: str
            - log_dir: str (optional)

    Returns:
        Result dictionary with status and findings
    """
    run_id = assignment["run_id"]
    worker_id = assignment["worker_id"]
    harness_id = assignment["harness_id"]
    fuzzer = assignment["fuzzer"]
    sanitizer = assignment["sanitizer"]
    sanitizers = list(assignment.get("sanitizers") or [sanitizer])
    binaries = dict(assignment.get("binaries") or {})
    workspace_path = assignment["workspace_path"]
    run_workspace_path = assignment.get("run_workspace_path")
    task_type = assignment["task_type"]
    project_name = assignment["project_name"]
    log_dir = assignment.get("log_dir")
    # Image the fuzzer binary runs in for PoC verify. From the task JSON when set
    # (a prebuilt/imported binary must run in the image it was built in), else the
    # OSS-Fuzz convention.
    poc_docker_image = assignment["docker_image"]

    # Pre-built fuzzer info from Analyzer (new architecture)
    fuzzer_binary_path = assignment.get("fuzzer_binary_path")
    coverage_fuzzer_path = assignment.get("coverage_fuzzer_path")
    analysis_socket_path = assignment.get("analysis_socket_path")
    index_path = assignment.get("index_path")

    # Scan mode and diff path (for delta mode)
    scan_mode = assignment.get("scan_mode", "full")
    diff_path = assignment.get("diff_path")

    # The run's ceiling on concurrently running fuzzers, enforced by every
    # worker against a shared ledger.
    max_parallel_fuzzers = assignment.get(
        "max_parallel_fuzzers", DEFAULT_MAX_PARALLEL_FUZZERS
    )
    vh_max_count = assignment.get("vh_max_count")
    fuzzer_sources = assignment.get("fuzzer_sources")
    fuzzer_worker = assignment.get("fuzzer_worker") or {}

    # Install this run's concurrency before anything reads it.
    from ..core.concurrency import set_concurrency
    from ..core.config import ConcurrencyConfig

    set_concurrency(ConcurrencyConfig.from_value(assignment["concurrency"]))

    display_name = f"{fuzzer}/{worker_id[:8]}"

    # Build worker metadata for logging
    worker_metadata = {
        "Display Name": display_name,
        "Run ID": run_id,
        "Worker ID": worker_id,
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

    # Install this run's model router (single source of truth for role -> model),
    # now that worker logging is configured so its resolved map lands in worker.log.
    # task fields win over env; from_sources validates and set_active_router logs.
    from ..llms.routing import ModelRouter, set_active_router

    _router = ModelRouter.from_sources(
        task={
            "models": assignment.get("models"),
            "force_model": assignment.get("force_model"),
            "strict_models": assignment.get("strict_models"),
        }
    )
    set_active_router(_router)

    from ..core.fuzzer_spec import set_detect_leaks

    set_detect_leaks(assignment["detect_leaks"])

    # This process works for this run / worker / harness: the tools read it.
    set_scope(
        WorkerScope(
            run_id=run_id,
            worker_id=worker_id,
            harness_id=harness_id,
            harness=fuzzer,
            sanitizers=sanitizers,
            binaries=binaries,
        )
    )
    executor = None
    try:
        get_store()
    except Exception as e:
        logger.exception(f"Failed to reach the database: {e}")
        return {"display_name": display_name, "status": "failed", "error": str(e)}

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
            run_workspace_path=run_workspace_path,
            project_name=project_name,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            task_type=task_type,
            run_id=run_id,
            worker_id=worker_id,
            harness_id=harness_id,
            scan_mode=scan_mode,
            fuzzer_binary_path=fuzzer_binary_path,
            analysis_socket_path=analysis_socket_path,
            index_path=index_path,
            diff_path=diff_path,
            log_dir=log_dir,
            docker_image=poc_docker_image,
            max_parallel_fuzzers=max_parallel_fuzzers,
            vh_max_count=vh_max_count,
            fuzzer_sources=fuzzer_sources,
            fuzzer_worker=fuzzer_worker,
        )
        result = executor.run()

        # Clean up analysis client
        executor.close()

        # Calculate elapsed time
        elapsed_seconds = (datetime.now() - start_time).total_seconds()

        logger.info(
            f"Worker completed in {elapsed_seconds:.0f}s: "
            f"{result.get('poc_generated', 0)} PoC generated"
        )

        # Cleanup workspace (keep results)
        from .cleanup import cleanup_worker_workspace

        cleanup_worker_workspace(workspace_path)

        return {
            "display_name": display_name,
            "worker_id": worker_id,
            "status": "completed",
            "fuzzer": fuzzer,
            "sanitizer": sanitizer,
            "poc_generated": result.get("poc_generated", 0),
            "patch_generated": result.get("patch_generated", 0),
        }

    except Exception as e:
        logger.exception(f"Failed: {e}")

        # Clean up FuzzerManager on error
        try:
            if executor is not None:
                executor.close()
        except Exception as cleanup_err:
            logger.warning(f"Error during cleanup: {cleanup_err}")

        # Calculate elapsed time
        elapsed_seconds = (datetime.now() - start_time).total_seconds()

        logger.error(f"Worker failed after {elapsed_seconds:.0f}s: {e}")
        # WorkerContext closes the row on a failure inside it; this covers one
        # before it opened (end_worker leaves an already-closed row alone).
        try:
            get_store().end_worker(worker_id, "error", error=traceback.format_exc())
        except Exception:
            pass

        return {
            "display_name": display_name,
            "status": "failed",
            "fuzzer": fuzzer,
            "sanitizer": sanitizer,
            "error": str(e),
        }
