"""
Analyzer Celery Tasks

Celery task for running the Code Analyzer.
Called by Controller, returns results for Worker dispatch.
"""

import time
from datetime import datetime

from loguru import logger

from ..celery_app import app
from ..db import MongoDB, init_repos
from ..core import Config
from ..core.logging import get_logo
from .models import AnalyzeRequest, AnalyzeResult
from .builder import AnalyzerBuilder
from .importer import StaticAnalysisImporter


def _log_to_db(repos, task_id: str, step: str, progress: str):
    """Update task status in database."""
    try:
        repos.tasks.collection.update_one(
            {"task_id": task_id},
            {"$set": {
                "analyze_step": step,
                "analyze_progress": progress,
                "status": "analyzing",
            }}
        )
    except Exception:
        pass  # Best effort


@app.task(bind=True, name="analyzer.run")
def run_analyzer(_self, request_dict: dict) -> dict:
    """
    Run the Code Analyzer.

    This task:
    1. Builds fuzzers with all sanitizers
    2. Builds coverage fuzzer
    3. Runs introspector for static analysis
    4. Imports results to MongoDB

    Args:
        request_dict: AnalyzeRequest as dict

    Returns:
        AnalyzeResult as dict
    """
    request = AnalyzeRequest.from_dict(request_dict)
    task_id = request.task_id

    # Initialize database connection
    config = Config.from_env()
    db = MongoDB.connect(config.mongodb_url, config.mongodb_db)
    repos = init_repos(db)

    def log(msg: str, level: str = "INFO"):
        """Log using loguru."""
        if level == "ERROR":
            logger.error(f"[Analyzer] {msg}")
        elif level == "WARN":
            logger.warning(f"[Analyzer] {msg}")
        else:
            logger.info(f"[Analyzer] {msg}")

    # Print Analyzer banner
    analyzer_banner = get_logo("analyzer")
    logger.info("\n" + analyzer_banner)
    logger.info(f"Task ID:      {task_id}")
    logger.info(f"Project:      {request.project_name}")
    logger.info(f"Sanitizers:   {', '.join(request.sanitizers)}")
    logger.info(f"Start Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("-" * 80)

    log(f"Starting analysis...")

    build_start = time.time()

    # Update status
    _log_to_db(repos, task_id, "building", "0/5")

    # Step 1: Build all fuzzers
    builder = AnalyzerBuilder(
        task_path=request.task_path,
        project_name=request.project_name,
        sanitizers=request.sanitizers,
        ossfuzz_project=request.ossfuzz_project,
        log_callback=log,
    )

    success, msg = builder.build_all()

    build_duration = time.time() - build_start

    if not success:
        log(f"Build failed: {msg}", "ERROR")
        return AnalyzeResult(
            success=False,
            task_id=task_id,
            error_msg=msg,
            build_duration_seconds=build_duration,
        ).to_dict()

    log(f"Build completed in {build_duration:.1f}s")

    # Update status
    _log_to_db(repos, task_id, "analyzing", "4/5")

    # Step 2: Import static analysis data
    analysis_start = time.time()
    static_analysis_ready = False
    reachable_count = 0

    introspector_path = builder.get_introspector_path()
    if introspector_path:
        log("Importing static analysis data to MongoDB")

        importer = StaticAnalysisImporter(
            task_id=task_id,
            introspector_path=introspector_path,
            repo_path=str(request.task_path) + "/repo",
            repos=repos,
            log_callback=log,
        )

        import_success, import_msg = importer.import_all()
        if import_success:
            static_analysis_ready = True
            reachable_count = importer.functions_imported
            log(f"Static analysis import: {import_msg}")
        else:
            log(f"Static analysis import failed: {import_msg}", "WARN")
    else:
        log("No introspector data available, skipping static analysis import", "WARN")

    analysis_duration = time.time() - analysis_start

    # Update status
    _log_to_db(repos, task_id, "completed", "5/5")

    # Build result
    result = AnalyzeResult(
        success=True,
        task_id=task_id,
        fuzzers=builder.get_fuzzers(),
        build_paths=builder.get_build_paths(),
        coverage_fuzzer_path=builder.get_coverage_path(),
        static_analysis_ready=static_analysis_ready,
        reachable_functions_count=reachable_count,
        build_duration_seconds=build_duration,
        analysis_duration_seconds=analysis_duration,
    )

    log(f"Analysis completed. {len(result.fuzzers)} fuzzers, {reachable_count} functions")

    return result.to_dict()


def run_analyzer_sync(request: AnalyzeRequest) -> AnalyzeResult:
    """
    Run analyzer synchronously (for testing or CLI mode).

    Args:
        request: AnalyzeRequest

    Returns:
        AnalyzeResult
    """
    result_dict = run_analyzer(request.to_dict())
    return AnalyzeResult.from_dict(result_dict)
