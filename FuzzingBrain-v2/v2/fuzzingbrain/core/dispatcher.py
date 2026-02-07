"""
Worker Dispatcher

Handles worker task dispatch:
1. Generate {fuzzer, sanitizer} pairs
2. Create worker workspaces
3. Dispatch Celery tasks
4. Monitor progress
5. Task-level FuzzerMonitor management
"""

import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional

from bson import ObjectId

from .logging import logger
from .config import Config
from .models import Task, Fuzzer, FuzzerStatus, Worker, WorkerStatus
from ..db import RepositoryManager
from ..analyzer import AnalyzeResult
from ..fuzzer.monitor import FuzzerMonitor


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
        self.project_name = config.ossfuzz_project_name or task.project_name
        self.analyze_result = analyze_result
        self.pov_count_target = config.pov_count  # Target POV count (0 = unlimited)
        self._task_oid = ObjectId(task.task_id)  # Cached ObjectId for MongoDB queries

        # Redis client for real-time budget reads (millisecond latency vs MongoDB's 2-7s)
        self._redis = self._connect_redis(config.redis_url)

        # Task-level FuzzerMonitor (auto-discovers crash directories)
        docker_image = f"gcr.io/oss-fuzz/{self.project_name}"

        # Get log directory for FuzzerMonitor log file
        from .logging import get_log_dir

        log_dir = get_log_dir()

        self.crash_monitor: Optional[FuzzerMonitor] = FuzzerMonitor(
            task_id=task.task_id,
            workspace_path=Path(task.task_path),
            auto_discover=True,
            docker_image=docker_image,
            on_crash=self._on_crash_found,
            log_dir=log_dir,
            repos=repos,
        )

    def _on_crash_found(self, crash_record) -> None:
        """
        Callback when FuzzerMonitor finds a new crash.

        Creates POV record, generates report, and activates POV.
        Note: This is called from FuzzerMonitor's background thread.

        Args:
            crash_record: CrashRecord from the monitor
        """
        import base64
        from pathlib import Path
        from .models import POV
        from .pov_packager import POVPackager
        from .utils import generate_id

        logger.info(
            f"[FuzzerMonitor] New crash detected: {crash_record.crash_hash[:8]} "
            f"(worker={crash_record.worker_id[:20]}..., vuln={crash_record.vuln_type})"
        )

        try:
            # 1. Read crash file bytes
            crash_path = Path(crash_record.crash_path)
            if not crash_path.exists():
                logger.error(f"[FuzzerMonitor] Crash file not found: {crash_path}")
                return

            crash_blob = crash_path.read_bytes()
            crash_blob_b64 = base64.b64encode(crash_blob).decode("utf-8")

            # 2. Re-verify crash to get proper sanitizer output (FuzzerMonitor may have failed)
            vuln_type = crash_record.vuln_type
            sanitizer_output = crash_record.sanitizer_output or ""

            if not sanitizer_output and self.analyze_result:
                # Try to verify using correct fuzzer path from analyze_result
                fuzzer_path = self.analyze_result.get_fuzzer_path(
                    crash_record.fuzzer_name, crash_record.sanitizer
                )
                if fuzzer_path:
                    verify_result = self._verify_crash_with_docker(
                        crash_blob,
                        fuzzer_path,
                        crash_record.sanitizer,
                    )
                    if verify_result:
                        vuln_type = verify_result.get("vuln_type") or vuln_type
                        sanitizer_output = verify_result.get("output", "")
                        logger.info(
                            f"[FuzzerMonitor] Re-verified crash: vuln_type={vuln_type}"
                        )

            # 3. Create POV record
            pov_id = generate_id()
            task_workspace = Path(self.task.task_path)
            results_dir = task_workspace / "results"
            povs_dir = results_dir / "povs"
            povs_dir.mkdir(parents=True, exist_ok=True)

            # Copy crash file to povs directory
            pov_blob_path = povs_dir / f"crash_{crash_record.crash_hash[:16]}.bin"
            pov_blob_path.write_bytes(crash_blob)

            # Determine source type from crash_record
            source = crash_record.source  # "global_fuzzer" | "sp_fuzzer"

            pov = POV(
                pov_id=pov_id,
                task_id=self.task.task_id,
                suspicious_point_id=crash_record.sp_id or "",  # SP ID if from SP Fuzzer
                generation_id=generate_id(),
                source=source,  # Track POV source
                source_worker_id=crash_record.worker_id,  # Track which worker found it
                iteration=0,
                attempt=1,
                variant=1,
                blob=crash_blob_b64,
                blob_path=str(pov_blob_path),
                gen_blob=f"""# Fuzzer-discovered crash
# Source: {source}
# Hash: {crash_record.crash_hash}
# Type: {vuln_type}
# Worker: {crash_record.worker_id}

import base64

POV_BLOB_B64 = "{crash_blob_b64}"

def generate(variant: int = 1) -> bytes:
    return base64.b64decode(POV_BLOB_B64)
""",
                vuln_type=vuln_type,
                harness_name=crash_record.fuzzer_name,
                sanitizer=crash_record.sanitizer,
                sanitizer_output=sanitizer_output[:10000] if sanitizer_output else "",
                description=f"Fuzzer-discovered crash ({source})",
                is_successful=False,  # Will be set True after packaging
                is_active=True,
            )

            # Save POV to database
            self.repos.povs.save(pov)
            logger.info(f"[FuzzerMonitor] POV {pov_id[:8]} created (pending report)")

            # 3. Package POV with report
            analyzer_socket = (
                self.analyze_result.socket_path if self.analyze_result else None
            )
            packager = POVPackager(
                str(results_dir),
                task_id=self.task.task_id,
                worker_id=crash_record.worker_id,
                repos=self.repos,
                analyzer_socket_path=analyzer_socket,
            )

            # Package synchronously (we're in a background thread)
            pov_dict = pov.to_dict()
            zip_path = packager.package_pov(pov_dict, None)  # No SP for fuzzer crashes

            if zip_path:
                logger.info(f"[FuzzerMonitor] ✅ POV {pov_id[:8]} packaged: {zip_path}")
                # Activate POV
                self.repos.povs.update(pov_id, {"is_successful": True})
                logger.info(f"[FuzzerMonitor] ✅ POV {pov_id[:8]} activated!")

                # Update worker's pov_generated count
                try:
                    worker_obj = self.repos.workers.find_by_id(crash_record.worker_id)
                    if worker_obj:
                        current_count = worker_obj.pov_generated or 0
                        self.repos.workers.update(
                            crash_record.worker_id,
                            {"pov_generated": current_count + 1},
                        )
                except Exception as e:
                    logger.debug(
                        f"[FuzzerMonitor] Failed to update worker POV count: {e}"
                    )
            else:
                logger.warning(f"[FuzzerMonitor] Failed to package POV {pov_id[:8]}")

        except Exception as e:
            logger.error(f"[FuzzerMonitor] Error processing crash: {e}")
            import traceback

            logger.debug(traceback.format_exc())

    def _verify_crash_with_docker(
        self,
        crash_blob: bytes,
        fuzzer_path: str,
        sanitizer: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Verify a crash by running it against the fuzzer in Docker.

        Args:
            crash_blob: The crash data
            fuzzer_path: Path to the fuzzer binary
            sanitizer: Sanitizer type

        Returns:
            Dict with 'vuln_type' and 'output', or None if verification failed
        """
        import hashlib
        import re
        import subprocess
        import tempfile
        from pathlib import Path

        docker_image = f"gcr.io/oss-fuzz/{self.project_name}"
        fuzzer_path = Path(fuzzer_path)
        fuzzer_dir = fuzzer_path.parent
        fuzzer_binary = fuzzer_path.name

        try:
            # Write crash to temp file
            crash_hash = hashlib.sha1(crash_blob).hexdigest()[:16]
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=f"_{crash_hash}.bin"
            ) as f:
                f.write(crash_blob)
                temp_blob = Path(f.name)

            # Build Docker command
            cmd = [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--entrypoint",
                "",
                "-e",
                "FUZZING_ENGINE=libfuzzer",
                "-e",
                f"SANITIZER={sanitizer}",
                "-e",
                "ARCHITECTURE=x86_64",
                "-v",
                f"{fuzzer_dir}:/fuzzers:ro",
                "-v",
                f"{temp_blob.parent}:/work",
                docker_image,
                f"/fuzzers/{fuzzer_binary}",
                "-timeout=30",
                f"/work/{temp_blob.name}",
            ]

            logger.debug(f"[FuzzerMonitor] Verifying crash: {' '.join(cmd[:10])}...")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            combined_output = result.stderr + "\n" + result.stdout

            # Parse vulnerability type
            vuln_type = None
            vuln_patterns = [
                (r"AddressSanitizer: ([\w-]+)", 1),
                (r"MemorySanitizer: ([\w-]+)", 1),
                (r"UndefinedBehaviorSanitizer: ([\w-]+)", 1),
                (r"ThreadSanitizer: ([\w-]+)", 1),
            ]
            for pattern, group in vuln_patterns:
                match = re.search(pattern, combined_output)
                if match:
                    vuln_type = match.group(group).strip()
                    break

            # Cleanup
            temp_blob.unlink(missing_ok=True)

            return {
                "vuln_type": vuln_type,
                "output": combined_output,
            }

        except subprocess.TimeoutExpired:
            logger.warning("[FuzzerMonitor] Crash verification timed out")
            return None
        except Exception as e:
            logger.warning(f"[FuzzerMonitor] Crash verification failed: {e}")
            return None

    def _connect_redis(self, redis_url: str):
        """Connect sync Redis client for real-time cost reads."""
        try:
            import redis as sync_redis

            client = sync_redis.Redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            client.ping()
            logger.info(f"Dispatcher Redis connected: {redis_url}")
            return client
        except Exception as e:
            logger.warning(f"Dispatcher Redis connection failed: {e}, falling back to MongoDB for budget checks")
            return None

    def _get_realtime_cost(self) -> float:
        """
        Get real-time task cost from Redis (millisecond latency).

        Falls back to MongoDB if Redis is unavailable.
        """
        COUNTER_PREFIX = "fuzzingbrain:counters"

        # Try Redis first (real-time, sub-millisecond)
        if self._redis:
            try:
                cost_str = self._redis.get(f"{COUNTER_PREFIX}:task:{self.task.task_id}:cost")
                if cost_str is not None:
                    return float(cost_str)
                # Key doesn't exist yet (no LLM calls made) — cost is 0
                return 0.0
            except Exception as e:
                logger.warning(f"Redis cost read failed: {e}, falling back to MongoDB")

        # Fallback to MongoDB
        task_doc = self.repos.tasks.collection.find_one(
            {"_id": self._task_oid},
            {"llm_cost": 1},
        )
        return (task_doc or {}).get("llm_cost", 0.0)

    def _close_redis(self) -> None:
        """Close Redis connection."""
        if self._redis:
            try:
                self._redis.close()
            except Exception:
                pass
            self._redis = None

    def dispatch(self, fuzzers: List[Fuzzer]) -> List[Dict[str, Any]]:
        """
        Dispatch worker tasks for all {fuzzer, sanitizer} pairs.

        Also starts the Task-level FuzzerMonitor.

        Args:
            fuzzers: List of successfully built fuzzers

        Returns:
            List of dispatched job info
        """
        # Start Task-level FuzzerMonitor
        if self.crash_monitor:
            self.crash_monitor.start_monitoring()
            logger.info(
                f"Started Task-level FuzzerMonitor (auto-discover={self.crash_monitor.auto_discover})"
            )

        # Filter to only successful fuzzers
        successful_fuzzers = [f for f in fuzzers if f.status == FuzzerStatus.SUCCESS]

        if not successful_fuzzers:
            logger.warning("No successful fuzzers to dispatch")
            return []

        # Apply fuzzer filter if specified
        if self.config.fuzzer_filter:
            filter_set = set(self.config.fuzzer_filter)
            before_count = len(successful_fuzzers)
            successful_fuzzers = [
                f for f in successful_fuzzers if f.fuzzer_name in filter_set
            ]
            logger.info(
                f"Fuzzer filter applied: {before_count} -> {len(successful_fuzzers)} fuzzers (filter: {self.config.fuzzer_filter})"
            )

            if not successful_fuzzers:
                logger.warning(
                    f"No fuzzers match the filter: {self.config.fuzzer_filter}"
                )
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
                pairs.append(
                    {
                        "fuzzer": fuzzer.fuzzer_name,
                        "sanitizer": sanitizer,
                    }
                )
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
        worker_workspace = (
            task_workspace
            / "worker_workspace"
            / f"{self.project_name}_{fuzzer}_{sanitizer}"
        )

        # Remove if exists
        if worker_workspace.exists():
            shutil.rmtree(worker_workspace)

        worker_workspace.mkdir(parents=True, exist_ok=True)

        # Copy repo (symlinks=True to avoid following self-referencing symlinks)
        src_repo = task_workspace / "repo"
        if src_repo.exists():
            shutil.copytree(src_repo, worker_workspace / "repo", symlinks=True)
            logger.debug(f"Copied repo to {worker_workspace / 'repo'}")

        # Copy fuzz-tooling
        src_fuzz_tooling = task_workspace / "fuzz-tooling"
        if src_fuzz_tooling.exists():
            shutil.copytree(
                src_fuzz_tooling, worker_workspace / "fuzz-tooling", symlinks=True
            )
            logger.debug(f"Copied fuzz-tooling to {worker_workspace / 'fuzz-tooling'}")

        # Copy diff (if exists)
        src_diff = task_workspace / "diff"
        if src_diff.exists():
            shutil.copytree(src_diff, worker_workspace / "diff", symlinks=True)
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

        Note: Worker record is NOT created here. WorkerContext creates
        the Worker record when the Celery task starts executing.

        Args:
            pair: {fuzzer, sanitizer} pair
            workspace_path: Path to worker workspace

        Returns:
            Job info dictionary
        """
        from ..worker.tasks import run_worker

        fuzzer = pair["fuzzer"]
        sanitizer = pair["sanitizer"]
        display_name = Worker.generate_display_name(fuzzer, sanitizer)

        # Get log directory from current logging config
        from .logging import get_log_dir

        log_dir = get_log_dir()

        # Get pre-built fuzzer path from analyze_result
        fuzzer_binary_path = None
        build_dir = None
        if self.analyze_result:
            fuzzer_binary_path = self.analyze_result.get_fuzzer_path(fuzzer, sanitizer)
            build_dir = self.analyze_result.build_paths.get(sanitizer)

        # Prepare assignment - WorkerContext will create Worker record
        assignment = {
            "task_id": self.task.task_id,
            "fuzzer": fuzzer,
            "sanitizer": sanitizer,
            "task_type": self.task.task_type.value,
            "workspace_path": workspace_path,
            "project_name": self.project_name,
            "log_dir": str(log_dir) if log_dir else None,
            # Pre-built fuzzer info from Analyzer
            "fuzzer_binary_path": fuzzer_binary_path,
            "build_dir": build_dir,
            "coverage_fuzzer_path": self.analyze_result.coverage_fuzzer_path
            if self.analyze_result
            else None,
            # Analysis Server socket for code queries
            "analysis_socket_path": self.analyze_result.socket_path
            if self.analyze_result
            else None,
            # Scan mode and diff path for delta mode
            "scan_mode": self.task.scan_mode.value,
            "diff_path": str(Path(workspace_path) / "diff" / "ref.diff")
            if self.task.scan_mode.value == "delta"
            else None,
            # Evaluation server for cost tracking
            "eval_server": self.config.eval_server,
            "budget_limit": self.config.budget_limit,
            "pov_count": self.config.pov_count,
        }

        # Dispatch Celery task with dynamic time limit based on config
        timeout_seconds = self.config.timeout_minutes * 60
        soft_timeout_seconds = int(timeout_seconds * 0.9)

        result = run_worker.apply_async(
            args=[assignment],
            time_limit=timeout_seconds,
            soft_time_limit=soft_timeout_seconds,
        )

        # Note: Celery job ID is passed to WorkerContext via assignment
        # We add it here for the worker to use
        assignment["celery_job_id"] = result.id

        logger.info(f"Dispatched worker: {display_name} (celery_id: {result.id})")

        return {
            "display_name": display_name,
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

        Note: Workers are created by WorkerContext when Celery task starts,
        so initially there may be fewer workers than dispatched jobs.

        Returns:
            Status summary dictionary
        """
        from celery.result import AsyncResult
        from bson import ObjectId
        from ..celery_app import app

        # Query workers by task_id (ObjectId)
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
            if (
                worker_status in ["pending", "building", "running"]
                and worker.celery_job_id
            ):
                try:
                    result = AsyncResult(worker.celery_job_id, app=app)
                    if result.failed():
                        # Celery task failed but DB not updated - mark as failed
                        worker.status = WorkerStatus.FAILED
                        worker.error_msg = (
                            str(result.result) if result.result else "Task failed"
                        )
                        self.repos.workers.save(worker)
                        worker_status = "failed"
                        logger.warning(
                            f"Worker {worker.display_name} failed (detected via Celery)"
                        )
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

    def get_verified_pov_count(self) -> int:
        """Get count of verified (successful) POVs for this task."""
        return self.repos.povs.count(
            {
                "task_id": self._task_oid,
                "is_successful": True,
            }
        )

    def graceful_shutdown(self) -> None:
        """
        Gracefully shutdown all running workers.

        Revokes Celery tasks and marks workers as completed.
        """
        from ..celery_app import app

        workers = self.repos.workers.find_by_task(self.task.task_id)

        for worker in workers:
            if worker.status.value in ["pending", "building", "running"]:
                # Revoke Celery task (terminate=True for immediate stop)
                if worker.celery_job_id:
                    try:
                        app.control.revoke(worker.celery_job_id, terminate=True)
                        logger.info(f"Revoked worker: {worker.display_name}")
                    except Exception as e:
                        logger.warning(f"Failed to revoke {worker.display_name}: {e}")

                # Mark as completed (graceful shutdown)
                worker.status = WorkerStatus.COMPLETED
                worker.error_msg = "Graceful shutdown: POV target reached"
                self.repos.workers.save(worker)

    def shutdown_all_fuzzers(self) -> None:
        """
        Shutdown all Global Fuzzers and FuzzerMonitors.

        Called when task truly ends (timeout/budget/pov_target/manual).
        This performs final sweep to catch any remaining crashes.
        """
        import asyncio
        from ..fuzzer import get_fuzzer_manager, unregister_fuzzer_manager

        logger.info("Shutting down all Global Fuzzers...")

        workers = self.repos.workers.find_by_task(self.task.task_id)
        shutdown_count = 0

        for worker in workers:
            # FuzzerManager is registered with ObjectId-based worker_id
            manager = get_fuzzer_manager(worker.worker_id)
            if manager:
                try:
                    # Run full shutdown (includes final sweep)
                    try:
                        loop = asyncio.get_event_loop()
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)

                    if loop.is_running():
                        # Schedule shutdown task
                        asyncio.create_task(manager.shutdown())
                    else:
                        loop.run_until_complete(manager.shutdown())

                    shutdown_count += 1
                    logger.info(f"Shutdown FuzzerManager: {worker.display_name}")
                except Exception as e:
                    logger.warning(
                        f"Failed to shutdown FuzzerManager {worker.display_name}: {e}"
                    )
                finally:
                    unregister_fuzzer_manager(worker.worker_id)

        logger.info(f"Shutdown {shutdown_count} FuzzerManager(s)")

        # Stop Task-level FuzzerMonitor (includes final sweep)
        if self.crash_monitor:
            self.crash_monitor.stop_monitoring()
            crash_stats = self.crash_monitor.get_stats()
            logger.info(
                f"Task-level FuzzerMonitor stopped: "
                f"{crash_stats['total_crashes']} crashes found"
            )

    def wait_for_completion(
        self,
        timeout_minutes: int = 60,
        poll_interval: int = 5,
        on_progress: callable = None,
    ) -> Dict[str, Any]:
        """
        Wait for task to complete (CLI mode).

        Task ends when one of:
        - Timeout reached
        - Budget exceeded
        - POV target reached
        - User manual shutdown (Ctrl+C)

        Note: "All workers completed" does NOT end the task!
        Global Fuzzer continues running until one of the above conditions.

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
        last_pov_count = 0
        global_fuzzer_only_logged = False  # Only log once

        if self.pov_count_target > 0:
            logger.info(
                f"Waiting for task to complete (timeout: {timeout_minutes}min, pov_target: {self.pov_count_target})"
            )
        else:
            logger.info(f"Waiting for task to complete (timeout: {timeout_minutes}min)")

        try:
            while True:
                elapsed = datetime.now() - start_time

                # ================================================================
                # Exit condition 1: Timeout
                # ================================================================
                if elapsed > timeout_delta:
                    logger.warning(f"Timeout reached after {timeout_minutes} minutes")
                    self.shutdown_all_fuzzers()
                    self._close_redis()
                    return {
                        "status": "timeout",
                        "elapsed_minutes": elapsed.total_seconds() / 60,
                        **self.get_status(),
                    }

                # ================================================================
                # Exit condition 2: Budget exceeded
                # ================================================================
                if self.config.budget_limit > 0:
                    current_cost = self._get_realtime_cost()
                    if current_cost >= self.config.budget_limit:
                        logger.warning(
                            f"Budget limit exceeded: ${current_cost:.2f} >= ${self.config.budget_limit:.2f}"
                        )
                        self.graceful_shutdown()
                        self.shutdown_all_fuzzers()
                        self._close_redis()
                        return {
                            "status": "budget_exceeded",
                            "elapsed_minutes": elapsed.total_seconds() / 60,
                            "error": f"Budget exceeded: ${current_cost:.2f} >= ${self.config.budget_limit:.2f}",
                            **self.get_status(),
                        }

                # ================================================================
                # Exit condition 3: POV target reached
                # ================================================================
                current_pov_count = self.get_verified_pov_count()
                if current_pov_count != last_pov_count:
                    logger.info(
                        f"Verified POVs: {current_pov_count}"
                        + (f"/{self.pov_count_target}" if self.pov_count_target > 0 else "")
                    )
                    last_pov_count = current_pov_count

                if self.pov_count_target > 0 and current_pov_count >= self.pov_count_target:
                    logger.info(
                        f"POV target reached! ({current_pov_count}/{self.pov_count_target})"
                    )
                    logger.info("Initiating graceful shutdown...")
                    self.graceful_shutdown()
                    self.shutdown_all_fuzzers()
                    self._close_redis()
                    return {
                        "status": "pov_target_reached",
                        "elapsed_minutes": elapsed.total_seconds() / 60,
                        "pov_count": current_pov_count,
                        **self.get_status(),
                    }

                # ================================================================
                # Status check: Workers progress
                # ================================================================
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

                # ================================================================
                # All workers completed: Enter "Global Fuzzer Only" mode
                # ================================================================
                if self.is_complete() and not global_fuzzer_only_logged:
                    logger.info("")
                    logger.info("=" * 60)
                    logger.info(
                        f"All Workers Completed with {current_pov_count} POV(s) found"
                    )
                    logger.info("Global Fuzzer continues running...")
                    logger.info("Waiting for: timeout / budget / POV target / Ctrl+C")
                    logger.info("=" * 60)
                    logger.info("")
                    global_fuzzer_only_logged = True

                # Wait before next poll
                time.sleep(poll_interval)

        except KeyboardInterrupt:
            logger.warning("KeyboardInterrupt received — shutting down fuzzers and cleaning up")
            self.shutdown_all_fuzzers()
            self._close_redis()
            raise

    def get_results(self) -> List[Dict[str, Any]]:
        """
        Get results from all completed workers.

        Returns:
            List of worker results with duration info and SP count
        """
        workers = self.repos.workers.find_by_task(self.task.task_id)
        results = []

        for worker in workers:
            # Count SPs for this worker (by sources array with $elemMatch)
            sp_count = self.repos.suspicious_points.count(
                {
                    "task_id": self._task_oid,
                    "sources": {
                        "$elemMatch": {
                            "harness_name": worker.fuzzer,
                            "sanitizer": worker.sanitizer,
                        }
                    },
                }
            )

            # Count merged duplicates for this worker
            # (SPs where this worker's description was merged into existing SP)
            merged_count = self.repos.suspicious_points.count(
                {
                    "task_id": self._task_oid,
                    "merged_duplicates": {
                        "$elemMatch": {
                            "harness_name": worker.fuzzer,
                            "sanitizer": worker.sanitizer,
                        }
                    },
                }
            )

            # Query actual successful POV count from DB (more reliable than worker's self-report)
            # This handles cases where worker was killed but POVs were already saved
            #
            # Count POVs by suspicious_point_id to include cross-fuzzer hits:
            # - A POV created for fuzzer "xml" might crash on "xpath" instead
            # - The cross-fuzzer POV has harness_name="xpath" but same suspicious_point_id
            # - We want to count it for the worker that created the original SP
            #
            # Get all SP IDs created by this worker
            worker_sp_ids = [
                sp.suspicious_point_id
                for sp in self.repos.suspicious_points.find_all(
                    {
                        "task_id": self._task_oid,
                        "sources": {
                            "$elemMatch": {
                                "harness_name": worker.fuzzer,
                                "sanitizer": worker.sanitizer,
                            }
                        },
                    }
                )
            ]

            # Count all successful POVs for those SPs (including cross-fuzzer hits)
            if worker_sp_ids:
                # Convert str IDs to ObjectId — POV documents store suspicious_point_id as ObjectId
                worker_sp_oids = []
                for sp_id in worker_sp_ids:
                    try:
                        worker_sp_oids.append(ObjectId(sp_id))
                    except Exception:
                        worker_sp_oids.append(sp_id)
                actual_pov_count = self.repos.povs.count(
                    {
                        "task_id": self._task_oid,
                        "suspicious_point_id": {"$in": worker_sp_oids},
                        "is_successful": True,
                    }
                )
            else:
                actual_pov_count = 0

            # Also count fuzzer-discovered POVs (no SP association)
            # These have suspicious_point_id="" because they were found directly by the fuzzer
            fuzzer_discovered_count = self.repos.povs.count(
                {
                    "task_id": self._task_oid,
                    "harness_name": worker.fuzzer,
                    "sanitizer": worker.sanitizer,
                    "suspicious_point_id": {"$in": ["", None]},
                    "is_successful": True,
                }
            )
            actual_pov_count += fuzzer_discovered_count

            # Determine effective status:
            # - If worker failed but has results (SPs or POVs), mark as "interrupted"
            # - This handles timeout cases where work was done but Celery task was killed
            effective_status = worker.status.value
            if effective_status == "failed" and (sp_count > 0 or actual_pov_count > 0):
                effective_status = "interrupted"

            result = {
                "worker_id": worker.display_name,  # Use display name for summaries
                "worker_object_id": worker.worker_id,  # ObjectId for DB queries
                "fuzzer": worker.fuzzer,
                "sanitizer": worker.sanitizer,
                "status": effective_status,
                "sps_found": sp_count,
                "sps_merged": merged_count,
                "pov_generated": actual_pov_count,  # Use DB count instead of worker's self-report
                "patch_generated": worker.patch_generated or 0,
                "error_msg": worker.error_msg,
                "duration_seconds": worker.get_duration_seconds(),
                "duration_str": worker.get_duration_str(),
            }
            results.append(result)

        return results
