# SPDX-License-Identifier: Apache-2.0
"""
Worker dispatch: one worker per harness.

For each harness the run registered:
  1. its workspace (worker_workspace/<harness>/)
  2. its workers row (status queued), inserted here so the Celery task
     carries the id and nothing has to look it up
  3. the Celery task

Then the run is watched until it ends, on the first of

  poc_target   the run has proved config.poc_count distinct bugs
  budget       the LLM spend reached config.budget_limit
  timeout      config.timeout_minutes passed

"All workers finished" does not end a run: their global fuzzers keep going
until one of the three. On the way out every open worker is closed with the
run's reason, every running agent is cancelled, and the run's containers are
killed by label.
"""

import shutil
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import Config
from .logging import logger, get_log_dir


@dataclass
class HarnessUnit:
    """A harness the run registered, with what its worker needs."""

    harness_id: str
    name: str
    binaries: Dict[str, str]  # sanitizer -> binary path
    sanitizers: List[str] = field(default_factory=list)

    @property
    def default_sanitizer(self) -> str:
        return self.sanitizers[0]


# What wait_for_completion returns -> runs.end_reason
END_REASONS = {
    "poc_target_reached": "poc_target",
    "timeout": "timeout",
    "budget_exceeded": "budget",
}


class WorkerDispatcher:
    COUNTER_PREFIX = "fuzzingbrain:counters"
    SHUTDOWN_DEADLINE_SECONDS = 120.0

    def __init__(
        self,
        run_id: str,
        config: Config,
        store,
        harnesses: List[HarnessUnit],
        analyze_result=None,
        celery_queue: Optional[str] = None,
    ):
        self.run_id = str(run_id)
        self.config = config
        self.store = store
        self.harnesses = harnesses
        self.analyze_result = analyze_result
        self.celery_queue = celery_queue
        self.project_name = config.ossfuzz_project_name or config.project_name
        self.workspace = Path(config.workspace)
        self.poc_count_target = config.poc_count
        self._redis = self._connect_redis(config.redis_url)
        # worker id -> celery task id
        self.jobs: Dict[str, str] = {}

    # ------------------------------------------------------------- Redis

    def _connect_redis(self, redis_url: str):
        try:
            import redis as sync_redis

            client = sync_redis.Redis.from_url(
                redis_url, decode_responses=True, socket_connect_timeout=5
            )
            client.ping()
            return client
        except Exception as e:
            logger.warning(f"Dispatcher Redis connection failed ({e}); budget reads the database")
            return None

    def current_cost(self) -> float:
        """The run's LLM spend: the higher of Redis (live) and the database (flushed)."""
        live = 0.0
        if self._redis:
            try:
                v = self._redis.get(f"{self.COUNTER_PREFIX}:run:{self.run_id}:cost")
                live = float(v) if v is not None else 0.0
            except Exception as e:
                logger.warning(f"Redis cost read failed: {e}")
        try:
            stored = self.store.run_cost(self.run_id)
        except Exception:
            stored = 0.0
        return max(live, stored)

    def _close_redis(self) -> None:
        if not self._redis:
            return
        prefix = f"{self.COUNTER_PREFIX}:run:{self.run_id}"
        try:
            self._redis.delete(f"{prefix}:cost", f"{prefix}:calls")
        except Exception as e:
            logger.warning(f"Failed to delete the run's Redis counters: {e}")
        try:
            self._redis.close()
        except Exception:
            pass
        self._redis = None

    # ----------------------------------------------------------- dispatch

    def dispatch(self) -> List[Dict[str, Any]]:
        jobs = []
        for unit in self.harnesses:
            workspace = self._create_worker_workspace(unit.name)
            worker_id = self.store.create_worker(self.run_id, unit.harness_id, workspace)
            celery_id = self._send(unit, str(worker_id), workspace)
            self.store.set_worker_job(worker_id, celery_id)
            self.jobs[str(worker_id)] = celery_id
            jobs.append(
                {
                    "worker_id": str(worker_id),
                    "celery_id": celery_id,
                    "fuzzer": unit.name,
                    "sanitizers": unit.sanitizers,
                    "workspace_path": workspace,
                }
            )
            logger.info(f"Dispatched worker {str(worker_id)[:8]} for {unit.name} (celery {celery_id})")
        return jobs

    def _create_worker_workspace(self, harness: str) -> str:
        path = self.workspace / "worker_workspace" / harness
        if path.exists():
            shutil.rmtree(path)
        (path / "results").mkdir(parents=True, exist_ok=True)
        return str(path)

    def _send(self, unit: HarnessUnit, worker_id: str, workspace: str) -> str:
        from ..worker.tasks import run_worker

        ar = self.analyze_result
        san = unit.default_sanitizer
        log_dir = get_log_dir()
        fw = self.config.fuzzer_worker
        assignment = {
            "run_id": self.run_id,
            "worker_id": worker_id,
            "harness_id": unit.harness_id,
            "fuzzer": unit.name,
            "sanitizer": san,
            "sanitizers": unit.sanitizers,
            "binaries": unit.binaries,
            "fuzzer_binary_path": unit.binaries[san],
            "task_type": self.config.task_type,
            "workspace_path": workspace,
            "run_workspace_path": str(self.workspace),
            "project_name": self.project_name,
            "log_dir": str(log_dir) if log_dir else None,
            "docker_image": self.config.docker_image,
            "detect_leaks": self.config.detect_leaks,
            "models": self.config.models,
            "force_model": self.config.force_model,
            "strict_models": not self.config.allow_fallback,
            "build_dir": ar.build_paths.get(san) if ar else None,
            "coverage_fuzzer_path": ar.coverage_fuzzer_path if ar else None,
            "analysis_socket_path": ar.socket_path if ar else None,
            "index_path": ar.index_path if ar else None,
            "scan_mode": self.config.scan_mode,
            "diff_path": str(self.workspace / "diff" / "ref.diff")
            if self.config.scan_mode == "delta"
            else None,
            "budget_limit": self.config.budget_limit,
            "poc_count": self.config.poc_count,
            "max_parallel_fuzzers": self.config.max_parallel_fuzzers,
            "fuzzer_worker": asdict(fw),
            "vh_max_count": fw.vh_max_count,
            "concurrency": self.config.concurrency.to_dict(),
            "fuzzer_sources": self.config.fuzzer_sources,
        }
        timeout_seconds = self.config.timeout_minutes * 60
        kwargs = {
            "args": [assignment],
            "time_limit": timeout_seconds,
            "soft_time_limit": int(timeout_seconds * 0.9),
        }
        if self.celery_queue:
            kwargs["queue"] = self.celery_queue
        return run_worker.apply_async(**kwargs).id

    # ------------------------------------------------------------- status

    def get_status(self) -> Dict[str, int]:
        """Worker counts by status. A worker whose task is over but whose row
        is still open died without closing it: it is marked lost."""
        from celery.result import AsyncResult

        from ..celery_app import app

        status = {"total": 0, "queued": 0, "running": 0, "completed": 0,
                  "cancelled": 0, "error": 0, "lost": 0}
        for w in self.store.workers(self.run_id):
            st = w.status
            if st in ("queued", "running") and w.celery_job_id:
                try:
                    if AsyncResult(w.celery_job_id, app=app).ready():
                        if self.store.end_worker(w.id, "lost"):
                            logger.warning(f"worker {str(w.id)[:8]}: task ended, row was open -> lost")
                        st = "lost"
                except Exception:
                    pass
            status["total"] += 1
            status[st] = status.get(st, 0) + 1
        return status

    def is_complete(self) -> bool:
        s = self.get_status()
        return s["total"] > 0 and s["queued"] + s["running"] == 0

    def crash_count(self) -> int:
        """Distinct bugs the run has proved (one row per signature)."""
        try:
            return self.store.crash_count(self.run_id)
        except Exception as e:
            logger.warning(f"Could not count crashes: {e}")
            return 0

    # ------------------------------------------------------------ stopping

    def _revoke_workers(self, end_reason: str, status: str = "completed") -> None:
        from ..celery_app import app

        for w in self.store.workers(self.run_id):
            if w.status in ("queued", "running") and w.celery_job_id:
                try:
                    app.control.revoke(w.celery_job_id, terminate=True)
                except Exception as e:
                    logger.warning(f"Failed to revoke worker {str(w.id)[:8]}: {e}")
        n = self.store.end_open_workers(self.run_id, status, end_reason)
        if n:
            logger.info(f"Closed {n} open worker(s): {end_reason}")
        # Their processes are gone; their agents cannot close their own rows.
        self.store.end_running_agents(run_id=self.run_id, status="cancelled")

    def _stop_containers(self) -> None:
        from .docker_limits import kill_run_containers

        try:
            n = kill_run_containers(self.run_id)
            if n:
                logger.info(f"Killed {n} container(s) of this run")
        except Exception as e:
            logger.warning(f"Could not sweep the run's containers: {e}")
        try:
            from ..fuzzer.budget import FuzzerBudget

            FuzzerBudget(run_id=self.run_id, limit=self.config.max_parallel_fuzzers).clear()
        except Exception as e:
            logger.debug(f"Could not clear the fuzzer slot ledger: {e}")

    def stop_everything(
        self, end_reason: Optional[str], deadline: Optional[float] = None, status: str = "completed"
    ) -> bool:
        """Revoke workers, kill containers, close Redis; give up after the deadline.

        On a daemon thread, so a wedged docker or database call cannot hold the
        process past it. Returns True if the shutdown finished.
        """
        import threading

        seconds = self.SHUTDOWN_DEADLINE_SECONDS if deadline is None else deadline
        finished = threading.Event()

        def _run():
            for step in (
                lambda: self._revoke_workers(end_reason, status),
                self._stop_containers,
                self._close_redis,
            ):
                try:
                    step()
                except Exception as e:
                    logger.warning(f"Shutdown step failed: {e}")
            finished.set()

        threading.Thread(target=_run, name="fuzzingbrain-shutdown", daemon=True).start()
        if finished.wait(timeout=seconds):
            return True
        logger.error(f"Shutdown did not finish within {seconds:.0f}s; abandoning it")
        return False

    # -------------------------------------------------------------- waiting

    def wait_for_completion(
        self,
        timeout_minutes: int,
        poll_interval: int = 5,
        on_progress: Optional[Callable[[Dict[str, int]], None]] = None,
    ) -> Dict[str, Any]:
        start = datetime.now()
        limit = timedelta(minutes=timeout_minutes)
        # A bound on the polls as well as the clock: a loop that stops sleeping
        # must fail as a hung run, not as an allocation loop on a shared host.
        poll_seconds = max(int(poll_interval), 1)
        max_polls = int(limit.total_seconds() // poll_seconds) + 10
        polls = 0
        last_status = None
        last_crashes = 0
        idle_logged = False
        logger.info(
            f"Waiting for the run (timeout {timeout_minutes}min"
            + (f", poc target {self.poc_count_target}" if self.poc_count_target else "")
            + (f", budget ${self.config.budget_limit:.2f}" if self.config.budget_limit else "")
            + ")"
        )

        def done(status: str, **extra) -> Dict[str, Any]:
            self.stop_everything(END_REASONS[status])
            return {
                "status": status,
                "elapsed_minutes": (datetime.now() - start).total_seconds() / 60,
                "poc_count": self.crash_count(),
                **extra,
                **self.get_status(),
            }

        try:
            while True:
                polls += 1
                elapsed = datetime.now() - start
                try:
                    self.store.run_heartbeat(self.run_id)
                except Exception:
                    pass

                if elapsed > limit or polls > max_polls:
                    logger.warning(f"Timeout after {timeout_minutes} minutes")
                    return done("timeout")

                if self.config.budget_limit > 0:
                    cost = self.current_cost()
                    if cost >= self.config.budget_limit:
                        msg = f"Budget reached: ${cost:.2f} >= ${self.config.budget_limit:.2f}"
                        logger.warning(msg)
                        return done("budget_exceeded", error=msg)

                crashes = self.crash_count()
                if crashes != last_crashes:
                    logger.info(
                        f"Distinct bugs proved: {crashes}"
                        + (f"/{self.poc_count_target}" if self.poc_count_target else "")
                    )
                    last_crashes = crashes
                if self.poc_count_target > 0 and crashes >= self.poc_count_target:
                    logger.info(f"PoC target reached ({crashes}/{self.poc_count_target})")
                    return done("poc_target_reached")

                status = self.get_status()
                if status != last_status:
                    logger.info(
                        f"Workers: {status['completed']}/{status['total']} completed, "
                        f"{status['running']} running, {status['error'] + status['lost']} failed"
                    )
                    last_status = status
                    if on_progress:
                        on_progress(status)
                if not idle_logged and status["total"] and status["queued"] + status["running"] == 0:
                    logger.info(
                        "All workers finished; the global fuzzers keep running until "
                        "timeout / budget / PoC target"
                    )
                    idle_logged = True

                time.sleep(poll_seconds)
        except KeyboardInterrupt:
            logger.warning("Interrupted: stopping workers and fuzzers")
            self.stop_everything(None, status="cancelled")
            raise
