# SPDX-License-Identifier: Apache-2.0
"""
The worker row's lifecycle, and the process's LLM buffer.

The dispatcher inserts the workers row (status queued) before it sends the
Celery task; the task carries its id. Here the row goes

    queued -> running            on enter (worker_started)
    running -> completed         on a normal exit (end_reason work_done)
    running -> error             on an exception (with the traceback)

and a heartbeat keeps heartbeat_at fresh while it runs, so the dispatcher
can tell a lost worker from a slow one. A worker the run ended first
(end_open_workers: poc_target / timeout / budget) is already closed; the
conditional update in end_worker leaves it as the run set it.
"""

import os
import threading
import traceback
from datetime import datetime
from typing import Any, Dict, Optional

from loguru import logger

from ..db.store import get_store


class WorkerContext:
    HEARTBEAT_EVERY = 30.0  # seconds

    def __init__(self, run_id: str, worker_id: str, fuzzer: str = "", sanitizer: str = ""):
        self.run_id = str(run_id)
        self.worker_id = str(worker_id)
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.started_at: Optional[datetime] = None
        self.ended_at: Optional[datetime] = None
        self.result_summary: Dict[str, Any] = {}
        self.poc_generated = 0
        self.patch_generated = 0
        self._stop = threading.Event()
        self._heartbeat: Optional[threading.Thread] = None
        self._llm_buffer = None

    # ------------------------------------------------------------ lifecycle

    def __enter__(self) -> "WorkerContext":
        self.started_at = datetime.now()
        store = get_store()
        if not store.worker_started(self.worker_id):
            # Not queued: the run already ended it (or a redelivered task).
            logger.warning(
                f"worker {self.worker_id[:8]}: row was not queued; running anyway"
            )

        from ..llms.buffer import ensure_buffer

        try:
            self._llm_buffer = ensure_buffer(
                store, os.getenv("REDIS_URL", "redis://localhost:6379/0")
            )
        except Exception as e:
            # Without it no LLM call is written; say so loudly.
            logger.error(f"worker {self.worker_id[:8]}: LLM buffer failed to start: {e}")

        self._heartbeat = threading.Thread(
            target=self._beat, name="worker-heartbeat", daemon=True
        )
        self._heartbeat.start()
        logger.info(f"worker {self.worker_id[:8]} ({self.fuzzer}) running")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.ended_at = datetime.now()
        self._stop.set()
        if self._heartbeat:
            self._heartbeat.join(timeout=5)

        # Flush the LLM calls before the row closes: a reader that sees the
        # worker finished expects its calls to be there.
        try:
            if self._llm_buffer is not None:
                self._llm_buffer.flush()
        except Exception as e:
            logger.warning(f"worker {self.worker_id[:8]}: LLM flush failed: {e}")

        try:
            if exc_type is None:
                get_store().end_worker(self.worker_id, "completed", end_reason="work_done")
            else:
                err = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
                get_store().end_worker(self.worker_id, "error", error=err)
        except Exception as e:
            logger.error(f"worker {self.worker_id[:8]}: could not close its row: {e}")

    def _beat(self) -> None:
        while not self._stop.wait(self.HEARTBEAT_EVERY):
            try:
                get_store().worker_heartbeat(self.worker_id)
            except Exception as e:
                logger.debug(f"worker heartbeat failed: {e}")

    @property
    def duration_seconds(self) -> float:
        if not self.started_at:
            return 0.0
        return ((self.ended_at or datetime.now()) - self.started_at).total_seconds()

    def __repr__(self) -> str:
        return f"WorkerContext(id={self.worker_id[:8]}, fuzzer={self.fuzzer})"
