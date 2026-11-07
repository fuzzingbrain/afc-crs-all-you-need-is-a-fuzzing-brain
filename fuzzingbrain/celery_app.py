# SPDX-License-Identifier: Apache-2.0
"""
Celery Application Configuration

Celery is used for distributed task queue.
Workers pick up tasks from Redis and execute them in parallel.
"""

import logging
import os
import sys
import traceback

from dotenv import load_dotenv

load_dotenv()  # Load .env file for API keys

logger = logging.getLogger(__name__)

from celery import Celery
from celery.signals import (
    task_failure,
    worker_process_init,
    worker_process_shutdown,
    setup_logging,
)

# Redis configuration from environment
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Create Celery app
app = Celery(
    "fuzzingbrain",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["fuzzingbrain.worker.tasks"],
)


@setup_logging.connect
def configure_celery_logging(**kwargs):
    """Keep Celery from installing its own handlers.

    The Celery main process logs to stderr, which the controller sends to
    <output>/logs/celery_worker.log; each task process re-configures itself
    for its worker (worker/tasks.py).
    """
    from .core.logging import setup_logging as fb_setup_logging

    fb_setup_logging(None, console=True)


# Signal handlers for better error logging
@task_failure.connect
def on_task_failure(
    sender=None, task_id=None, exception=None, traceback=None, **kwargs
):
    """Log task failures to stderr."""
    error_msg = f"[CELERY TASK FAILED] Task {sender.name}[{task_id}]: {exception}"
    sys.stderr.write(error_msg + "\n")
    if traceback:
        sys.stderr.write(str(traceback) + "\n")
    sys.stderr.flush()


@worker_process_init.connect
def on_worker_init(**kwargs):
    """Setup error handling and LLM buffer when worker process initializes."""

    def handle_exception(exc_type, exc_value, exc_tb):
        error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        sys.stderr.write(f"[CELERY WORKER ERROR]\n{error_msg}\n")
        sys.stderr.flush()

    sys.excepthook = handle_exception


@worker_process_shutdown.connect
def on_worker_shutdown(**kwargs):
    """Safety net: flush LLM buffer if WorkerContext.__exit__ didn't run.

    This handles the case where Celery kills the worker process (SIGTERM)
    before the context manager's __exit__ has a chance to run.
    buffer.stop() is idempotent — safe to call even if already stopped.
    """
    try:
        from .llms.buffer import get_worker_buffer

        buffer = get_worker_buffer()
        if buffer and buffer._running:
            logger.info("worker_process_shutdown: flushing LLM buffer (safety net)")
            buffer.stop()
    except Exception as e:
        sys.stderr.write(f"[CELERY SHUTDOWN] Failed to flush buffer: {e}\n")
        sys.stderr.flush()


# Celery configuration
app.conf.update(
    # Serialization
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # Timezone
    timezone="UTC",
    enable_utc=True,
    # Task settings
    task_track_started=True,
    task_time_limit=86400,  # 24 hour default hard limit (overridden per-task by dispatcher)
    task_soft_time_limit=86100,  # 23h55m default soft limit (overridden per-task by dispatcher)
    # Worker settings
    worker_prefetch_multiplier=1,  # Fetch one task at a time
    # A fallback only: InfrastructureManager starts the worker with
    # --concurrency from the task's configuration, which wins over this.
    worker_concurrency=8,
    # Result settings
    result_expires=86400,  # 24 hours
    # Task routing (optional, for future use)
    task_routes={
        "fuzzingbrain.worker.tasks.run_worker": {"queue": "workers"},
    },
)

# Optional: Configure task logging
app.conf.worker_hijack_root_logger = False
