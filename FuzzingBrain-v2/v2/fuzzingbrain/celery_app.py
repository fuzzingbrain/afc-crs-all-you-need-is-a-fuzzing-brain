"""
Celery Application Configuration

Celery is used for distributed task queue.
Workers pick up tasks from Redis and execute them in parallel.
"""

import logging
import os
import sys
import traceback
from celery import Celery
from celery.signals import task_failure, worker_process_init, setup_logging

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
    """
    Disable Celery's default logging to console.

    This prevents Celery from interfering with our console output.
    All Celery logs go to file only.
    """
    # Get Celery's logger and remove all handlers
    celery_logger = logging.getLogger("celery")
    celery_logger.handlers = []
    celery_logger.propagate = False

    # Also suppress celery.worker and celery.task loggers
    for name in ["celery.worker", "celery.task", "celery.app.trace"]:
        log = logging.getLogger(name)
        log.handlers = []
        log.propagate = False


# Signal handlers for better error logging
@task_failure.connect
def on_task_failure(sender=None, task_id=None, exception=None, traceback=None, **kwargs):
    """Log task failures to stderr."""
    error_msg = f"[CELERY TASK FAILED] Task {sender.name}[{task_id}]: {exception}"
    sys.stderr.write(error_msg + "\n")
    if traceback:
        sys.stderr.write(str(traceback) + "\n")
    sys.stderr.flush()


@worker_process_init.connect
def on_worker_init(**kwargs):
    """Setup error handling when worker process initializes."""
    def handle_exception(exc_type, exc_value, exc_tb):
        error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
        sys.stderr.write(f"[CELERY WORKER ERROR]\n{error_msg}\n")
        sys.stderr.flush()

    sys.excepthook = handle_exception

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
    task_time_limit=3600,  # 1 hour hard limit
    task_soft_time_limit=3300,  # 55 min soft limit

    # Worker settings
    worker_prefetch_multiplier=1,  # Fetch one task at a time
    worker_concurrency=8,  # Default concurrency

    # Result settings
    result_expires=86400,  # 24 hours

    # Task routing (optional, for future use)
    task_routes={
        "fuzzingbrain.worker.tasks.run_worker": {"queue": "workers"},
    },
)

# Optional: Configure task logging
app.conf.worker_hijack_root_logger = False
