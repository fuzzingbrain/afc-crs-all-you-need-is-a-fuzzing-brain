"""
Celery Application Configuration

Celery is used for distributed task queue.
Workers pick up tasks from Redis and execute them in parallel.
"""

import os
from celery import Celery

# Redis configuration from environment
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Create Celery app
app = Celery(
    "fuzzingbrain",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["fuzzingbrain.worker.tasks"],
)

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
