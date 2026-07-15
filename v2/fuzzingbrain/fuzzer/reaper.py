# SPDX-License-Identifier: Apache-2.0
"""Docker labelling and reaping for fuzzer containers.

Fuzzer containers are launched as ``docker run`` from inside the Celery worker
subprocess, but shutdown is driven from the main dispatcher process. The
in-process FuzzerManager registry cannot cross that process boundary, so a
container the subprocess started is invisible to the dispatcher's shutdown.

Instead, every fuzzer container is labelled with its task id and reaped through
the Docker daemon, which all processes share. Reaping by label works regardless
of which process launched the container, and is idempotent.
"""

import subprocess
from typing import List

from loguru import logger

# Label namespace applied to every fuzzer container.
NAMESPACE_LABEL = "fuzzingbrain"
TASK_LABEL = "fuzzingbrain.task"
WORKER_LABEL = "fuzzingbrain.worker"


def container_labels(task_id: str, worker_id: str = "") -> List[str]:
    """Build the ``docker run`` --label args that identify a fuzzer container."""
    labels = ["--label", f"{NAMESPACE_LABEL}=1"]
    if task_id:
        labels += ["--label", f"{TASK_LABEL}={task_id}"]
    if worker_id:
        labels += ["--label", f"{WORKER_LABEL}={worker_id}"]
    return labels


def reap_task_containers(task_id: str, timeout: float = 30.0) -> int:
    """Force-remove every fuzzer container belonging to a task.

    Queries the Docker daemon by label, so it reaps containers no matter which
    process started them. Safe to call repeatedly — an already-clean task is a
    no-op.

    Returns:
        Number of containers removed.
    """
    if not task_id:
        return 0

    try:
        listed = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label={TASK_LABEL}={task_id}"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning(f"[reaper] Could not list containers for task {task_id}: {e}")
        return 0

    container_ids = [c for c in listed.stdout.split() if c]
    if not container_ids:
        return 0

    try:
        subprocess.run(
            ["docker", "rm", "-f", *container_ids],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning(f"[reaper] Failed to remove containers {container_ids}: {e}")
        return 0

    logger.info(
        f"[reaper] Removed {len(container_ids)} leaked fuzzer "
        f"container(s) for task {task_id}"
    )
    return len(container_ids)
