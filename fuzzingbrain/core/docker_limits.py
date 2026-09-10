"""Docker-level resource caps for containers this package spawns.

libFuzzer's -rss_limit_mb only bounds the fuzzer's own allocator, and only
while the process is healthy: ASAN overhead, forked children, and hung
containers all escape it. Without cgroup caps a single task can spawn enough
containers to exhaust host memory and livelock the machine (no swap means
the kernel thrashes instead of OOM-killing). Every heavyweight `docker run`
call site takes its limits from here so a runaway container is killed by
its cgroup instead of taking the host down.
"""

import os
import subprocess
from typing import List

from loguru import logger

# Every long-running container a task spawns carries this label, so the
# controller can find them again without a handle to the process that
# started them. The fuzzers are launched inside the Celery worker process;
# when the task ends the controller revokes that worker with SIGTERM, which
# kills the Python side but not the `docker run` clients it forked, and
# certainly not the containers behind them. Six curl fuzzers were found
# still running hours after their tasks had reported "POV target reached".
TASK_LABEL = "fuzzingbrain.task"


def docker_resource_args(memory_mb: int, cpus: float) -> List[str]:
    """Docker-run flags capping memory and CPU for one container.

    memory-swap is set equal to memory so the container gets no swap: a
    container over its budget is OOM-killed immediately (exit 137) rather
    than dragging the host into reclaim.

    Env overrides FUZZINGBRAIN_DOCKER_MEMORY_MB / FUZZINGBRAIN_DOCKER_CPUS
    apply to every call site at once, for hosts of a different size.
    """
    memory_mb = int(os.environ.get("FUZZINGBRAIN_DOCKER_MEMORY_MB", memory_mb))
    cpus = float(os.environ.get("FUZZINGBRAIN_DOCKER_CPUS", cpus))
    return [
        f"--memory={memory_mb}m",
        f"--memory-swap={memory_mb}m",
        f"--cpus={cpus:g}",
        "--pids-limit=512",
    ]


def task_label_args(task_id: str) -> List[str]:
    """Docker-run flags tagging a container with the task that owns it."""
    return ["--label", f"{TASK_LABEL}={task_id}"] if task_id else []


def kill_task_containers(task_id: str, timeout: float = 30.0) -> int:
    """Kill every container labelled with this task. Returns how many.

    Bounded by ``timeout`` per docker call, because this runs on the
    shutdown path where a wedged daemon must not hold the process open.
    """
    if not task_id:
        return 0
    try:
        listed = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"label={TASK_LABEL}={task_id}"],
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning(f"Could not list containers for task {task_id}: {e}")
        return 0
    ids = listed.stdout.split()
    if not ids:
        return 0
    try:
        subprocess.run(
            ["docker", "kill", *ids],
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning(f"Could not kill {len(ids)} container(s) of task {task_id}: {e}")
        return 0
    logger.info(f"Killed {len(ids)} leftover container(s) of task {task_id}")
    return len(ids)
