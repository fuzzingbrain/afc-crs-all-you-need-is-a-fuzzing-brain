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
from typing import List


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
