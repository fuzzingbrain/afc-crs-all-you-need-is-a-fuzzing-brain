"""Docker plumbing shared by every container FBv3 starts.

Every container gets cgroup caps (memory == memory-swap, so an over-budget
container is OOM-killed instead of pushing this swapless host into reclaim)
and two labels: ``fbv3.run=<run id>`` (so a run can kill exactly its own
containers, even after a hard crash) and ``fbv3.kind`` (workspace / fuzzer /
build / repro). Nothing here ever touches a container it did not label.
"""

from __future__ import annotations

import logging
import os
import subprocess

logger = logging.getLogger(__name__)

RUN_LABEL = "fbv3.run"
KIND_LABEL = "fbv3.kind"


def uid_gid() -> str:
    return f"{os.getuid()}:{os.getgid()}"


def resource_args(memory_mb: int, cpus: float, pids: int = 1024) -> list[str]:
    memory_mb = int(os.environ.get("FBV3_DOCKER_MEMORY_MB", memory_mb))
    cpus = float(os.environ.get("FBV3_DOCKER_CPUS", cpus))
    return [f"--memory={memory_mb}m", f"--memory-swap={memory_mb}m", f"--cpus={cpus:g}",
            f"--pids-limit={pids}"]


def label_args(run_id: str, kind: str) -> list[str]:
    args = ["--label", f"{KIND_LABEL}={kind}"]
    if run_id:
        args += ["--label", f"{RUN_LABEL}={run_id}"]
    return args


def run(argv: list[str], *, timeout: float, input: bytes | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, input=input, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(argv, 124, exc.stdout or b"", (exc.stderr or b"") + b"\n[timeout]")


def image_exists(tag: str) -> bool:
    return run(["docker", "image", "inspect", tag], timeout=60).returncode == 0


def kill_run_containers(run_id: str) -> int:
    """Remove every container labelled with this run; returns how many."""
    if not run_id:
        return 0
    listed = run(["docker", "ps", "-aq", "--filter", f"label={RUN_LABEL}={run_id}"], timeout=60)
    ids = listed.stdout.decode().split()
    if ids:
        run(["docker", "rm", "-f", *ids], timeout=120)
        logger.info("removed %d container(s) of run %s", len(ids), run_id)
    return len(ids)


def chown_tree(path: str, image: str) -> None:
    """Give a tree a root container wrote back to the host user."""
    run(["docker", "run", "--rm", "--entrypoint", "", "-v", f"{path}:/t", image,
         "chown", "-R", uid_gid(), "/t"], timeout=600)
