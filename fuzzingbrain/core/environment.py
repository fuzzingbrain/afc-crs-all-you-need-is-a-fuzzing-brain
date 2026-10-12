# SPDX-License-Identifier: Apache-2.0
"""Start-up checks: Docker, MongoDB, Redis and the API keys a task needs.

Each check returns an error message, or None when it passed, so main() can
report every problem in one go and stop before any work starts.
"""

import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import urlparse


def in_docker() -> bool:
    """Running inside a container (docker-compose manages MongoDB and Redis then)."""
    if Path("/.dockerenv").exists() or os.environ.get("RUNNING_IN_DOCKER"):
        return True
    try:
        return "docker" in Path("/proc/1/cgroup").read_text()
    except OSError:
        return False


def check_docker() -> Optional[str]:
    """Every build, fuzzer and PoV runs in a container."""
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=30)
    except FileNotFoundError:
        return "docker not found; FuzzingBrain runs every fuzzer in a container"
    except subprocess.TimeoutExpired:
        return "'docker info' timed out"
    if r.returncode != 0:
        return "'docker info' failed: daemon not running, or this user is not in the docker group"
    return None


def _reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _container_state(name: str) -> Optional[str]:
    """'running', 'exited', ... or None when no such container exists."""
    r = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Status}}", name],
        capture_output=True, text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else None


def ensure_service(
    name: str, url: str, container: str, image: str, inner_port: int, volume: str
) -> Optional[str]:
    """Make sure a service answers at `url`, starting its container if it is ours to start."""
    parsed = urlparse(url)
    host, port = parsed.hostname or "localhost", parsed.port or inner_port
    if _reachable(host, port):
        return None
    if in_docker() or host not in ("localhost", "127.0.0.1"):
        return f"{name} is not reachable at {host}:{port}"

    state = _container_state(container)
    if state == "running":
        pass  # up but not answering yet; wait below
    elif state is not None:
        subprocess.run(["docker", "start", container], capture_output=True)
    else:
        r = subprocess.run(
            [
                "docker", "run", "-d", "--name", container, "--restart=always",
                "-p", f"127.0.0.1:{port}:{inner_port}",
                "-v", f"{volume}:/data" + ("/db" if name == "MongoDB" else ""),
                image,
            ],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return f"could not start {name} container: {r.stderr.strip()}"

    for _ in range(20):
        if _reachable(host, port):
            return None
        time.sleep(1)
    return f"{name} container {container} did not come up on {host}:{port}"


def ensure_mongodb(url: str) -> Optional[str]:
    return ensure_service(
        "MongoDB", url, "fuzzingbrain-mongodb", "mongo:8.2", 27017,
        "fuzzingbrain-mongodb-data",
    )


def ensure_redis(url: str) -> Optional[str]:
    return ensure_service(
        "Redis", url, "fuzzingbrain-redis", "redis:7-alpine", 6379,
        "fuzzingbrain-redis-data",
    )


def check_api_keys(model_ids: Iterable[str]) -> List[str]:
    """Each model the task names must be known and have its provider's key set."""
    from ..llms.config import LLMConfig
    from ..llms.models import get_model_by_id

    errors = []
    llm_config = LLMConfig()
    for model_id in model_ids:
        info = get_model_by_id(model_id)
        if info is None:
            errors.append(f"unknown model id {model_id!r}")
        elif not llm_config.get_api_key(info.provider):
            errors.append(
                f"{model_id}: no API key for {info.provider.value} in .env"
            )
    return errors
