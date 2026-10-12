# SPDX-License-Identifier: Apache-2.0
"""Start-up checks: Docker, PostgreSQL, Redis and the API keys a task needs.

Each check returns an error message, or None when it passed, so main() can
report every problem in one go and stop before any work starts.
"""

import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional
from urllib.parse import urlparse


def in_docker() -> bool:
    """Running inside a container (docker-compose manages the database and Redis then)."""
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
    name: str,
    url: str,
    container: str,
    image: str,
    inner_port: int,
    volume: str,
    data_dir: str = "/data",
    env: Optional[Dict[str, str]] = None,
    ready: Optional[Callable[[], bool]] = None,
) -> Optional[str]:
    """Make sure a service answers at `url`, starting its container if it is ours to start.

    `ready` says whether the service actually answers; without it an open port
    is taken as enough.
    """
    parsed = urlparse(url)
    host, port = parsed.hostname or "localhost", parsed.port or inner_port
    if ready is None:
        ready = lambda: _reachable(host, port)  # noqa: E731
    if ready():
        return None
    if in_docker() or host not in ("localhost", "127.0.0.1"):
        return f"{name} is not reachable at {host}:{port}"

    state = _container_state(container)
    if state == "running":
        pass  # up but not answering yet; wait below
    elif state is not None:
        subprocess.run(["docker", "start", container], capture_output=True)
    else:
        env_args = [arg for k, v in (env or {}).items() for arg in ("-e", f"{k}={v}")]
        r = subprocess.run(
            [
                "docker", "run", "-d", "--name", container, "--restart=always",
                "-p", f"127.0.0.1:{port}:{inner_port}",
                "-v", f"{volume}:{data_dir}",
                *env_args,
                image,
            ],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return f"could not start {name} container: {r.stderr.strip()}"

    # A first start initialises the data directory, which takes a while.
    for _ in range(60):
        if ready():
            return None
        time.sleep(1)
    return f"{name} container {container} did not come up on {host}:{port}"


def _postgres_answers(url: str) -> bool:
    """A query goes through (an open port alone may be Docker's proxy)."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.pool import NullPool

    engine = create_engine(url, poolclass=NullPool, connect_args={"connect_timeout": 2})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
    finally:
        engine.dispose()


def ensure_postgres(url: str) -> Optional[str]:
    """The run database. A container we start takes its user, password and
    database name from the URL, so the URL in .env is all there is to set."""
    parsed = urlparse(url)
    return ensure_service(
        "PostgreSQL", url, "fuzzingbrain-postgres", "postgres:18", 5432,
        "fuzzingbrain-postgres-data",
        data_dir="/var/lib/postgresql",
        env={
            "POSTGRES_USER": parsed.username or "fuzzingbrain",
            "POSTGRES_PASSWORD": parsed.password or "fuzzingbrain",
            "POSTGRES_DB": parsed.path.lstrip("/") or "fuzzingbrain",
        },
        ready=lambda: _postgres_answers(url),
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
