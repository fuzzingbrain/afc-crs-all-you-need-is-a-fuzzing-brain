# SPDX-License-Identifier: Apache-2.0
"""Process-scoped docker container cleanup.

Registers an ``atexit`` hook plus ``SIGINT``/``SIGTERM`` handlers that stop
any still-running docker containers when the current process terminates.
This is an **opt-in** module: importing it does nothing until
``install_cleanup_handlers`` is called. The legacy behaviour of installing
handlers as a side effect of ``import`` was unsafe for library consumers
(a plain ``import`` could kill unrelated containers on the host).

Typical call site: the strategy CLI entry point, immediately after
argument parsing.
"""
from __future__ import annotations

import atexit
import logging
import os
import signal
import subprocess
import sys
from typing import List

logger = logging.getLogger(__name__)

_installed = False
_cleanup_in_progress = False


def _list_running_container_ids() -> List[str]:
    """Return ``docker ps -q`` output as a list of ids, or empty on failure."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        logger.debug("docker ps failed during cleanup: %s", exc)
        return []

    return [line for line in result.stdout.strip().split("\n") if line]


def _stop_containers() -> None:
    """Stop every running docker container on the host (best-effort).

    Skipped when running inside a container (``/.dockerenv`` present) so we
    never suicide the parent container we were invoked from.
    """
    global _cleanup_in_progress
    if _cleanup_in_progress:
        return
    _cleanup_in_progress = True

    if os.path.exists("/.dockerenv"):
        logger.debug("Inside a container; skipping docker cleanup")
        return

    container_ids = _list_running_container_ids()
    if not container_ids:
        return

    logger.warning("Stopping %d docker container(s) on exit", len(container_ids))
    try:
        subprocess.run(
            ["docker", "stop", *container_ids],
            timeout=10,
            capture_output=True,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        logger.warning("Failed to stop containers during cleanup: %s", exc)


def _signal_handler(signum, _frame) -> None:
    """Stop containers on interrupt and exit with the conventional 128+signum code."""
    logger.warning("Received signal %s; running docker cleanup", signum)
    _stop_containers()
    # 130 == 128 + SIGINT (2); match historical behaviour for any signal
    sys.exit(130)


def install_cleanup_handlers() -> None:
    """Install the atexit + signal hooks. Idempotent.

    Library / utility modules MUST NOT call this. Only the top-level
    strategy entry point should, and only when it is acceptable to stop
    unrelated containers on the host at exit time.
    """
    global _installed
    if _installed:
        return
    _installed = True

    atexit.register(_stop_containers)
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    logger.debug("Docker cleanup handlers installed")
