# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for FuzzingBrain tests."""

import pytest
import mongomock

from fuzzingbrain.db.repository import RepositoryManager


@pytest.fixture
def mock_db():
    """In-memory MongoDB via mongomock."""
    client = mongomock.MongoClient()
    db = client["fuzzingbrain_test"]
    yield db
    client.close()


@pytest.fixture
def repos(mock_db):
    """RepositoryManager backed by mongomock."""
    return RepositoryManager(mock_db)


# ---------------------------------------------------------------------------
# Two limits on the test process itself
#
# A test that loops without sleeping and calls a MagicMock on every pass grows
# `mock_calls` by about 1.2 KB a call and never frees any of it -- roughly a
# gigabyte every three seconds. One such test, left running unattended, took
# this machine's 62 GB and then the machine: MongoDB stopped answering, the
# kernel stopped being able to write its own log, and the box needed a reboot.
#
# Nothing about that test's bug was subtle, but the blast radius was: a failure
# inside one Python process should cost that process. So the process caps its
# own address space, and each test gets a wall clock. Either one alone would
# have turned an unusable machine into a red test.
# ---------------------------------------------------------------------------

import faulthandler
import os
import resource
import signal

import pytest

# Generous next to what the suite actually uses -- the point is to catch
# unbounded growth, not to tune anyone's headroom.
_MEMORY_LIMIT_GB = float(os.environ.get("FUZZINGBRAIN_TEST_MEMORY_GB", "8"))
_TEST_TIMEOUT_SECONDS = int(os.environ.get("FUZZINGBRAIN_TEST_TIMEOUT", "120"))


def pytest_configure(config):
    """Cap this process's address space before any test runs."""
    if _MEMORY_LIMIT_GB <= 0:
        return
    limit = int(_MEMORY_LIMIT_GB * 1024**3)
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    if hard != resource.RLIM_INFINITY and limit > hard:
        limit = hard
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit, hard))
    except (ValueError, OSError):
        pass  # a platform that will not take it; the timeout still applies


@pytest.fixture(autouse=True)
def _test_watchdog(request):
    """Fail a test that runs too long, with a traceback of where it is stuck.

    SIGALRM rather than a thread: the runaway case is a tight loop that never
    yields, and a signal interrupts it where a cooperative check would not.
    """
    if _TEST_TIMEOUT_SECONDS <= 0:
        yield
        return

    def _expired(signum, frame):
        faulthandler.dump_traceback()
        raise TimeoutError(
            f"{request.node.name} exceeded {_TEST_TIMEOUT_SECONDS}s -- "
            f"it is most likely looping. Set FUZZINGBRAIN_TEST_TIMEOUT to change."
        )

    previous = signal.signal(signal.SIGALRM, _expired)
    signal.alarm(_TEST_TIMEOUT_SECONDS)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
