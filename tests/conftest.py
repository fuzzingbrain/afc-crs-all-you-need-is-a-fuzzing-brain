# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for FuzzingBrain tests."""

import shutil
import subprocess
import time
import uuid as _uuid

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


# ---------------------------------------------------------------------------
# PostgreSQL
#
# Schema tests need a real server: CHECK constraints, foreign keys and
# ON CONFLICT are what they test. FUZZINGBRAIN_TEST_PG_URL names a server to
# use; otherwise one is started in a capped, labelled container for the
# session. Either way the tests work in a database of their own, created and
# dropped here, never in one that already exists.
# ---------------------------------------------------------------------------

PG_IMAGE = "postgres:18"
PG_TEST_LABEL = "fuzzingbrain.test=pg"


def _start_pg_container() -> tuple:
    from fuzzingbrain.core.docker_limits import docker_resource_args

    name = f"fb-test-pg-{_uuid.uuid4().hex[:8]}"
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name, "--label", PG_TEST_LABEL,
         *docker_resource_args(1024, 1.0),
         "-e", "POSTGRES_USER=fb", "-e", "POSTGRES_PASSWORD=fbtest",
         "-p", "127.0.0.1::5432", PG_IMAGE],
        check=True, capture_output=True, timeout=120,
    )
    port = subprocess.run(
        ["docker", "port", name, "5432/tcp"],
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout.strip().rsplit(":", 1)[1]
    return name, f"postgresql://fb:fbtest@127.0.0.1:{port}/postgres"


def _wait_for_pg(url: str, seconds: float = 60) -> None:
    import psycopg

    deadline = time.monotonic() + seconds
    while True:
        try:
            psycopg.connect(url, connect_timeout=2).close()
            return
        except psycopg.OperationalError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)


@pytest.fixture(scope="session")
def pg_server():
    """A libpq URL for a PostgreSQL server's maintenance database."""
    url = os.environ.get("FUZZINGBRAIN_TEST_PG_URL")
    container = None
    if not url:
        if not shutil.which("docker"):
            pytest.skip("no FUZZINGBRAIN_TEST_PG_URL and no docker to start PostgreSQL")
        container, url = _start_pg_container()
    try:
        _wait_for_pg(url)
        yield url
    finally:
        if container:
            subprocess.run(["docker", "rm", "-f", container],
                           capture_output=True, timeout=60)


@pytest.fixture
def fresh_pg(pg_server):
    """An empty database for one test; a SQLAlchemy URL to it."""
    import psycopg

    name = f"fb_test_{_uuid.uuid4().hex[:12]}"
    with psycopg.connect(pg_server, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    base = pg_server.rsplit("/", 1)[0]
    try:
        yield f"{base.replace('postgresql://', 'postgresql+psycopg://', 1)}/{name}"
    finally:
        with psycopg.connect(pg_server, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
