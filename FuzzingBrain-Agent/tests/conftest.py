import json
import re
import subprocess
import threading
from pathlib import Path

import pytest

from minisweagent.models import GLOBAL_MODEL_STATS


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--run-fire",
        action="store_true",
        default=False,
        help="Run fire tests (real API calls that cost money)",
    )


# Global lock for tests that modify global state - this works across threads
_global_stats_lock = threading.Lock()


@pytest.fixture
def reset_global_stats():
    """Reset global model stats and ensure exclusive access for tests that need it.

    This fixture should be used by any test that depends on global model stats
    to ensure thread safety and test isolation.
    """
    with _global_stats_lock:
        # Reset at start
        GLOBAL_MODEL_STATS._cost = 0.0  # noqa: protected-access
        GLOBAL_MODEL_STATS._n_calls = 0  # noqa: protected-access
        yield
        # Reset at end to clean up
        GLOBAL_MODEL_STATS._cost = 0.0  # noqa: protected-access
        GLOBAL_MODEL_STATS._n_calls = 0  # noqa: protected-access


def _get_container_executable() -> str | None:
    """Return 'docker' or 'podman', whichever is available and running."""
    for exe in ("docker", "podman"):
        try:
            subprocess.run([exe, "version"], capture_output=True, check=True, timeout=5)
            return exe
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


@pytest.fixture
def container_executable(monkeypatch):
    """Provide the available container executable, skip if neither docker nor podman is available.

    Sets MSWEA_DOCKER_EXECUTABLE so DockerEnvironment uses the right executable.
    """
    exe = _get_container_executable()
    if exe is None:
        pytest.skip("Neither docker nor podman is available")
    monkeypatch.setenv("MSWEA_DOCKER_EXECUTABLE", exe)
    return exe


def get_test_data(trajectory_name: str) -> dict[str, list[str]]:
    """Load test fixtures from a trajectory JSON file"""
    json_path = Path(__file__).parent / "test_data" / f"{trajectory_name}.traj.json"
    with json_path.open() as f:
        trajectory = json.load(f)

    # Extract model responses (assistant messages, starting from index 2)
    model_responses = []
    # Extract expected observations (user messages, starting from index 3)
    expected_observations = []

    for i, message in enumerate(trajectory):
        if i < 2:  # Skip system message (0) and initial user message (1)
            continue

        if message["role"] == "assistant":
            model_responses.append(message["content"])
        elif message["role"] == "user":
            expected_observations.append(message["content"])

    return {"model_responses": model_responses, "expected_observations": expected_observations}


def normalize_outputs(s: str) -> str:
    """Strip leading/trailing whitespace and normalize internal whitespace"""
    # Remove everything between <args> and </args>, because this contains docker container ids
    s = re.sub(r"<args>(.*?)</args>", "", s, flags=re.DOTALL)
    # Replace all lines that have root in them because they tend to appear with times
    s = "\n".join(l for l in s.split("\n") if "root root" not in l)
    return "\n".join(line.rstrip() for line in s.strip().split("\n"))


def assert_observations_match(expected_observations: list[str], messages: list[dict]) -> None:
    """Compare expected observations with actual observations from agent messages

    Args:
        expected_observations: List of expected observation strings
        messages: Agent conversation messages (list of message dicts with 'role' and 'content')
    """
    # Extract actual observations from agent messages
    # User/exit messages (observations) are at indices 3, 5, 7, etc.
    actual_observations = []
    for i in range(len(expected_observations)):
        user_message_index = 3 + (i * 2)
        assert messages[user_message_index]["role"] in ("user", "exit")
        actual_observations.append(messages[user_message_index]["content"])

    assert len(actual_observations) == len(expected_observations), (
        f"Expected {len(expected_observations)} observations, got {len(actual_observations)}"
    )

    for i, (expected_observation, actual_observation) in enumerate(zip(expected_observations, actual_observations)):
        normalized_actual = normalize_outputs(actual_observation)
        normalized_expected = normalize_outputs(expected_observation)

        assert normalized_actual == normalized_expected, (
            f"Step {i + 1} observation mismatch:\nExpected: {repr(normalized_expected)}\nActual: {repr(normalized_actual)}"
        )


@pytest.fixture
def github_test_data():
    """Load GitHub issue test fixtures"""
    return get_test_data("github_issue")


@pytest.fixture
def local_test_data():
    """Load local test fixtures"""
    return get_test_data("local")


def pytest_sessionfinish(session, exitstatus):
    """Remove containers the environment tests left behind.

    The tests do call cleanup(), and cleanup() works -- but it backgrounds its
    `docker stop`, and the container it started sleeps for container_timeout (2h
    by default). So a suite that is KILLED rather than finished -- a timeout, a
    Ctrl-C, a harness that backgrounds it and moves on -- leaves them running
    for two hours. That is how 43 accumulated here, on a machine with no swap
    that has been livelocked once, holding ~3 GB of disk and ~2.4 GB of RAM.

    This is a backstop for the interrupted case, not a fix for cleanup(). It
    matches only the exact name DockerEnvironment generates,
    `minisweagent-<8 hex>`, so nothing else on the machine can be caught by it.
    """
    import re
    import subprocess

    pattern = re.compile(r"^minisweagent-[0-9a-f]{8}$")
    for exe in ("docker", "podman"):
        try:
            out = subprocess.run([exe, "ps", "-q", "--format", "{{.Names}}"],
                                 capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode != 0:
            continue
        stale = [n for n in out.stdout.split() if pattern.match(n)]
        if stale:
            subprocess.run([exe, "rm", "-f", *stale],
                           capture_output=True, timeout=120)
        break
