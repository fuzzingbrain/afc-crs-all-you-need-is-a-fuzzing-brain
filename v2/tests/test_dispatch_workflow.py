"""
Dispatch Workflow Tests

Tests the Task → Worker dispatch flow.

Business invariants under test:
1. N successful fuzzers × M sanitizers = exactly N×M workers dispatched
2. Only fuzzers with status=SUCCESS are dispatched (FAILED/PENDING/BUILDING are skipped)
3. fuzzer_filter restricts dispatch to named fuzzers only
4. Each worker's assignment carries correct task_id, fuzzer, sanitizer, scan_mode
5. Each worker gets an isolated (distinct) workspace
6. One dispatch failure does not block the rest
"""

import pytest
from pathlib import Path
from typing import List
from unittest.mock import patch, MagicMock

from bson import ObjectId

from fuzzingbrain.core.models.task import Task, JobType, ScanMode, TaskStatus
from fuzzingbrain.core.models.fuzzer import Fuzzer, FuzzerStatus
from fuzzingbrain.core.config import Config
from fuzzingbrain.core.dispatcher import WorkerDispatcher


# =========================================================================
# Helpers
# =========================================================================


def _make_fuzzer(name: str, status: FuzzerStatus = FuzzerStatus.SUCCESS) -> Fuzzer:
    """Create a Fuzzer with given name and status."""
    return Fuzzer(
        fuzzer_id=str(ObjectId()),
        task_id=str(ObjectId()),
        fuzzer_name=name,
        status=status,
    )


def _make_task(task_id: str = None, tmp_path: Path = None) -> Task:
    """Create a Task for testing."""
    tid = task_id or str(ObjectId())
    task_path = str(tmp_path) if tmp_path else "/tmp/test_task"
    return Task(
        task_id=tid,
        task_type=JobType.POV,
        scan_mode=ScanMode.FULL,
        status=TaskStatus.RUNNING,
        task_path=task_path,
        project_name="libpng",
    )


def _make_config(
    sanitizers: List[str] = None,
    fuzzer_filter: List[str] = None,
    timeout_minutes: int = 30,
) -> Config:
    """Create a Config for testing."""
    return Config(
        sanitizers=sanitizers or ["address"],
        fuzzer_filter=fuzzer_filter or [],
        ossfuzz_project_name="libpng",
        timeout_minutes=timeout_minutes,
        budget_limit=50.0,
        pov_count=1,
    )


def _make_dispatcher(
    task: Task,
    config: Config,
    repos: MagicMock = None,
) -> WorkerDispatcher:
    """Create a WorkerDispatcher with mocked dependencies."""
    repos = repos or MagicMock()
    dispatcher = WorkerDispatcher(
        task=task,
        config=config,
        repos=repos,
        analyze_result=None,
    )
    # Disable crash monitor (needs real infrastructure)
    dispatcher.crash_monitor = None
    return dispatcher


# =========================================================================
# Tests: Pair Generation (cartesian product invariant)
# =========================================================================


class TestPairGeneration:
    """
    Business rule: each fuzzer must be tested with each sanitizer.
    The dispatch count is always |fuzzers| × |sanitizers|.
    """

    def test_single_fuzzer_single_sanitizer(self, tmp_path):
        """1 × 1 = 1"""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path), _make_config(sanitizers=["address"])
        )
        pairs = dispatcher._generate_pairs([_make_fuzzer("fuzz_png")], ["address"])

        assert len(pairs) == 1
        assert pairs[0] == {"fuzzer": "fuzz_png", "sanitizer": "address"}

    def test_cartesian_product(self, tmp_path):
        """2 fuzzers × 3 sanitizers = 6 unique pairs, no duplicates."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path), _make_config()
        )
        fuzzers = [_make_fuzzer("fuzz_a"), _make_fuzzer("fuzz_b")]
        sanitizers = ["address", "memory", "undefined"]
        pairs = dispatcher._generate_pairs(fuzzers, sanitizers)

        assert len(pairs) == 6

        # Every combination must exist exactly once
        pair_tuples = [(p["fuzzer"], p["sanitizer"]) for p in pairs]
        assert len(set(pair_tuples)) == 6, "Duplicate pairs generated"
        for f in ["fuzz_a", "fuzz_b"]:
            for s in sanitizers:
                assert (f, s) in pair_tuples, f"Missing pair ({f}, {s})"

    def test_zero_fuzzers_zero_workers(self, tmp_path):
        """No fuzzers = no pairs (not an error)."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path), _make_config()
        )
        assert dispatcher._generate_pairs([], ["address"]) == []


# =========================================================================
# Tests: Status Filtering (only SUCCESS fuzzers get dispatched)
# =========================================================================


class TestStatusFiltering:
    """
    Business rule: only fuzzers that built successfully can be dispatched.
    FAILED, PENDING, BUILDING fuzzers must never produce workers.
    """

    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._dispatch_celery_task")
    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._create_worker_workspace")
    def test_only_success_status_dispatched(
        self, mock_workspace, mock_celery, tmp_path
    ):
        """4 fuzzers with different statuses → only the SUCCESS one is dispatched."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path), _make_config()
        )
        mock_workspace.return_value = str(tmp_path / "ws")
        mock_celery.return_value = {"celery_id": "c1", "fuzzer": "", "sanitizer": ""}

        fuzzers = [
            _make_fuzzer("good", FuzzerStatus.SUCCESS),
            _make_fuzzer("bad", FuzzerStatus.FAILED),
            _make_fuzzer("waiting", FuzzerStatus.PENDING),
            _make_fuzzer("building", FuzzerStatus.BUILDING),
        ]
        jobs = dispatcher.dispatch(fuzzers)

        assert len(jobs) == 1
        dispatched_fuzzer = mock_celery.call_args[0][0]["fuzzer"]
        assert dispatched_fuzzer == "good"

    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._dispatch_celery_task")
    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._create_worker_workspace")
    def test_all_failed_produces_zero_workers(
        self, mock_workspace, mock_celery, tmp_path
    ):
        """If every fuzzer failed to build, zero workers are dispatched."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path), _make_config()
        )
        fuzzers = [
            _make_fuzzer("a", FuzzerStatus.FAILED),
            _make_fuzzer("b", FuzzerStatus.FAILED),
        ]
        jobs = dispatcher.dispatch(fuzzers)

        assert jobs == []
        mock_celery.assert_not_called()

    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._dispatch_celery_task")
    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._create_worker_workspace")
    def test_empty_fuzzer_list_produces_zero_workers(
        self, mock_workspace, mock_celery, tmp_path
    ):
        """Empty input → zero workers, no crash."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path), _make_config()
        )
        assert dispatcher.dispatch([]) == []
        mock_celery.assert_not_called()

    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._dispatch_celery_task")
    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._create_worker_workspace")
    def test_multiple_success_all_dispatched(
        self, mock_workspace, mock_celery, tmp_path
    ):
        """3 successful fuzzers × 1 sanitizer = exactly 3 workers."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path), _make_config(sanitizers=["address"])
        )
        mock_workspace.return_value = str(tmp_path / "ws")
        mock_celery.return_value = {"celery_id": "c", "fuzzer": "", "sanitizer": ""}

        fuzzers = [_make_fuzzer(f"fuzz_{i}") for i in range(3)]
        jobs = dispatcher.dispatch(fuzzers)

        assert len(jobs) == 3
        dispatched = {call[0][0]["fuzzer"] for call in mock_celery.call_args_list}
        assert dispatched == {"fuzz_0", "fuzz_1", "fuzz_2"}


# =========================================================================
# Tests: Fuzzer Filter
# =========================================================================


class TestFuzzerFilter:
    """
    Business rule: when fuzzer_filter is set, only named fuzzers are dispatched
    even if other fuzzers built successfully. Filter + status are AND conditions.
    """

    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._dispatch_celery_task")
    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._create_worker_workspace")
    def test_filter_selects_subset(self, mock_workspace, mock_celery, tmp_path):
        """3 successful fuzzers, filter=["fuzz_png"] → only fuzz_png dispatched."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path),
            _make_config(fuzzer_filter=["fuzz_png"]),
        )
        mock_workspace.return_value = str(tmp_path / "ws")
        mock_celery.return_value = {"celery_id": "c", "fuzzer": "", "sanitizer": ""}

        fuzzers = [
            _make_fuzzer("fuzz_png"),
            _make_fuzzer("fuzz_icc"),
            _make_fuzzer("fuzz_text"),
        ]
        jobs = dispatcher.dispatch(fuzzers)

        assert len(jobs) == 1
        assert mock_celery.call_args[0][0]["fuzzer"] == "fuzz_png"

    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._dispatch_celery_task")
    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._create_worker_workspace")
    def test_filter_no_match_zero_workers(self, mock_workspace, mock_celery, tmp_path):
        """Filter names a fuzzer that doesn't exist → zero workers."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path),
            _make_config(fuzzer_filter=["nonexistent"]),
        )
        fuzzers = [_make_fuzzer("fuzz_png"), _make_fuzzer("fuzz_icc")]
        assert dispatcher.dispatch(fuzzers) == []
        mock_celery.assert_not_called()

    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._dispatch_celery_task")
    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._create_worker_workspace")
    def test_filter_and_status_are_and_conditions(
        self, mock_workspace, mock_celery, tmp_path
    ):
        """Filter matches fuzz_icc but it FAILED → zero workers for fuzz_icc."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path),
            _make_config(fuzzer_filter=["fuzz_png", "fuzz_icc"]),
        )
        mock_workspace.return_value = str(tmp_path / "ws")
        mock_celery.return_value = {"celery_id": "c", "fuzzer": "", "sanitizer": ""}

        fuzzers = [
            _make_fuzzer("fuzz_png", FuzzerStatus.SUCCESS),
            _make_fuzzer("fuzz_icc", FuzzerStatus.FAILED),
            _make_fuzzer("fuzz_text", FuzzerStatus.SUCCESS),  # not in filter
        ]
        jobs = dispatcher.dispatch(fuzzers)

        assert len(jobs) == 1
        assert mock_celery.call_args[0][0]["fuzzer"] == "fuzz_png"


# =========================================================================
# Tests: Assignment Content (what actually reaches Celery)
# =========================================================================


class TestCeleryAssignment:
    """
    Business rule: the assignment dict sent to Celery must contain all fields
    that run_worker needs to function correctly. Missing fields cause runtime
    failures inside the Celery worker.

    These tests let _dispatch_celery_task run for real (only mock apply_async)
    to verify the actual assignment dict.
    """

    @patch("fuzzingbrain.core.logging.get_log_dir", return_value=None)
    @patch("fuzzingbrain.worker.tasks.run_worker.apply_async")
    def test_assignment_has_required_fields(
        self, mock_apply, mock_log_dir, tmp_path
    ):
        """Assignment must contain every field that run_worker() destructures."""
        task_id = str(ObjectId())
        task = _make_task(task_id=task_id, tmp_path=tmp_path)
        config = _make_config()
        dispatcher = _make_dispatcher(task, config)

        mock_result = MagicMock()
        mock_result.id = "celery-job-123"
        mock_apply.return_value = mock_result

        # Create workspace for real
        pair = {"fuzzer": "fuzz_png", "sanitizer": "address"}
        ws = dispatcher._create_worker_workspace(pair)

        dispatcher._dispatch_celery_task(pair, ws)

        # Extract the assignment dict sent to Celery
        assignment = mock_apply.call_args[1]["args"][0] if "args" in mock_apply.call_args[1] else mock_apply.call_args[0][0][0]

        # Required fields that run_worker() reads with [] (KeyError if missing)
        required_keys = ["task_id", "fuzzer", "sanitizer", "task_type",
                         "workspace_path", "project_name"]
        for key in required_keys:
            assert key in assignment, f"Assignment missing required field: {key}"

        # Verify values are correct (not just present)
        assert assignment["task_id"] == task_id
        assert assignment["fuzzer"] == "fuzz_png"
        assert assignment["sanitizer"] == "address"
        assert assignment["task_type"] == "pov"
        assert assignment["workspace_path"] == ws
        assert assignment["scan_mode"] == "full"

    @patch("fuzzingbrain.core.logging.get_log_dir", return_value=None)
    @patch("fuzzingbrain.worker.tasks.run_worker.apply_async")
    def test_each_pair_gets_correct_assignment(
        self, mock_apply, mock_log_dir, tmp_path
    ):
        """2 fuzzers × 2 sanitizers: each Celery call gets its own fuzzer+sanitizer."""
        task = _make_task(tmp_path=tmp_path)
        config = _make_config(sanitizers=["address", "memory"])
        dispatcher = _make_dispatcher(task, config)

        mock_result = MagicMock()
        mock_result.id = "celery-job"
        mock_apply.return_value = mock_result

        fuzzers = [_make_fuzzer("fuzz_a"), _make_fuzzer("fuzz_b")]
        dispatcher.dispatch(fuzzers)

        assert mock_apply.call_count == 4

        # Extract all (fuzzer, sanitizer) pairs from actual Celery calls
        celery_pairs = set()
        for call in mock_apply.call_args_list:
            args = call[1].get("args") or call[0][0]
            assignment = args[0]
            celery_pairs.add((assignment["fuzzer"], assignment["sanitizer"]))

        assert celery_pairs == {
            ("fuzz_a", "address"), ("fuzz_a", "memory"),
            ("fuzz_b", "address"), ("fuzz_b", "memory"),
        }

    @patch("fuzzingbrain.core.logging.get_log_dir", return_value=None)
    @patch("fuzzingbrain.worker.tasks.run_worker.apply_async")
    def test_celery_timeout_derived_from_config(
        self, mock_apply, mock_log_dir, tmp_path
    ):
        """Celery time_limit must match config.timeout_minutes × 60."""
        task = _make_task(tmp_path=tmp_path)
        config = _make_config(timeout_minutes=45)
        dispatcher = _make_dispatcher(task, config)

        mock_result = MagicMock()
        mock_result.id = "celery-job"
        mock_apply.return_value = mock_result

        pair = {"fuzzer": "fuzz_png", "sanitizer": "address"}
        ws = dispatcher._create_worker_workspace(pair)
        dispatcher._dispatch_celery_task(pair, ws)

        call_kwargs = mock_apply.call_args[1]
        assert call_kwargs["time_limit"] == 45 * 60
        assert call_kwargs["soft_time_limit"] == int(45 * 60 * 0.9)


# =========================================================================
# Tests: Workspace Isolation
# =========================================================================


class TestWorkspaceIsolation:
    """
    Business rule: each worker must get its own isolated workspace.
    Sharing a workspace would cause file conflicts between workers.
    """

    def test_different_pairs_get_different_workspaces(self, tmp_path):
        """Two distinct pairs must produce two distinct workspace paths."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path), _make_config()
        )
        ws_a = dispatcher._create_worker_workspace(
            {"fuzzer": "fuzz_png", "sanitizer": "address"}
        )
        ws_b = dispatcher._create_worker_workspace(
            {"fuzzer": "fuzz_png", "sanitizer": "memory"}
        )
        assert ws_a != ws_b, "Different pairs must get different workspaces"
        assert Path(ws_a).exists()
        assert Path(ws_b).exists()

    def test_workspace_is_clean_on_redispatch(self, tmp_path):
        """Re-dispatching same pair gives a clean workspace (no leftover files)."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path), _make_config()
        )
        pair = {"fuzzer": "fuzz_png", "sanitizer": "address"}

        ws = dispatcher._create_worker_workspace(pair)
        (Path(ws) / "stale_crash.txt").write_text("old data")

        ws2 = dispatcher._create_worker_workspace(pair)
        assert not (Path(ws2) / "stale_crash.txt").exists(), \
            "Stale files from previous run must be removed"

    def test_workspace_has_results_dir(self, tmp_path):
        """Every workspace must have a results/ directory for outputs."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path), _make_config()
        )
        ws = dispatcher._create_worker_workspace(
            {"fuzzer": "fuzz_png", "sanitizer": "address"}
        )
        assert (Path(ws) / "results").is_dir()


# =========================================================================
# Tests: Fault Tolerance
# =========================================================================


class TestFaultTolerance:
    """
    Business rule: dispatch is best-effort per pair.
    One pair failing must not prevent other pairs from being dispatched.
    """

    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._dispatch_celery_task")
    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._create_worker_workspace")
    def test_one_failure_does_not_block_others(
        self, mock_workspace, mock_celery, tmp_path
    ):
        """3 fuzzers, first one fails to dispatch → 2 still succeed."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path), _make_config()
        )
        mock_workspace.return_value = str(tmp_path / "ws")

        call_count = [0]

        def side_effect(pair, workspace_path):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("Celery connection lost")
            return {
                "celery_id": "c",
                "fuzzer": pair["fuzzer"],
                "sanitizer": pair["sanitizer"],
            }

        mock_celery.side_effect = side_effect

        fuzzers = [_make_fuzzer("a"), _make_fuzzer("b"), _make_fuzzer("c")]
        jobs = dispatcher.dispatch(fuzzers)

        assert mock_celery.call_count == 3, "All 3 must be attempted"
        assert len(jobs) == 2, "2 of 3 should succeed"

    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._dispatch_celery_task")
    @patch("fuzzingbrain.core.dispatcher.WorkerDispatcher._create_worker_workspace")
    def test_workspace_failure_does_not_block_others(
        self, mock_workspace, mock_celery, tmp_path
    ):
        """If workspace creation fails for one pair, others still proceed."""
        dispatcher = _make_dispatcher(
            _make_task(tmp_path=tmp_path), _make_config()
        )

        call_count = [0]

        def ws_side_effect(pair):
            call_count[0] += 1
            if call_count[0] == 1:
                raise OSError("Disk full")
            return str(tmp_path / "ws")

        mock_workspace.side_effect = ws_side_effect
        mock_celery.return_value = {"celery_id": "c", "fuzzer": "", "sanitizer": ""}

        fuzzers = [_make_fuzzer("a"), _make_fuzzer("b")]
        jobs = dispatcher.dispatch(fuzzers)

        # First workspace fails, so first celery call is skipped.
        # Second workspace succeeds, second celery call succeeds.
        assert len(jobs) == 1
