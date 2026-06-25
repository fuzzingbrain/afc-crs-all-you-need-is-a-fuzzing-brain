"""
Tests for FuzzingBrain stopping conditions.

Verifies that the system correctly stops when:
1. Timeout is reached
2. Budget limit is exceeded (llm_cost >= budget_limit)
3. POV count target is reached

Also tests the LLM call buffer initialization in Celery workers.

Run with: pytest tests/test_stopping_conditions.py -v
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
from bson import ObjectId


# ============================================================================
# Helpers
# ============================================================================


def _make_dispatcher(
    task_id=None,
    timeout_minutes=30,
    budget_limit=0.0,
    pov_count=0,
):
    """Create a WorkerDispatcher with mocked dependencies."""
    from fuzzingbrain.core.models import Task
    from fuzzingbrain.core.config import Config

    task_id = task_id or str(ObjectId())

    task = MagicMock(spec=Task)
    task.task_id = task_id
    task.task_type = MagicMock()
    task.task_type.value = "pov"
    task.scan_mode = MagicMock()
    task.scan_mode.value = "full"
    task.task_path = "/tmp/fake_workspace"
    task.project_name = "test_project"

    config = MagicMock(spec=Config)
    config.timeout_minutes = timeout_minutes
    config.budget_limit = budget_limit
    config.pov_count = pov_count
    config.sanitizers = ["address"]
    config.fuzzer_filter = None
    config.ossfuzz_project_name = "test_project"

    repos = MagicMock()

    # Patch FuzzerMonitor to avoid filesystem access
    with patch("fuzzingbrain.core.dispatcher.FuzzerMonitor"):
        from fuzzingbrain.core.dispatcher import WorkerDispatcher

        dispatcher = WorkerDispatcher(
            task=task,
            config=config,
            repos=repos,
            analyze_result=None,
        )

    return dispatcher, repos


def _run_wait(dispatcher, repos, timeout_minutes=60, **overrides):
    """
    Run wait_for_completion with mocked time.sleep and datetime.now.

    `overrides` can contain:
        now_times: list of datetime values for datetime.now() calls
        budget_limit: float (already set in dispatcher via _make_dispatcher)
    """
    now_times = overrides.get("now_times", None)

    # Default: first call is start time, subsequent calls within limit
    if now_times is None:
        base = datetime(2026, 1, 1, 0, 0, 0)
        now_times = [base, base + timedelta(seconds=1)]

    now_iter = iter(now_times)

    original_datetime = datetime

    class FakeDatetime(datetime):
        @classmethod
        def now(cls):
            try:
                return next(now_iter)
            except StopIteration:
                # Return last value repeatedly
                return now_times[-1]

    with patch("time.sleep"):
        with patch("datetime.datetime", FakeDatetime):
            return dispatcher.wait_for_completion(timeout_minutes=timeout_minutes)


# ============================================================================
# Test: Timeout stopping condition
# ============================================================================


class TestTimeoutCondition:
    """Tests for timeout-based task termination."""

    def test_timeout_triggers_shutdown(self):
        """Task should stop when elapsed time exceeds timeout_minutes."""
        dispatcher, repos = _make_dispatcher(timeout_minutes=1)

        dispatcher.get_status = MagicMock(return_value={
            "total": 1, "pending": 0, "building": 0,
            "running": 1, "completed": 0, "failed": 0,
        })
        dispatcher.is_complete = MagicMock(return_value=False)
        dispatcher.shutdown_all_fuzzers = MagicMock()
        repos.povs.count.return_value = 0

        # Time: start at 0:00, immediately jump to 0:02 (past 1min timeout)
        base = datetime(2026, 1, 1, 0, 0, 0)
        after = base + timedelta(minutes=2)

        result = _run_wait(
            dispatcher, repos, timeout_minutes=1,
            now_times=[base, after],
        )

        assert result["status"] == "timeout"
        dispatcher.shutdown_all_fuzzers.assert_called_once()

    def test_no_timeout_when_pov_found_first(self):
        """Task should not timeout if POV target reached first."""
        dispatcher, repos = _make_dispatcher(pov_count=1, timeout_minutes=60)

        dispatcher.get_status = MagicMock(return_value={
            "total": 1, "pending": 0, "building": 0,
            "running": 1, "completed": 0, "failed": 0,
        })
        dispatcher.is_complete = MagicMock(return_value=False)
        dispatcher.graceful_shutdown = MagicMock()
        dispatcher.shutdown_all_fuzzers = MagicMock()

        repos.tasks.collection.find_one.return_value = {"llm_cost": 0.0}
        repos.povs.count.return_value = 1  # POV found

        base = datetime(2026, 1, 1, 0, 0, 0)
        result = _run_wait(
            dispatcher, repos, timeout_minutes=60,
            now_times=[base, base + timedelta(seconds=5)],
        )

        assert result["status"] == "pov_target_reached"


# ============================================================================
# Test: Budget stopping condition
# ============================================================================


class TestBudgetCondition:
    """Tests for budget-based task termination."""

    def test_budget_exceeded_triggers_shutdown(self):
        """Task should stop when llm_cost >= budget_limit."""
        task_id = str(ObjectId())
        dispatcher, repos = _make_dispatcher(
            task_id=task_id,
            budget_limit=30.0,
            timeout_minutes=60,
        )

        dispatcher.get_status = MagicMock(return_value={
            "total": 1, "pending": 0, "building": 0,
            "running": 1, "completed": 0, "failed": 0,
        })
        dispatcher.is_complete = MagicMock(return_value=False)
        dispatcher.graceful_shutdown = MagicMock()
        dispatcher.shutdown_all_fuzzers = MagicMock()
        repos.povs.count.return_value = 0

        # $35 spent, limit is $30
        repos.tasks.collection.find_one.return_value = {"llm_cost": 35.0}

        base = datetime(2026, 1, 1, 0, 0, 0)
        result = _run_wait(
            dispatcher, repos, timeout_minutes=60,
            now_times=[base, base + timedelta(seconds=5)],
        )

        assert result["status"] == "budget_exceeded"
        assert "$35.00" in result["error"]
        assert "$30.00" in result["error"]
        dispatcher.graceful_shutdown.assert_called_once()
        dispatcher.shutdown_all_fuzzers.assert_called_once()

    def test_budget_exactly_at_limit(self):
        """Task should stop when llm_cost == budget_limit."""
        dispatcher, repos = _make_dispatcher(budget_limit=30.0, timeout_minutes=60)

        dispatcher.get_status = MagicMock(return_value={
            "total": 1, "pending": 0, "building": 0,
            "running": 1, "completed": 0, "failed": 0,
        })
        dispatcher.is_complete = MagicMock(return_value=False)
        dispatcher.graceful_shutdown = MagicMock()
        dispatcher.shutdown_all_fuzzers = MagicMock()
        repos.povs.count.return_value = 0

        repos.tasks.collection.find_one.return_value = {"llm_cost": 30.0}

        base = datetime(2026, 1, 1, 0, 0, 0)
        result = _run_wait(
            dispatcher, repos, timeout_minutes=60,
            now_times=[base, base + timedelta(seconds=5)],
        )

        assert result["status"] == "budget_exceeded"

    def test_no_budget_limit_skips_check(self):
        """When budget_limit=0, budget check should be skipped entirely."""
        dispatcher, repos = _make_dispatcher(
            budget_limit=0.0,
            pov_count=1,
            timeout_minutes=60,
        )

        dispatcher.get_status = MagicMock(return_value={
            "total": 1, "pending": 0, "building": 0,
            "running": 0, "completed": 1, "failed": 0,
        })
        dispatcher.is_complete = MagicMock(return_value=True)
        dispatcher.graceful_shutdown = MagicMock()
        dispatcher.shutdown_all_fuzzers = MagicMock()

        repos.povs.count.return_value = 1  # POV found

        base = datetime(2026, 1, 1, 0, 0, 0)
        result = _run_wait(
            dispatcher, repos, timeout_minutes=60,
            now_times=[base, base + timedelta(seconds=5)],
        )

        # Should NOT have queried tasks collection for llm_cost
        repos.tasks.collection.find_one.assert_not_called()
        assert result["status"] == "pov_target_reached"

    def test_budget_under_limit_continues(self):
        """Task should continue when llm_cost < budget_limit."""
        dispatcher, repos = _make_dispatcher(
            budget_limit=30.0,
            pov_count=1,
            timeout_minutes=60,
        )

        dispatcher.get_status = MagicMock(return_value={
            "total": 1, "pending": 0, "building": 0,
            "running": 1, "completed": 0, "failed": 0,
        })
        dispatcher.is_complete = MagicMock(return_value=False)
        dispatcher.graceful_shutdown = MagicMock()
        dispatcher.shutdown_all_fuzzers = MagicMock()

        # Under budget, but POV target reached
        repos.tasks.collection.find_one.return_value = {"llm_cost": 10.0}
        repos.povs.count.return_value = 1

        base = datetime(2026, 1, 1, 0, 0, 0)
        result = _run_wait(
            dispatcher, repos, timeout_minutes=60,
            now_times=[base, base + timedelta(seconds=5)],
        )

        assert result["status"] == "pov_target_reached"

    def test_budget_check_handles_missing_llm_cost(self):
        """Budget check should handle task doc without llm_cost field."""
        dispatcher, repos = _make_dispatcher(
            budget_limit=30.0,
            pov_count=1,
            timeout_minutes=60,
        )

        dispatcher.get_status = MagicMock(return_value={
            "total": 1, "pending": 0, "building": 0,
            "running": 1, "completed": 0, "failed": 0,
        })
        dispatcher.is_complete = MagicMock(return_value=False)
        dispatcher.graceful_shutdown = MagicMock()
        dispatcher.shutdown_all_fuzzers = MagicMock()

        # Task doc exists but no llm_cost field (defaults to 0.0)
        repos.tasks.collection.find_one.return_value = {}
        repos.povs.count.return_value = 1  # POV found

        base = datetime(2026, 1, 1, 0, 0, 0)
        result = _run_wait(
            dispatcher, repos, timeout_minutes=60,
            now_times=[base, base + timedelta(seconds=5)],
        )

        assert result["status"] == "pov_target_reached"

    def test_budget_check_handles_none_task_doc(self):
        """Budget check should handle find_one returning None."""
        dispatcher, repos = _make_dispatcher(
            budget_limit=30.0,
            pov_count=1,
            timeout_minutes=60,
        )

        dispatcher.get_status = MagicMock(return_value={
            "total": 1, "pending": 0, "building": 0,
            "running": 1, "completed": 0, "failed": 0,
        })
        dispatcher.is_complete = MagicMock(return_value=False)
        dispatcher.graceful_shutdown = MagicMock()
        dispatcher.shutdown_all_fuzzers = MagicMock()

        repos.tasks.collection.find_one.return_value = None
        repos.povs.count.return_value = 1  # POV found

        base = datetime(2026, 1, 1, 0, 0, 0)
        result = _run_wait(
            dispatcher, repos, timeout_minutes=60,
            now_times=[base, base + timedelta(seconds=5)],
        )

        assert result["status"] == "pov_target_reached"


# ============================================================================
# Test: POV count stopping condition
# ============================================================================


class TestPOVCountCondition:
    """Tests for POV count-based task termination."""

    def test_pov_target_reached(self):
        """Task should stop when verified POV count >= pov_count target."""
        task_id = str(ObjectId())
        dispatcher, repos = _make_dispatcher(
            task_id=task_id,
            pov_count=3,
            timeout_minutes=60,
        )

        dispatcher.get_status = MagicMock(return_value={
            "total": 1, "pending": 0, "building": 0,
            "running": 1, "completed": 0, "failed": 0,
        })
        dispatcher.is_complete = MagicMock(return_value=False)
        dispatcher.graceful_shutdown = MagicMock()
        dispatcher.shutdown_all_fuzzers = MagicMock()

        repos.tasks.collection.find_one.return_value = {"llm_cost": 0.0}
        repos.povs.count.return_value = 3

        base = datetime(2026, 1, 1, 0, 0, 0)
        result = _run_wait(
            dispatcher, repos, timeout_minutes=60,
            now_times=[base, base + timedelta(seconds=5)],
        )

        assert result["status"] == "pov_target_reached"
        assert result["pov_count"] == 3
        dispatcher.graceful_shutdown.assert_called_once()
        dispatcher.shutdown_all_fuzzers.assert_called_once()

    def test_pov_count_uses_objectid(self):
        """get_verified_pov_count should query with ObjectId, not string."""
        task_id = str(ObjectId())
        dispatcher, repos = _make_dispatcher(task_id=task_id, pov_count=1)

        repos.povs.count.return_value = 2

        count = dispatcher.get_verified_pov_count()

        assert count == 2
        call_args = repos.povs.count.call_args[0][0]
        assert isinstance(call_args["task_id"], ObjectId)
        assert str(call_args["task_id"]) == task_id
        assert call_args["is_successful"] is True

    def test_unlimited_pov_count(self):
        """When pov_count=0, POV target check should be skipped."""
        dispatcher, repos = _make_dispatcher(pov_count=0, timeout_minutes=1)

        assert dispatcher.pov_count_target == 0

        dispatcher.get_status = MagicMock(return_value={
            "total": 1, "pending": 0, "building": 0,
            "running": 1, "completed": 0, "failed": 0,
        })
        dispatcher.is_complete = MagicMock(return_value=False)
        dispatcher.shutdown_all_fuzzers = MagicMock()
        repos.povs.count.return_value = 10

        # Even with 10 POVs, should NOT stop (pov_count=0 means no target)
        # Will timeout instead
        base = datetime(2026, 1, 1, 0, 0, 0)
        after = base + timedelta(minutes=2)

        result = _run_wait(
            dispatcher, repos, timeout_minutes=1,
            now_times=[base, after],
        )

        assert result["status"] == "timeout"


# ============================================================================
# Test: ObjectId in dispatcher queries
# ============================================================================


class TestDispatcherObjectId:
    """Tests that dispatcher uses ObjectId consistently for MongoDB queries."""

    def test_task_oid_is_objectid(self):
        """Dispatcher should cache task_id as ObjectId."""
        task_id = str(ObjectId())
        dispatcher, _ = _make_dispatcher(task_id=task_id)

        assert isinstance(dispatcher._task_oid, ObjectId)
        assert str(dispatcher._task_oid) == task_id

    def test_get_results_uses_objectid(self):
        """get_results should use ObjectId for all queries."""
        task_id = str(ObjectId())
        dispatcher, repos = _make_dispatcher(task_id=task_id)

        mock_worker = MagicMock()
        mock_worker.fuzzer = "fuzz_test"
        mock_worker.sanitizer = "address"
        mock_worker.status.value = "completed"
        mock_worker.worker_id = str(ObjectId())
        mock_worker.pov_generated = 0
        mock_worker.patch_generated = 0
        mock_worker.error_msg = None
        mock_worker.get_duration_seconds.return_value = 60.0
        mock_worker.get_duration_str.return_value = "1.0m"
        repos.workers.find_by_task.return_value = [mock_worker]

        repos.suspicious_points.count.return_value = 0
        mock_sp = MagicMock()
        mock_sp.suspicious_point_id = str(ObjectId())
        repos.suspicious_points.find_all.return_value = [mock_sp]
        repos.povs.count.return_value = 0

        dispatcher.get_results()

        for call in repos.suspicious_points.count.call_args_list:
            query = call[0][0]
            assert isinstance(query["task_id"], ObjectId)

        for call in repos.povs.count.call_args_list:
            query = call[0][0]
            assert isinstance(query["task_id"], ObjectId)


# ============================================================================
# Test: LLM call buffer initialization
# ============================================================================


class TestWorkerLLMBuffer:
    """Tests for WorkerLLMBuffer (per-worker LLM call buffer)."""

    def test_get_database_import_exists(self):
        """get_database should be importable from fuzzingbrain.db."""
        from fuzzingbrain.db import get_database
        assert callable(get_database)

    def test_get_db_import_does_not_exist(self):
        """get_db should NOT be importable (the bug we fixed)."""
        with pytest.raises(ImportError):
            from fuzzingbrain.db import get_db  # noqa: F401

    def test_buffer_init_with_mongo(self):
        """Buffer should initialize with mongo_db."""
        from fuzzingbrain.llms.buffer import WorkerLLMBuffer

        mock_db = MagicMock()
        buffer = WorkerLLMBuffer(redis_url="redis://localhost:6379/0", mongo_db=mock_db)

        assert buffer.mongo_db is mock_db
        assert buffer._running is False

    def test_buffer_flush_skips_without_mongo(self):
        """Flush should return 0 when mongo_db is None."""
        from fuzzingbrain.llms.buffer import WorkerLLMBuffer

        buffer = WorkerLLMBuffer(redis_url=None, mongo_db=None)
        count = buffer._flush()
        assert count == 0

    def test_buffer_record_appends_to_memory(self):
        """record() should append to internal records list."""
        from fuzzingbrain.llms.buffer import WorkerLLMBuffer
        from fuzzingbrain.core.models.llm_call import LLMCall

        buffer = WorkerLLMBuffer(redis_url=None, mongo_db=None)

        call = LLMCall(
            agent_id="", worker_id="", task_id="",
            model="test-model", provider="test",
            input_tokens=100, output_tokens=50,
            cost=0.01, latency_ms=500,
        )
        buffer.record(call)

        assert len(buffer._records) == 1
        assert buffer._records[0]["model"] == "test-model"

    def test_buffer_flush_inserts_to_mongo(self):
        """Flush should insert_many records to MongoDB."""
        from fuzzingbrain.llms.buffer import WorkerLLMBuffer
        from fuzzingbrain.core.models.llm_call import LLMCall

        mock_db = MagicMock()
        buffer = WorkerLLMBuffer(redis_url=None, mongo_db=mock_db)

        call = LLMCall(
            agent_id="", worker_id="", task_id="",
            model="test-model", provider="test",
            input_tokens=100, output_tokens=50,
            cost=0.01, latency_ms=500,
        )
        buffer.record(call)
        count = buffer._flush()

        assert count == 1
        mock_db.llm_calls.insert_many.assert_called_once()
        assert len(buffer._records) == 0  # Cleared after flush

    def test_get_set_worker_buffer(self):
        """Module-level get/set should work correctly."""
        from fuzzingbrain.llms.buffer import (
            WorkerLLMBuffer, get_worker_buffer, set_worker_buffer,
        )

        # Initially None
        old = get_worker_buffer()

        try:
            buffer = WorkerLLMBuffer(redis_url=None, mongo_db=None)
            set_worker_buffer(buffer)
            assert get_worker_buffer() is buffer
        finally:
            set_worker_buffer(old)  # Restore


# ============================================================================
# Test: Exit condition priority
# ============================================================================


class TestExitConditionPriority:
    """Tests for the priority order of exit conditions."""

    def test_timeout_checked_before_budget(self):
        """Timeout should be checked before budget in the poll loop."""
        dispatcher, repos = _make_dispatcher(
            budget_limit=30.0,
            timeout_minutes=1,
        )

        dispatcher.get_status = MagicMock(return_value={
            "total": 1, "pending": 0, "building": 0,
            "running": 1, "completed": 0, "failed": 0,
        })
        dispatcher.is_complete = MagicMock(return_value=False)
        dispatcher.graceful_shutdown = MagicMock()
        dispatcher.shutdown_all_fuzzers = MagicMock()

        repos.tasks.collection.find_one.return_value = {"llm_cost": 50.0}
        repos.povs.count.return_value = 0

        # Both timeout and budget exceeded
        base = datetime(2026, 1, 1, 0, 0, 0)
        after = base + timedelta(minutes=2)

        result = _run_wait(
            dispatcher, repos, timeout_minutes=1,
            now_times=[base, after],
        )

        # Timeout checked first
        assert result["status"] == "timeout"

    def test_budget_checked_before_pov(self):
        """Budget should be checked before POV count in the poll loop."""
        dispatcher, repos = _make_dispatcher(
            budget_limit=30.0,
            pov_count=3,
            timeout_minutes=60,
        )

        dispatcher.get_status = MagicMock(return_value={
            "total": 1, "pending": 0, "building": 0,
            "running": 1, "completed": 0, "failed": 0,
        })
        dispatcher.is_complete = MagicMock(return_value=False)
        dispatcher.graceful_shutdown = MagicMock()
        dispatcher.shutdown_all_fuzzers = MagicMock()

        # Both budget exceeded and POV target reached
        repos.tasks.collection.find_one.return_value = {"llm_cost": 50.0}
        repos.povs.count.return_value = 5

        base = datetime(2026, 1, 1, 0, 0, 0)
        result = _run_wait(
            dispatcher, repos, timeout_minutes=60,
            now_times=[base, base + timedelta(seconds=5)],
        )

        # Budget checked before POV
        assert result["status"] == "budget_exceeded"
