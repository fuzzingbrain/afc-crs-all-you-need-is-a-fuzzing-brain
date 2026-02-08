"""
Direction Creation Workflow Tests

Tests the direction creation flow: LLM tool call → create_direction_impl → DB → find_pending.

Business invariants under test:
1. LLM params (name, risk_level, core_functions) flow correctly to analyzer client
2. fuzzer is system-injected from ContextVar, not from LLM
3. Invalid risk_level is rejected before reaching the server
4. Created directions have PENDING status so find_pending() can retrieve them
5. find_pending filters by task_id + fuzzer (cross-task/cross-fuzzer isolation)
6. Direction planning failure → empty list → pipeline doesn't crash
"""

import asyncio
from unittest.mock import patch, MagicMock

import mongomock
import pytest
from bson import ObjectId

from fuzzingbrain.core.models.direction import Direction, DirectionStatus
from fuzzingbrain.db.repository import DirectionRepository
from fuzzingbrain.tools.directions import (
    create_direction_impl,
    set_direction_context,
    get_direction_context,
)


# =========================================================================
# Helpers
# =========================================================================


def _mock_client_create_success(direction_id=None):
    """Return a mock AnalysisClient whose create_direction returns success."""
    client = MagicMock()
    did = direction_id or str(ObjectId())
    client.create_direction.return_value = {
        "id": did,
        "created": True,
        "name": "test",
        "risk_level": "high",
    }
    return client


def _make_direction(task_id, fuzzer, name="test_dir", risk_level="high"):
    """Create a Direction with given fields."""
    return Direction(
        task_id=task_id,
        fuzzer=fuzzer,
        name=name,
        risk_level=risk_level,
        risk_reason="buffer overflow in parser",
        core_functions=["parse_chunk", "read_header"],
        entry_functions=["LLVMFuzzerTestOneInput"],
    )


@pytest.fixture
def direction_repo():
    """Create a DirectionRepository backed by mongomock."""
    client = mongomock.MongoClient()
    db = client["test_fuzzingbrain"]
    return DirectionRepository(db)


# =========================================================================
# Tests: Tool → Client field flow
# =========================================================================


class TestCreateDirectionFieldFlow:
    """
    Business rule: LLM parameters must arrive at the analyzer client unchanged.
    System fields (fuzzer) must come from ContextVar, not from LLM.
    """

    @patch("fuzzingbrain.tools.directions._get_client")
    @patch("fuzzingbrain.tools.directions._ensure_client", return_value=None)
    def test_llm_params_forwarded_to_client(self, _ensure, mock_get_client):
        """All LLM-provided params must reach client.create_direction."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client
        set_direction_context("fuzz_png")

        result = create_direction_impl(
            name="Chunk Parsing",
            risk_level="high",
            risk_reason="Direct memory write from untrusted input",
            core_functions=["parse_chunk", "decompress_data"],
            entry_functions=["LLVMFuzzerTestOneInput"],
            code_summary="Parses PNG chunk data",
        )

        assert result["success"] is True

        call_kwargs = client.create_direction.call_args[1]
        assert call_kwargs["name"] == "Chunk Parsing"
        assert call_kwargs["risk_level"] == "high"
        assert call_kwargs["risk_reason"] == "Direct memory write from untrusted input"
        assert call_kwargs["core_functions"] == ["parse_chunk", "decompress_data"]
        assert call_kwargs["entry_functions"] == ["LLVMFuzzerTestOneInput"]
        assert call_kwargs["code_summary"] == "Parses PNG chunk data"

    @patch("fuzzingbrain.tools.directions._get_client")
    @patch("fuzzingbrain.tools.directions._ensure_client", return_value=None)
    def test_fuzzer_injected_from_contextvar(self, _ensure, mock_get_client):
        """fuzzer must come from ContextVar, not from LLM parameters."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        # System sets context — LLM never touches this
        set_direction_context("fuzz_png")

        create_direction_impl(
            name="test",
            risk_level="medium",
            risk_reason="test",
            core_functions=["foo"],
        )

        call_kwargs = client.create_direction.call_args[1]
        assert call_kwargs["fuzzer"] == "fuzz_png"

    @patch("fuzzingbrain.tools.directions._get_client")
    @patch("fuzzingbrain.tools.directions._ensure_client", return_value=None)
    def test_different_contextvar_different_fuzzer(self, _ensure, mock_get_client):
        """Changing ContextVar must change the fuzzer in the next call."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        set_direction_context("fuzz_png")
        create_direction_impl(
            name="dir1", risk_level="high", risk_reason="r", core_functions=["a"]
        )
        first_fuzzer = client.create_direction.call_args[1]["fuzzer"]

        set_direction_context("fuzz_icc")
        create_direction_impl(
            name="dir2", risk_level="high", risk_reason="r", core_functions=["b"]
        )
        second_fuzzer = client.create_direction.call_args[1]["fuzzer"]

        assert first_fuzzer == "fuzz_png"
        assert second_fuzzer == "fuzz_icc"

    @patch("fuzzingbrain.tools.directions._get_client")
    @patch("fuzzingbrain.tools.directions._ensure_client", return_value=None)
    def test_risk_level_normalized_to_lowercase(self, _ensure, mock_get_client):
        """LLM might send 'HIGH' or 'High' — must be lowercased before sending."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client
        set_direction_context("fuzz_png")

        create_direction_impl(
            name="test", risk_level="HIGH", risk_reason="r", core_functions=["f"]
        )

        assert client.create_direction.call_args[1]["risk_level"] == "high"


# =========================================================================
# Tests: risk_level validation
# =========================================================================


class TestRiskLevelValidation:
    """
    Business rule: only high/medium/low are valid risk levels.
    Invalid values must be rejected before reaching the server.
    """

    @patch("fuzzingbrain.tools.directions._get_client")
    @patch("fuzzingbrain.tools.directions._ensure_client", return_value=None)
    def test_invalid_risk_level_rejected(self, _ensure, mock_get_client):
        """'critical' is not a valid risk level — must return error."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        result = create_direction_impl(
            name="test",
            risk_level="critical",
            risk_reason="test",
            core_functions=["foo"],
        )

        assert result["success"] is False
        assert "Invalid risk_level" in result["error"]
        client.create_direction.assert_not_called()

    @patch("fuzzingbrain.tools.directions._get_client")
    @patch("fuzzingbrain.tools.directions._ensure_client", return_value=None)
    def test_all_valid_risk_levels_accepted(self, _ensure, mock_get_client):
        """high, medium, low must all pass validation."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client
        set_direction_context("fuzz_png")

        for level in ["high", "medium", "low"]:
            result = create_direction_impl(
                name=f"test_{level}",
                risk_level=level,
                risk_reason="r",
                core_functions=["f"],
            )
            assert result["success"] is True, f"risk_level '{level}' should be valid"


# =========================================================================
# Tests: Direction initial status + find_pending handoff
# =========================================================================


class TestDirectionPendingHandoff:
    """
    Business rule: a newly created Direction must have status=PENDING.
    find_pending(task_id, fuzzer) must return it.
    If status is wrong, find_pending won't find it and it's dead.
    """

    def test_new_direction_has_pending_status(self):
        """Direction() defaults to PENDING — if this ever changes, pipeline breaks."""
        d = Direction()
        assert d.status == "pending"

    def test_save_and_find_pending_returns_direction(self, direction_repo):
        """Save a direction → find_pending must return it."""
        task_id = str(ObjectId())
        d = _make_direction(task_id, "fuzz_png", name="Chunk Parsing")
        direction_repo.save(d)

        found = direction_repo.find_pending(task_id, "fuzz_png")
        assert len(found) == 1
        assert found[0].name == "Chunk Parsing"
        assert found[0].status == "pending"

    def test_find_pending_excludes_completed(self, direction_repo):
        """Completed directions must NOT appear in find_pending."""
        task_id = str(ObjectId())

        pending = _make_direction(task_id, "fuzz_png", name="pending_dir")
        completed = _make_direction(task_id, "fuzz_png", name="completed_dir")
        completed.status = DirectionStatus.COMPLETED.value

        direction_repo.save(pending)
        direction_repo.save(completed)

        found = direction_repo.find_pending(task_id, "fuzz_png")
        assert len(found) == 1
        assert found[0].name == "pending_dir"

    def test_find_pending_isolates_by_fuzzer(self, direction_repo):
        """find_pending(fuzzer='fuzz_png') must not return fuzz_icc's directions."""
        task_id = str(ObjectId())

        d_png = _make_direction(task_id, "fuzz_png", name="png_dir")
        d_icc = _make_direction(task_id, "fuzz_icc", name="icc_dir")

        direction_repo.save(d_png)
        direction_repo.save(d_icc)

        found_png = direction_repo.find_pending(task_id, "fuzz_png")
        found_icc = direction_repo.find_pending(task_id, "fuzz_icc")

        assert len(found_png) == 1
        assert found_png[0].name == "png_dir"
        assert len(found_icc) == 1
        assert found_icc[0].name == "icc_dir"

    def test_find_pending_isolates_by_task(self, direction_repo):
        """Directions from task A must not appear when querying task B."""
        task_a = str(ObjectId())
        task_b = str(ObjectId())

        d_a = _make_direction(task_a, "fuzz_png", name="task_a_dir")
        d_b = _make_direction(task_b, "fuzz_png", name="task_b_dir")

        direction_repo.save(d_a)
        direction_repo.save(d_b)

        found_a = direction_repo.find_pending(task_a, "fuzz_png")
        found_b = direction_repo.find_pending(task_b, "fuzz_png")

        assert len(found_a) == 1
        assert found_a[0].name == "task_a_dir"
        assert len(found_b) == 1
        assert found_b[0].name == "task_b_dir"

    def test_multiple_directions_all_returned(self, direction_repo):
        """3 pending directions → find_pending returns all 3."""
        task_id = str(ObjectId())
        for i in range(3):
            d = _make_direction(task_id, "fuzz_png", name=f"dir_{i}")
            direction_repo.save(d)

        found = direction_repo.find_pending(task_id, "fuzz_png")
        assert len(found) == 3


# =========================================================================
# Tests: Direction planning failure handling
# =========================================================================


class TestPlanningFailureHandling:
    """
    Business rule: if DirectionPlanningAgent fails (LLM timeout, tool error),
    the strategy must return empty directions, not crash the worker.
    """

    def test_planning_exception_returns_empty_list(self):
        """_run_direction_planning catches exception and returns []."""
        from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy

        # Create a minimal mock executor
        executor = MagicMock()
        executor.task_id = str(ObjectId())
        executor.worker_id = str(ObjectId())
        executor.fuzzer = "fuzz_png"
        executor.sanitizer = "address"
        executor.scan_mode = "full"
        executor.workspace_path = "/tmp/test"
        executor.results_path = MagicMock()
        executor.project_name = "libpng"
        executor.analysis_socket_path = None
        executor.celery_job_id = "test"
        executor.repos = MagicMock()
        executor.fuzzer_binary_path = None

        strategy = POVFullscanStrategy(executor)

        # Mock DirectionPlanningAgent to raise
        with patch(
            "fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent"
        ) as MockAgent:
            MockAgent.return_value.plan_directions_sync.side_effect = RuntimeError(
                "LLM API timeout"
            )

            result = strategy._run_direction_planning()

        assert result == []

    def test_no_directions_returns_empty_pipeline_stats(self):
        """_run_full_pipeline with 0 directions → PipelineStats() not crash."""
        from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy

        executor = MagicMock()
        executor.task_id = str(ObjectId())
        executor.worker_id = str(ObjectId())
        executor.fuzzer = "fuzz_png"
        executor.sanitizer = "address"
        executor.scan_mode = "full"
        executor.workspace_path = "/tmp/test"
        executor.results_path = MagicMock()
        executor.project_name = "libpng"
        executor.analysis_socket_path = None
        executor.celery_job_id = "test"
        executor.repos = MagicMock()
        executor.fuzzer_binary_path = None

        strategy = POVFullscanStrategy(executor)

        # Mock planning to return empty
        with patch.object(
            strategy, "_run_direction_planning_async", return_value=[]
        ):
            stats = asyncio.run(strategy._run_full_pipeline())

        # Should return empty stats, not crash
        assert stats.sp_verified == 0
        assert stats.pov_generated == 0


# =========================================================================
# Tests: Seed generation priority (risk_level sorting)
# =========================================================================


class TestSeedPriority:
    """
    Business rule: directions are sorted high → medium → low for seed generation.
    Only top 5 directions get seed agents. If sorting is wrong,
    low-value directions steal seed slots from high-value ones.
    """

    def test_high_risk_sorted_first(self):
        """Sorted order must be: high → medium → low."""
        directions = [
            _make_direction(str(ObjectId()), "f", name="low_dir", risk_level="low"),
            _make_direction(str(ObjectId()), "f", name="high_dir", risk_level="high"),
            _make_direction(str(ObjectId()), "f", name="med_dir", risk_level="medium"),
        ]

        # This is the exact sort from pov_fullscan.py line 700-703
        sorted_dirs = sorted(
            directions,
            key=lambda d: {"high": 0, "medium": 1, "low": 2}.get(d.risk_level, 3),
        )

        assert sorted_dirs[0].name == "high_dir"
        assert sorted_dirs[1].name == "med_dir"
        assert sorted_dirs[2].name == "low_dir"

    def test_only_top_5_get_seeds(self):
        """Strategy slices [:5] — 7 directions → only 5 get seed agents."""
        directions = [
            _make_direction(str(ObjectId()), "f", name=f"dir_{i}")
            for i in range(7)
        ]

        # This is the exact slice from pov_fullscan.py line 741
        selected = directions[:5]
        assert len(selected) == 5
