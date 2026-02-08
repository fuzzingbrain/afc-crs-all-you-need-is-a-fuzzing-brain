"""
Suspicious Point Creation Tests

Tests the SP creation flow: LLM tool call → create_suspicious_point_impl → client → DB.

Business invariants under test:
1. No direction_id in context → create SP blocked (Layer A guard)
2. LLM params (function_name, vuln_type, description, score) forwarded correctly to client
3. harness_name/sanitizer/direction_id/agent_id come from ContextVar, not LLM
4. New SP defaults to PENDING_VERIFY status so claim_for_verify() can pick it up
5. created_by_agent_id is set from context (not LLM)
6. sources array contains the correct harness/sanitizer pair
"""

import mongomock
import pytest
from unittest.mock import patch, MagicMock

from bson import ObjectId

from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint, SPStatus
from fuzzingbrain.db.repository import SuspiciousPointRepository
from fuzzingbrain.tools.suspicious_points import (
    create_suspicious_point_impl,
    set_sp_context,
    set_sp_agent_id,
    get_sp_context,
)


# =========================================================================
# Helpers
# =========================================================================


def _mock_client_create_success(sp_id=None):
    """Return a mock AnalysisClient whose create_suspicious_point returns success."""
    client = MagicMock()
    sid = sp_id or str(ObjectId())
    client.create_suspicious_point.return_value = {
        "id": sid,
        "created": True,
        "merged": False,
    }
    return client


@pytest.fixture
def sp_repo():
    """SuspiciousPointRepository backed by mongomock."""
    client = mongomock.MongoClient()
    db = client["test_fuzzingbrain"]
    return SuspiciousPointRepository(db)


# =========================================================================
# Tests: Direction guard (Layer A)
# =========================================================================


class TestDirectionGuard:
    """
    Business rule: only SP Finding agents (with direction_id set) may create SPs.
    SPVerifier and POVAgent must NOT be able to create SPs even if they
    somehow get access to the tool.
    """

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_no_direction_id_blocks_creation(self, _ensure, mock_get_client):
        """Without direction_id in context, create must fail."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        # Set context WITHOUT direction_id (simulates SPVerifier/POVAgent)
        set_sp_context("fuzz_png", "address", direction_id="", agent_id=str(ObjectId()))

        result = create_suspicious_point_impl(
            function_name="parse_chunk",
            vuln_type="buffer-overflow",
            description="heap overflow in chunk parser",
        )

        assert result["success"] is False
        assert "no direction_id" in result["error"]
        client.create_suspicious_point.assert_not_called()

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_with_direction_id_allows_creation(self, _ensure, mock_get_client):
        """With direction_id set (SPG agent), create must succeed."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        direction_id = str(ObjectId())
        set_sp_context("fuzz_png", "address", direction_id=direction_id)

        result = create_suspicious_point_impl(
            function_name="parse_chunk",
            vuln_type="buffer-overflow",
            description="heap overflow",
        )

        assert result["success"] is True
        client.create_suspicious_point.assert_called_once()

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_set_sp_agent_id_does_not_bypass_guard(self, _ensure, mock_get_client):
        """
        set_sp_agent_id() only sets agent_id, not direction_id.
        An agent that only calls set_sp_agent_id (SPVerifier) must still be blocked.
        """
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        # Simulate SPVerifier: set_sp_context without direction, then set_sp_agent_id
        set_sp_context("fuzz_png", "address", direction_id="")
        set_sp_agent_id(str(ObjectId()))

        result = create_suspicious_point_impl(
            function_name="parse_chunk",
            vuln_type="buffer-overflow",
            description="test",
        )

        assert result["success"] is False
        client.create_suspicious_point.assert_not_called()


# =========================================================================
# Tests: LLM params → client field flow
# =========================================================================


class TestSPFieldFlow:
    """
    Business rule: LLM-provided params must reach the client unchanged.
    System-injected fields (harness, sanitizer, direction_id, agent_id)
    must come from ContextVar.
    """

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_llm_params_forwarded_to_client(self, _ensure, mock_get_client):
        """All LLM-provided fields must arrive at the client."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        direction_id = str(ObjectId())
        set_sp_context("fuzz_png", "address", direction_id=direction_id)

        create_suspicious_point_impl(
            function_name="decompress_data",
            vuln_type="use-after-free",
            description="UAF after realloc in decompression loop",
            score=0.85,
            important_controlflow=[{"type": "function", "name": "realloc", "location": "line 42"}],
        )

        kw = client.create_suspicious_point.call_args[1]
        assert kw["function_name"] == "decompress_data"
        assert kw["vuln_type"] == "use-after-free"
        assert kw["description"] == "UAF after realloc in decompression loop"
        assert kw["score"] == 0.85
        assert kw["important_controlflow"] == [
            {"type": "function", "name": "realloc", "location": "line 42"}
        ]

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_context_fields_injected_from_contextvar(self, _ensure, mock_get_client):
        """harness_name, sanitizer, direction_id, agent_id must come from ContextVar."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        direction_id = str(ObjectId())
        agent_id = str(ObjectId())
        set_sp_context("fuzz_png", "address", direction_id=direction_id, agent_id=agent_id)

        create_suspicious_point_impl(
            function_name="f",
            vuln_type="buffer-overflow",
            description="d",
        )

        kw = client.create_suspicious_point.call_args[1]
        assert kw["harness_name"] == "fuzz_png"
        assert kw["sanitizer"] == "address"
        assert kw["direction_id"] == direction_id
        assert kw["agent_id"] == agent_id

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_different_worker_different_context(self, _ensure, mock_get_client):
        """Switching context must change harness/sanitizer in subsequent calls."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        d1 = str(ObjectId())
        set_sp_context("fuzz_png", "address", direction_id=d1)
        create_suspicious_point_impl(
            function_name="f1", vuln_type="bof", description="d1"
        )
        first = client.create_suspicious_point.call_args[1]

        d2 = str(ObjectId())
        set_sp_context("fuzz_icc", "memory", direction_id=d2)
        create_suspicious_point_impl(
            function_name="f2", vuln_type="uaf", description="d2"
        )
        second = client.create_suspicious_point.call_args[1]

        assert first["harness_name"] == "fuzz_png"
        assert first["sanitizer"] == "address"
        assert second["harness_name"] == "fuzz_icc"
        assert second["sanitizer"] == "memory"

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_default_score_is_half(self, _ensure, mock_get_client):
        """If LLM doesn't provide score, default is 0.5."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        set_sp_context("fuzz_png", "address", direction_id=str(ObjectId()))

        create_suspicious_point_impl(
            function_name="f",
            vuln_type="bof",
            description="d",
            # score not provided
        )

        assert client.create_suspicious_point.call_args[1]["score"] == 0.5


# =========================================================================
# Tests: SP initial state in DB
# =========================================================================


class TestSPInitialState:
    """
    Business rule: a newly created SP must have status=PENDING_VERIFY.
    claim_for_verify() queries for this status — wrong initial status = dead SP.
    Also: created_by_agent_id and sources must be correctly populated.
    """

    def test_sp_model_defaults_to_pending_verify(self):
        """SuspiciousPoint() defaults to PENDING_VERIFY."""
        sp = SuspiciousPoint()
        assert sp.status == "pending_verify"

    def test_sp_model_defaults_unchecked(self):
        """New SP must be is_checked=False, is_real=False, is_important=False."""
        sp = SuspiciousPoint()
        assert sp.is_checked is False
        assert sp.is_real is False
        assert sp.is_important is False

    def test_sp_saved_with_pending_verify_found_by_claim(self, sp_repo):
        """Save SP → claim_for_verify must find it."""
        task_id = str(ObjectId())
        sp = SuspiciousPoint(
            task_id=task_id,
            function_name="parse_chunk",
            description="heap overflow",
            vuln_type="buffer-overflow",
            score=0.8,
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
        )
        sp_repo.save(sp)

        claimed = sp_repo.claim_for_verify(
            task_id=task_id,
            processor_id=str(ObjectId()),
        )

        assert claimed is not None
        assert claimed.function_name == "parse_chunk"

    def test_created_by_agent_id_persisted(self, sp_repo):
        """created_by_agent_id from server must round-trip through DB."""
        task_id = str(ObjectId())
        agent_id = str(ObjectId())

        sp = SuspiciousPoint(
            task_id=task_id,
            function_name="f",
            created_by_agent_id=agent_id,
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
        )
        sp_repo.save(sp)

        found = sp_repo.find_by_task(task_id)
        assert len(found) == 1
        assert found[0].created_by_agent_id == agent_id

    def test_sources_contain_harness_and_sanitizer(self, sp_repo):
        """The sources array must record which harness/sanitizer discovered this SP."""
        task_id = str(ObjectId())
        sp = SuspiciousPoint(
            task_id=task_id,
            function_name="f",
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
        )
        sp_repo.save(sp)

        found = sp_repo.find_by_task(task_id)
        assert len(found) == 1
        assert found[0].sources == [{"harness_name": "fuzz_png", "sanitizer": "address"}]

    def test_direction_id_persisted(self, sp_repo):
        """SP must record which direction it belongs to."""
        task_id = str(ObjectId())
        direction_id = str(ObjectId())

        sp = SuspiciousPoint(
            task_id=task_id,
            function_name="f",
            direction_id=direction_id,
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
        )
        sp_repo.save(sp)

        found = sp_repo.find_by_task(task_id)
        assert len(found) == 1
        assert found[0].direction_id == direction_id


# =========================================================================
# Tests: SP context isolation
# =========================================================================


class TestSPContextIsolation:
    """
    Business rule: set_sp_context only affects current context.
    set_sp_agent_id sets agent_id without touching direction_id.
    """

    def test_set_sp_agent_id_preserves_direction_id(self):
        """set_sp_agent_id must NOT clear direction_id."""
        direction_id = str(ObjectId())
        set_sp_context("fuzz_png", "address", direction_id=direction_id)

        # Agent startup calls set_sp_agent_id
        new_agent_id = str(ObjectId())
        set_sp_agent_id(new_agent_id)

        _, _, ctx_direction, ctx_agent = get_sp_context()
        assert ctx_direction == direction_id, "direction_id must not be cleared"
        assert ctx_agent == new_agent_id

    def test_set_sp_context_replaces_all_fields(self):
        """set_sp_context replaces everything including direction_id."""
        set_sp_context("fuzz_png", "address", direction_id="old_dir", agent_id="old_agent")
        set_sp_context("fuzz_icc", "memory", direction_id="new_dir", agent_id="new_agent")

        harness, san, direction, agent = get_sp_context()
        assert harness == "fuzz_icc"
        assert san == "memory"
        assert direction == "new_dir"
        assert agent == "new_agent"
