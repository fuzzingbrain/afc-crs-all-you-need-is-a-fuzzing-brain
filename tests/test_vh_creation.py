# SPDX-License-Identifier: Apache-2.0
"""
Vulnerability Hypothesis Creation Tests

Tests the VH creation flow: LLM tool call → create_vulnerability_hypothesis_impl → client → DB.

Business invariants under test:
1. No lg_id in context → create VH blocked (Layer A guard)
2. LLM params (function_name, description, score) forwarded correctly to client
3. harness_name/sanitizer/lg_id/agent_id come from ContextVar, not LLM
4. New VH defaults to PENDING_VERIFY status so claim_for_verify() can pick it up
5. created_by_agent_id is set from context (not LLM)
6. sources array contains the correct harness/sanitizer pair
"""

import mongomock
import pytest
from unittest.mock import patch, MagicMock

from bson import ObjectId

from fuzzingbrain.core.models.vulnerability_hypothesis import VulnerabilityHypothesis
from fuzzingbrain.db.repository import VulnerabilityHypothesisRepository
from fuzzingbrain.tools.vulnerability_hypotheses import (
    create_vulnerability_hypothesis_impl,
    set_vh_context,
    set_vh_agent_id,
    get_vh_context,
)


# =========================================================================
# Helpers
# =========================================================================


def _mock_client_create_success(vh_id=None):
    """Return a mock AnalysisClient whose create_vulnerability_hypothesis returns success."""
    client = MagicMock()
    sid = vh_id or str(ObjectId())
    client.create_vulnerability_hypothesis.return_value = {
        "id": sid,
        "created": True,
        "merged": False,
    }
    return client


@pytest.fixture
def vh_repo():
    """VulnerabilityHypothesisRepository backed by mongomock."""
    client = mongomock.MongoClient()
    db = client["test_fuzzingbrain"]
    return VulnerabilityHypothesisRepository(db)


# =========================================================================
# Tests: Logic group guard (Layer A)
# =========================================================================


class TestLogicGroupGuard:
    """
    VH creation access is controlled at the agent level via include_vh_create_tools.
    The tool itself does not gate on lg_id — delta mode has no logic groups.
    """

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_no_lg_id_allows_creation(self, _ensure, mock_get_client):
        """Without lg_id (delta mode), create must succeed."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        set_vh_context("fuzz_png", "address", lg_id="", agent_id=str(ObjectId()))

        result = create_vulnerability_hypothesis_impl(
            function_name="parse_chunk",
            description="heap overflow in chunk parser",
        )

        assert result["success"] is True
        client.create_vulnerability_hypothesis.assert_called_once()

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_with_lg_id_allows_creation(self, _ensure, mock_get_client):
        """With lg_id set (fullscan VHG agent), create must succeed."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        lg_id = str(ObjectId())
        set_vh_context("fuzz_png", "address", lg_id=lg_id)

        result = create_vulnerability_hypothesis_impl(
            function_name="parse_chunk",
            description="heap overflow",
        )

        assert result["success"] is True
        client.create_vulnerability_hypothesis.assert_called_once()


# =========================================================================
# Tests: LLM params → client field flow
# =========================================================================


class TestVHFieldFlow:
    """
    Business rule: LLM-provided params must reach the client unchanged.
    System-injected fields (harness, sanitizer, lg_id, agent_id)
    must come from ContextVar.
    """

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_llm_params_forwarded_to_client(self, _ensure, mock_get_client):
        """All LLM-provided fields must arrive at the client."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        lg_id = str(ObjectId())
        set_vh_context("fuzz_png", "address", lg_id=lg_id)

        create_vulnerability_hypothesis_impl(
            function_name="decompress_data",
            description="UAF after realloc in decompression loop",
            score=0.85,
            important_controlflow=[
                {"type": "function", "name": "realloc", "location": "line 42"}
            ],
        )

        kw = client.create_vulnerability_hypothesis.call_args[1]
        assert kw["function_name"] == "decompress_data"
        assert kw["description"] == "UAF after realloc in decompression loop"
        assert kw["score"] == 0.85
        assert kw["important_controlflow"] == [
            {"type": "function", "name": "realloc", "location": "line 42"}
        ]

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_context_fields_injected_from_contextvar(self, _ensure, mock_get_client):
        """harness_name, sanitizer, lg_id, agent_id must come from ContextVar."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        lg_id = str(ObjectId())
        agent_id = str(ObjectId())
        set_vh_context(
            "fuzz_png", "address", lg_id=lg_id, agent_id=agent_id
        )

        create_vulnerability_hypothesis_impl(
            function_name="f",
            description="d",
        )

        kw = client.create_vulnerability_hypothesis.call_args[1]
        assert kw["harness_name"] == "fuzz_png"
        assert kw["sanitizer"] == "address"
        assert kw["lg_id"] == lg_id
        assert kw["agent_id"] == agent_id

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_different_worker_different_context(self, _ensure, mock_get_client):
        """Switching context must change harness/sanitizer in subsequent calls."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        d1 = str(ObjectId())
        set_vh_context("fuzz_png", "address", lg_id=d1)
        create_vulnerability_hypothesis_impl(
            function_name="f1", description="d1"
        )
        first = client.create_vulnerability_hypothesis.call_args[1]

        d2 = str(ObjectId())
        set_vh_context("fuzz_icc", "memory", lg_id=d2)
        create_vulnerability_hypothesis_impl(
            function_name="f2", description="d2"
        )
        second = client.create_vulnerability_hypothesis.call_args[1]

        assert first["harness_name"] == "fuzz_png"
        assert first["sanitizer"] == "address"
        assert second["harness_name"] == "fuzz_icc"
        assert second["sanitizer"] == "memory"

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_default_score_is_half(self, _ensure, mock_get_client):
        """If LLM doesn't provide score, default is 0.5."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        set_vh_context("fuzz_png", "address", lg_id=str(ObjectId()))

        create_vulnerability_hypothesis_impl(
            function_name="f",
            description="d",
            # score not provided
        )

        assert client.create_vulnerability_hypothesis.call_args[1]["score"] == 0.5


# =========================================================================
# Tests: VH initial state in DB
# =========================================================================


class TestVHInitialState:
    """
    Business rule: a newly created VH must have status=PENDING_VERIFY.
    claim_for_verify() queries for this status — wrong initial status = dead VH.
    Also: created_by_agent_id and sources must be correctly populated.
    """

    def test_vh_model_defaults_to_pending_verify(self):
        """VulnerabilityHypothesis() defaults to PENDING_VERIFY."""
        vh = VulnerabilityHypothesis()
        assert vh.status == "pending_verify"

    def test_vh_model_defaults_unchecked(self):
        """New VH must be is_checked_by_verifier=False, is_crash_found=False, is_important=False."""
        vh = VulnerabilityHypothesis()
        assert vh.is_checked_by_verifier is False
        assert vh.is_crash_found is False
        assert vh.proceed is True

    def test_vh_saved_with_pending_verify_found_by_claim(self, vh_repo):
        """Save VH → claim_for_verify must find it."""
        run_id = str(ObjectId())
        vh = VulnerabilityHypothesis(
            run_id=run_id,
            function_name="parse_chunk",
            description="heap overflow",
            score=0.8,
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
        )
        vh_repo.save(vh)

        claimed = vh_repo.claim_for_verify(
            run_id=run_id,
            processor_id=str(ObjectId()),
        )

        assert claimed is not None
        assert claimed.function_name == "parse_chunk"

    def test_created_by_agent_id_persisted(self, vh_repo):
        """created_by_agent_id from server must round-trip through DB."""
        run_id = str(ObjectId())
        agent_id = str(ObjectId())

        vh = VulnerabilityHypothesis(
            run_id=run_id,
            function_name="f",
            created_by_agent_id=agent_id,
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
        )
        vh_repo.save(vh)

        found = vh_repo.find_by_run(run_id)
        assert len(found) == 1
        assert found[0].created_by_agent_id == agent_id

    def test_sources_contain_harness_and_sanitizer(self, vh_repo):
        """The sources array must record which harness/sanitizer discovered this VH."""
        run_id = str(ObjectId())
        vh = VulnerabilityHypothesis(
            run_id=run_id,
            function_name="f",
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
        )
        vh_repo.save(vh)

        found = vh_repo.find_by_run(run_id)
        assert len(found) == 1
        assert found[0].sources == [
            {"harness_name": "fuzz_png", "sanitizer": "address"}
        ]

    def test_lg_id_persisted(self, vh_repo):
        """VH must record which logic group it belongs to."""
        run_id = str(ObjectId())
        lg_id = str(ObjectId())

        vh = VulnerabilityHypothesis(
            run_id=run_id,
            function_name="f",
            lg_id=lg_id,
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
        )
        vh_repo.save(vh)

        found = vh_repo.find_by_run(run_id)
        assert len(found) == 1
        assert found[0].lg_id == lg_id


# =========================================================================
# Tests: VH context isolation
# =========================================================================


class TestVHContextIsolation:
    """
    Business rule: set_vh_context only affects current context.
    set_vh_agent_id sets agent_id without touching lg_id.
    """

    def test_set_vh_agent_id_preserves_lg_id(self):
        """set_vh_agent_id must NOT clear lg_id."""
        lg_id = str(ObjectId())
        set_vh_context("fuzz_png", "address", lg_id=lg_id)

        # Agent startup calls set_vh_agent_id
        new_agent_id = str(ObjectId())
        set_vh_agent_id(new_agent_id)

        _, _, ctx_logic_group, ctx_agent = get_vh_context()
        assert ctx_logic_group == lg_id, "lg_id must not be cleared"
        assert ctx_agent == new_agent_id

    def test_set_vh_context_replaces_all_fields(self):
        """set_vh_context replaces everything including lg_id."""
        set_vh_context(
            "fuzz_png", "address", lg_id="old_dir", agent_id="old_agent"
        )
        set_vh_context(
            "fuzz_icc", "memory", lg_id="new_dir", agent_id="new_agent"
        )

        harness, san, logic_group, agent = get_vh_context()
        assert harness == "fuzz_icc"
        assert san == "memory"
        assert logic_group == "new_dir"
        assert agent == "new_agent"
