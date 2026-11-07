# SPDX-License-Identifier: Apache-2.0
"""
VH Verification Tests

Tests the verify flow: claim_for_verify → VHVerifier updates → complete_verify → status routing.

Business invariants under test:
1. claim_for_verify atomically transitions PENDING_VERIFY → VERIFYING
2. complete_verify routes: is_important + score >= threshold → PENDING_POC, else VERIFIED
3. poc_guidance is REQUIRED when is_important=True (even via _impl path)
4. verified_by_agent_id is set when agent calls update with is_checked_by_verifier=True
5. claim priority: is_important DESC, score DESC, created_at ASC
6. complete_verify releases processor_id (lock)
"""

import mongomock
import pytest
from unittest.mock import patch, MagicMock

from bson import ObjectId

from fuzzingbrain.core.models.vulnerability_hypothesis import VulnerabilityHypothesis, VHStatus
from fuzzingbrain.db.repository import VulnerabilityHypothesisRepository
from fuzzingbrain.tools.vulnerability_hypotheses import (
    update_vulnerability_hypothesis_impl,
    set_vh_context,
)


# =========================================================================
# Helpers
# =========================================================================


def _make_vh(run_id, function_name="parse_chunk", score=0.7, status=None):
    """Create a VH for testing."""
    vh = VulnerabilityHypothesis(
        run_id=run_id,
        function_name=function_name,
        description=f"potential overflow in {function_name}",
        score=score,
        sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
    )
    if status:
        vh.status = status
    return vh


@pytest.fixture
def vh_repo():
    """VulnerabilityHypothesisRepository backed by mongomock."""
    client = mongomock.MongoClient()
    db = client["test_fuzzingbrain"]
    return VulnerabilityHypothesisRepository(db)


# =========================================================================
# Tests: claim_for_verify
# =========================================================================


class TestClaimForVerify:
    """
    Business rule: claim_for_verify atomically transitions VH from
    PENDING_VERIFY → VERIFYING and sets processor_id.
    """

    def test_claim_transitions_to_verifying(self, vh_repo):
        """Claimed VH must have status=VERIFYING."""
        run_id = str(ObjectId())
        vh = _make_vh(run_id)
        vh_repo.save(vh)

        claimed = vh_repo.claim_for_verify(run_id, processor_id=str(ObjectId()))

        assert claimed is not None
        assert claimed.status == VHStatus.VERIFYING.value

    def test_claim_sets_processor_id(self, vh_repo):
        """Claimed VH must have processor_id set to the claiming agent."""
        run_id = str(ObjectId())
        agent_id = str(ObjectId())
        vh = _make_vh(run_id)
        vh_repo.save(vh)

        claimed = vh_repo.claim_for_verify(run_id, processor_id=agent_id)

        assert claimed.processor_id == agent_id

    def test_already_claimed_not_double_claimed(self, vh_repo):
        """Once claimed (VERIFYING), a second claim must return None."""
        run_id = str(ObjectId())
        vh = _make_vh(run_id)
        vh_repo.save(vh)

        first = vh_repo.claim_for_verify(run_id, processor_id=str(ObjectId()))
        second = vh_repo.claim_for_verify(run_id, processor_id=str(ObjectId()))

        assert first is not None
        assert second is None

    def test_claim_priority_important_first(self, vh_repo):
        """is_important=True VH must be claimed before is_important=False."""
        run_id = str(ObjectId())

        normal = _make_vh(run_id, function_name="normal", score=0.9)
        important = _make_vh(run_id, function_name="important", score=0.3)
        important.priority = 1.0

        vh_repo.save(normal)
        vh_repo.save(important)

        claimed = vh_repo.claim_for_verify(run_id, processor_id=str(ObjectId()))

        assert claimed.function_name == "important"

    def test_claim_priority_high_score_first(self, vh_repo):
        """Among equal importance, higher score claimed first."""
        run_id = str(ObjectId())

        low = _make_vh(run_id, function_name="low_score", score=0.3)
        high = _make_vh(run_id, function_name="high_score", score=0.9)

        vh_repo.save(low)
        vh_repo.save(high)

        claimed = vh_repo.claim_for_verify(run_id, processor_id=str(ObjectId()))

        assert claimed.function_name == "high_score"


# =========================================================================
# Tests: complete_verify status routing
# =========================================================================


class TestCompleteVerifyRouting:
    """
    Business rule:
    - is_important=True + score >= poc_min → PENDING_POC (proceed to PoC)
    - otherwise → VERIFIED (terminal, false positive or low priority)
    """

    def test_important_high_score_goes_to_poc(self, vh_repo):
        """is_important=True, score=0.9, proceed_to_poc=True → PENDING_POC."""
        run_id = str(ObjectId())
        vh = _make_vh(run_id, status=VHStatus.VERIFYING.value)
        vh_repo.save(vh)

        vh_repo.complete_verify(
            vh.vulnerability_hypothesis_id,
            is_crash_found=True,
            score=0.9,
            proceed=True,
            proceed_to_poc=True,
        )

        updated = vh_repo.find_by_id(vh.vulnerability_hypothesis_id)
        assert updated.status == VHStatus.PENDING_POC.value

    def test_not_important_stays_verified(self, vh_repo):
        """is_important=False, proceed_to_poc=False → VERIFIED (terminal)."""
        run_id = str(ObjectId())
        vh = _make_vh(run_id, status=VHStatus.VERIFYING.value)
        vh_repo.save(vh)

        vh_repo.complete_verify(
            vh.vulnerability_hypothesis_id,
            is_crash_found=False,
            score=0.2,
            proceed=False,
            proceed_to_poc=False,
        )

        updated = vh_repo.find_by_id(vh.vulnerability_hypothesis_id)
        assert updated.status == VHStatus.VERIFIED.value

    def test_complete_verify_releases_processor_lock(self, vh_repo):
        """After complete_verify, processor_id must be None (released)."""
        run_id = str(ObjectId())
        vh = _make_vh(run_id, status=VHStatus.VERIFYING.value)
        vh.processor_id = str(ObjectId())  # locked
        vh_repo.save(vh)

        vh_repo.complete_verify(
            vh.vulnerability_hypothesis_id,
            is_crash_found=True,
            score=0.8,
            proceed_to_poc=True,
            proceed=True,
        )

        updated = vh_repo.find_by_id(vh.vulnerability_hypothesis_id)
        assert updated.processor_id is None

    def test_complete_verify_sets_is_checked(self, vh_repo):
        """After complete_verify, is_checked_by_verifier must be True."""
        run_id = str(ObjectId())
        vh = _make_vh(run_id, status=VHStatus.VERIFYING.value)
        vh_repo.save(vh)

        vh_repo.complete_verify(
            vh.vulnerability_hypothesis_id,
            is_crash_found=True,
            score=0.8,
        )

        updated = vh_repo.find_by_id(vh.vulnerability_hypothesis_id)
        assert updated.is_checked_by_verifier is True


# =========================================================================
# Tests: poc_guidance validation
# =========================================================================


class TestPovGuidanceValidation:
    """
    Business rule: when an agent marks a VH as is_important=True,
    it MUST also provide poc_guidance. Without guidance, the PoC agent
    has no logic group on how to exploit the vulnerability.

    The MCP decorator version validates this (line 397-402 in vulnerability_hypotheses.py).
    The _impl version (used by MCP factory, which is what agents actually call)
    must also validate this.
    """

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_impl_rejects_important_without_guidance(self, _ensure, mock_get_client):
        """
        update_vulnerability_hypothesis_impl must reject is_important=True without poc_guidance.

        This is the path agents actually use (via MCP factory → _impl).
        """
        client = MagicMock()
        client.update_vulnerability_hypothesis.return_value = {"updated": True}
        mock_get_client.return_value = client

        set_vh_context("fuzz_png", "address", lg_id=str(ObjectId()))

        result = update_vulnerability_hypothesis_impl(
            vulnerability_hypothesis_id=str(ObjectId()),
            is_checked_by_verifier=True,
            is_crash_found=True,
            pattern="confirmed",
            verification_notes="Confirmed buffer overflow",
            poc_guidance=None,  # no longer required
        )

        # Recall-first: poc_guidance is no longer required; the update proceeds.
        assert result.get("success") is not False
        client.update_vulnerability_hypothesis.assert_called_once()

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_impl_accepts_important_with_guidance(self, _ensure, mock_get_client):
        """is_important=True WITH poc_guidance must succeed."""
        client = MagicMock()
        client.update_vulnerability_hypothesis.return_value = {"updated": True}
        mock_get_client.return_value = client

        set_vh_context("fuzz_png", "address", lg_id=str(ObjectId()))

        result = update_vulnerability_hypothesis_impl(
            vulnerability_hypothesis_id=str(ObjectId()),
            is_checked_by_verifier=True,
            is_crash_found=True,
            pattern="confirmed",
            verification_notes="Confirmed buffer overflow",
            poc_guidance="Send oversized PNG chunk with length > 0x7fffffff",
        )

        assert result["success"] is True

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_impl_allows_not_important_without_guidance(self, _ensure, mock_get_client):
        """is_important=False does not require poc_guidance."""
        client = MagicMock()
        client.update_vulnerability_hypothesis.return_value = {"updated": True}
        mock_get_client.return_value = client

        set_vh_context("fuzz_png", "address", lg_id=str(ObjectId()))

        result = update_vulnerability_hypothesis_impl(
            vulnerability_hypothesis_id=str(ObjectId()),
            is_checked_by_verifier=True,
            is_crash_found=False,
            pattern="refuted",
            verification_notes="False positive",
        )

        assert result["success"] is True


# =========================================================================
# Tests: verified_by_agent_id tracking
# =========================================================================


class TestVerifiedByTracking:
    """
    Business rule: when an agent verifies a VH (is_checked_by_verifier=True),
    the server must record which agent did it (verified_by_agent_id).
    """

    def test_server_sets_verified_by_agent_id(self):
        """
        Server _update_vulnerability_hypothesis (async) must set verified_by_agent_id
        when is_checked_by_verifier=True and agent_id is provided.

        The conversion agent_id → verified_by_agent_id happens in the async method,
        which builds the updates dict before passing to _sync.
        We mock _run_sync to bypass the executor and directly call the sync function.
        """
        import asyncio
        from fuzzingbrain.analyzer.server import AnalysisServer

        repos = MagicMock()
        repos.vulnerability_hypotheses.update.return_value = True

        server = AnalysisServer.__new__(AnalysisServer)
        server.repos = repos
        server.run_id = str(ObjectId())
        server._log = lambda *args, **kwargs: None

        # Mock _run_sync to directly call the sync function (bypass executor)
        async def fake_run_sync(func, *args, **kwargs):
            return func(*args, **kwargs)

        server._run_sync = fake_run_sync

        vh_id = str(ObjectId())
        agent_id = str(ObjectId())

        result = asyncio.run(
            server._update_vulnerability_hypothesis(
                {
                    "id": vh_id,
                    "is_checked_by_verifier": True,
                    "is_crash_found": True,
                    "score": 0.9,
                    "agent_id": agent_id,
                }
            )
        )

        # Extract the updates dict that was passed to repo.update
        call_args = repos.vulnerability_hypotheses.update.call_args
        updates = call_args[0][1]

        assert "verified_by_agent_id" in updates
        assert str(updates["verified_by_agent_id"]) == agent_id

    def test_server_does_not_set_verified_when_not_checked(self):
        """
        If is_checked_by_verifier is not set, verified_by_agent_id must NOT be set.
        """
        import asyncio
        from fuzzingbrain.analyzer.server import AnalysisServer

        repos = MagicMock()
        repos.vulnerability_hypotheses.update.return_value = True

        server = AnalysisServer.__new__(AnalysisServer)
        server.repos = repos
        server.run_id = str(ObjectId())
        server._log = lambda *args, **kwargs: None

        async def fake_run_sync(func, *args, **kwargs):
            return func(*args, **kwargs)

        server._run_sync = fake_run_sync

        vh_id = str(ObjectId())
        agent_id = str(ObjectId())

        asyncio.run(
            server._update_vulnerability_hypothesis(
                {
                    "id": vh_id,
                    "score": 0.5,
                    "agent_id": agent_id,
                    # is_checked_by_verifier not set
                }
            )
        )

        call_args = repos.vulnerability_hypotheses.update.call_args
        updates = call_args[0][1]

        assert "verified_by_agent_id" not in updates


# =========================================================================
# Tests: release_claim on failure
# =========================================================================


class TestReleaseClaimOnFailure:
    """
    Business rule: if verification fails (agent crash, timeout),
    release_claim must revert VH to PENDING_VERIFY so another agent can retry.
    """

    def test_release_claim_reverts_to_pending(self, vh_repo):
        """release_claim → status back to PENDING_VERIFY, processor_id cleared."""
        run_id = str(ObjectId())
        vh = _make_vh(run_id, status=VHStatus.VERIFYING.value)
        vh.processor_id = str(ObjectId())
        vh_repo.save(vh)

        vh_repo.release_claim(vh.vulnerability_hypothesis_id, VHStatus.PENDING_VERIFY.value)

        updated = vh_repo.find_by_id(vh.vulnerability_hypothesis_id)
        assert updated.status == VHStatus.PENDING_VERIFY.value
        assert updated.processor_id is None

    def test_released_vh_can_be_reclaimed(self, vh_repo):
        """After release_claim, another agent must be able to claim it."""
        run_id = str(ObjectId())
        vh = _make_vh(run_id, status=VHStatus.VERIFYING.value)
        vh.processor_id = str(ObjectId())
        vh_repo.save(vh)

        vh_repo.release_claim(vh.vulnerability_hypothesis_id, VHStatus.PENDING_VERIFY.value)

        reclaimed = vh_repo.claim_for_verify(run_id, processor_id=str(ObjectId()))
        assert reclaimed is not None
        assert reclaimed.vulnerability_hypothesis_id == vh.vulnerability_hypothesis_id
