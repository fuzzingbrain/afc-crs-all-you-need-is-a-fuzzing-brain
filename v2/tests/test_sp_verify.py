"""
SP Verification Tests

Tests the verify flow: claim_for_verify → SPVerifier updates → complete_verify → status routing.

Business invariants under test:
1. claim_for_verify atomically transitions PENDING_VERIFY → VERIFYING
2. complete_verify routes: is_important + score >= threshold → PENDING_POV, else VERIFIED
3. pov_guidance is REQUIRED when is_important=True (even via _impl path)
4. verified_by_agent_id is set when agent calls update with is_checked=True
5. claim priority: is_important DESC, score DESC, created_at ASC
6. complete_verify releases processor_id (lock)
"""

import mongomock
import pytest
from unittest.mock import patch, MagicMock

from bson import ObjectId

from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint, SPStatus
from fuzzingbrain.db.repository import SuspiciousPointRepository
from fuzzingbrain.tools.suspicious_points import (
    update_suspicious_point_impl,
    set_sp_context,
)


# =========================================================================
# Helpers
# =========================================================================


def _make_sp(task_id, function_name="parse_chunk", score=0.7, status=None):
    """Create an SP for testing."""
    sp = SuspiciousPoint(
        task_id=task_id,
        function_name=function_name,
        description=f"potential overflow in {function_name}",
        vuln_type="buffer-overflow",
        score=score,
        sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
    )
    if status:
        sp.status = status
    return sp


@pytest.fixture
def sp_repo():
    """SuspiciousPointRepository backed by mongomock."""
    client = mongomock.MongoClient()
    db = client["test_fuzzingbrain"]
    return SuspiciousPointRepository(db)


# =========================================================================
# Tests: claim_for_verify
# =========================================================================


class TestClaimForVerify:
    """
    Business rule: claim_for_verify atomically transitions SP from
    PENDING_VERIFY → VERIFYING and sets processor_id.
    """

    def test_claim_transitions_to_verifying(self, sp_repo):
        """Claimed SP must have status=VERIFYING."""
        task_id = str(ObjectId())
        sp = _make_sp(task_id)
        sp_repo.save(sp)

        claimed = sp_repo.claim_for_verify(task_id, processor_id=str(ObjectId()))

        assert claimed is not None
        assert claimed.status == SPStatus.VERIFYING.value

    def test_claim_sets_processor_id(self, sp_repo):
        """Claimed SP must have processor_id set to the claiming agent."""
        task_id = str(ObjectId())
        agent_id = str(ObjectId())
        sp = _make_sp(task_id)
        sp_repo.save(sp)

        claimed = sp_repo.claim_for_verify(task_id, processor_id=agent_id)

        assert claimed.processor_id == agent_id

    def test_already_claimed_not_double_claimed(self, sp_repo):
        """Once claimed (VERIFYING), a second claim must return None."""
        task_id = str(ObjectId())
        sp = _make_sp(task_id)
        sp_repo.save(sp)

        first = sp_repo.claim_for_verify(task_id, processor_id=str(ObjectId()))
        second = sp_repo.claim_for_verify(task_id, processor_id=str(ObjectId()))

        assert first is not None
        assert second is None

    def test_claim_priority_important_first(self, sp_repo):
        """is_important=True SP must be claimed before is_important=False."""
        task_id = str(ObjectId())

        normal = _make_sp(task_id, function_name="normal", score=0.9)
        important = _make_sp(task_id, function_name="important", score=0.3)
        important.is_important = True

        sp_repo.save(normal)
        sp_repo.save(important)

        claimed = sp_repo.claim_for_verify(task_id, processor_id=str(ObjectId()))

        assert claimed.function_name == "important"

    def test_claim_priority_high_score_first(self, sp_repo):
        """Among equal importance, higher score claimed first."""
        task_id = str(ObjectId())

        low = _make_sp(task_id, function_name="low_score", score=0.3)
        high = _make_sp(task_id, function_name="high_score", score=0.9)

        sp_repo.save(low)
        sp_repo.save(high)

        claimed = sp_repo.claim_for_verify(task_id, processor_id=str(ObjectId()))

        assert claimed.function_name == "high_score"


# =========================================================================
# Tests: complete_verify status routing
# =========================================================================


class TestCompleteVerifyRouting:
    """
    Business rule:
    - is_important=True + score >= pov_min → PENDING_POV (proceed to POV)
    - otherwise → VERIFIED (terminal, false positive or low priority)
    """

    def test_important_high_score_goes_to_pov(self, sp_repo):
        """is_important=True, score=0.9, proceed_to_pov=True → PENDING_POV."""
        task_id = str(ObjectId())
        sp = _make_sp(task_id, status=SPStatus.VERIFYING.value)
        sp_repo.save(sp)

        sp_repo.complete_verify(
            sp.suspicious_point_id,
            is_real=True,
            score=0.9,
            is_important=True,
            proceed_to_pov=True,
        )

        updated = sp_repo.find_by_id(sp.suspicious_point_id)
        assert updated.status == SPStatus.PENDING_POV.value

    def test_not_important_stays_verified(self, sp_repo):
        """is_important=False, proceed_to_pov=False → VERIFIED (terminal)."""
        task_id = str(ObjectId())
        sp = _make_sp(task_id, status=SPStatus.VERIFYING.value)
        sp_repo.save(sp)

        sp_repo.complete_verify(
            sp.suspicious_point_id,
            is_real=False,
            score=0.2,
            is_important=False,
            proceed_to_pov=False,
        )

        updated = sp_repo.find_by_id(sp.suspicious_point_id)
        assert updated.status == SPStatus.VERIFIED.value

    def test_complete_verify_releases_processor_lock(self, sp_repo):
        """After complete_verify, processor_id must be None (released)."""
        task_id = str(ObjectId())
        sp = _make_sp(task_id, status=SPStatus.VERIFYING.value)
        sp.processor_id = str(ObjectId())  # locked
        sp_repo.save(sp)

        sp_repo.complete_verify(
            sp.suspicious_point_id,
            is_real=True,
            score=0.8,
            proceed_to_pov=True,
            is_important=True,
        )

        updated = sp_repo.find_by_id(sp.suspicious_point_id)
        assert updated.processor_id is None

    def test_complete_verify_sets_is_checked(self, sp_repo):
        """After complete_verify, is_checked must be True."""
        task_id = str(ObjectId())
        sp = _make_sp(task_id, status=SPStatus.VERIFYING.value)
        sp_repo.save(sp)

        sp_repo.complete_verify(
            sp.suspicious_point_id,
            is_real=True,
            score=0.8,
        )

        updated = sp_repo.find_by_id(sp.suspicious_point_id)
        assert updated.is_checked is True


# =========================================================================
# Tests: pov_guidance validation
# =========================================================================


class TestPovGuidanceValidation:
    """
    Business rule: when an agent marks a SP as is_important=True,
    it MUST also provide pov_guidance. Without guidance, the POV agent
    has no direction on how to exploit the vulnerability.

    The MCP decorator version validates this (line 397-402 in suspicious_points.py).
    The _impl version (used by MCP factory, which is what agents actually call)
    must also validate this.
    """

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_impl_rejects_important_without_guidance(self, _ensure, mock_get_client):
        """
        update_suspicious_point_impl must reject is_important=True without pov_guidance.

        This is the path agents actually use (via MCP factory → _impl).
        """
        client = MagicMock()
        client.update_suspicious_point.return_value = {"updated": True}
        mock_get_client.return_value = client

        set_sp_context("fuzz_png", "address", direction_id=str(ObjectId()))

        result = update_suspicious_point_impl(
            suspicious_point_id=str(ObjectId()),
            is_checked=True,
            is_real=True,
            is_important=True,
            score=0.95,
            verification_notes="Confirmed buffer overflow",
            pov_guidance=None,  # Missing!
        )

        assert result["success"] is False, (
            "update_suspicious_point_impl must reject is_important=True without pov_guidance. "
            "The MCP decorator version validates this but _impl (used by factory) does not."
        )
        client.update_suspicious_point.assert_not_called()

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_impl_accepts_important_with_guidance(self, _ensure, mock_get_client):
        """is_important=True WITH pov_guidance must succeed."""
        client = MagicMock()
        client.update_suspicious_point.return_value = {"updated": True}
        mock_get_client.return_value = client

        set_sp_context("fuzz_png", "address", direction_id=str(ObjectId()))

        result = update_suspicious_point_impl(
            suspicious_point_id=str(ObjectId()),
            is_checked=True,
            is_real=True,
            is_important=True,
            score=0.95,
            verification_notes="Confirmed buffer overflow",
            pov_guidance="Send oversized PNG chunk with length > 0x7fffffff",
        )

        assert result["success"] is True

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_impl_allows_not_important_without_guidance(self, _ensure, mock_get_client):
        """is_important=False does not require pov_guidance."""
        client = MagicMock()
        client.update_suspicious_point.return_value = {"updated": True}
        mock_get_client.return_value = client

        set_sp_context("fuzz_png", "address", direction_id=str(ObjectId()))

        result = update_suspicious_point_impl(
            suspicious_point_id=str(ObjectId()),
            is_checked=True,
            is_real=False,
            is_important=False,
            score=0.2,
            verification_notes="False positive",
        )

        assert result["success"] is True


# =========================================================================
# Tests: verified_by_agent_id tracking
# =========================================================================


class TestVerifiedByTracking:
    """
    Business rule: when an agent verifies an SP (is_checked=True),
    the server must record which agent did it (verified_by_agent_id).
    """

    def test_server_sets_verified_by_agent_id(self):
        """
        Server _update_suspicious_point (async) must set verified_by_agent_id
        when is_checked=True and agent_id is provided.

        The conversion agent_id → verified_by_agent_id happens in the async method,
        which builds the updates dict before passing to _sync.
        We mock _run_sync to bypass the executor and directly call the sync function.
        """
        import asyncio
        from fuzzingbrain.analyzer.server import AnalysisServer

        repos = MagicMock()
        repos.suspicious_points.update.return_value = True

        server = AnalysisServer.__new__(AnalysisServer)
        server.repos = repos
        server.task_id = str(ObjectId())
        server._log = lambda *args, **kwargs: None

        # Mock _run_sync to directly call the sync function (bypass executor)
        async def fake_run_sync(func, *args, **kwargs):
            return func(*args, **kwargs)
        server._run_sync = fake_run_sync

        sp_id = str(ObjectId())
        agent_id = str(ObjectId())

        result = asyncio.run(
            server._update_suspicious_point(
                {
                    "id": sp_id,
                    "is_checked": True,
                    "is_real": True,
                    "score": 0.9,
                    "agent_id": agent_id,
                }
            )
        )

        # Extract the updates dict that was passed to repo.update
        call_args = repos.suspicious_points.update.call_args
        updates = call_args[0][1]

        assert "verified_by_agent_id" in updates
        assert str(updates["verified_by_agent_id"]) == agent_id

    def test_server_does_not_set_verified_when_not_checked(self):
        """
        If is_checked is not set, verified_by_agent_id must NOT be set.
        """
        import asyncio
        from fuzzingbrain.analyzer.server import AnalysisServer

        repos = MagicMock()
        repos.suspicious_points.update.return_value = True

        server = AnalysisServer.__new__(AnalysisServer)
        server.repos = repos
        server.task_id = str(ObjectId())
        server._log = lambda *args, **kwargs: None

        async def fake_run_sync(func, *args, **kwargs):
            return func(*args, **kwargs)
        server._run_sync = fake_run_sync

        sp_id = str(ObjectId())
        agent_id = str(ObjectId())

        asyncio.run(
            server._update_suspicious_point(
                {
                    "id": sp_id,
                    "score": 0.5,
                    "agent_id": agent_id,
                    # is_checked not set
                }
            )
        )

        call_args = repos.suspicious_points.update.call_args
        updates = call_args[0][1]

        assert "verified_by_agent_id" not in updates


# =========================================================================
# Tests: release_claim on failure
# =========================================================================


class TestReleaseClaimOnFailure:
    """
    Business rule: if verification fails (agent crash, timeout),
    release_claim must revert SP to PENDING_VERIFY so another agent can retry.
    """

    def test_release_claim_reverts_to_pending(self, sp_repo):
        """release_claim → status back to PENDING_VERIFY, processor_id cleared."""
        task_id = str(ObjectId())
        sp = _make_sp(task_id, status=SPStatus.VERIFYING.value)
        sp.processor_id = str(ObjectId())
        sp_repo.save(sp)

        sp_repo.release_claim(sp.suspicious_point_id, SPStatus.PENDING_VERIFY.value)

        updated = sp_repo.find_by_id(sp.suspicious_point_id)
        assert updated.status == SPStatus.PENDING_VERIFY.value
        assert updated.processor_id is None

    def test_released_sp_can_be_reclaimed(self, sp_repo):
        """After release_claim, another agent must be able to claim it."""
        task_id = str(ObjectId())
        sp = _make_sp(task_id, status=SPStatus.VERIFYING.value)
        sp.processor_id = str(ObjectId())
        sp_repo.save(sp)

        sp_repo.release_claim(sp.suspicious_point_id, SPStatus.PENDING_VERIFY.value)

        reclaimed = sp_repo.claim_for_verify(task_id, processor_id=str(ObjectId()))
        assert reclaimed is not None
        assert reclaimed.suspicious_point_id == sp.suspicious_point_id
