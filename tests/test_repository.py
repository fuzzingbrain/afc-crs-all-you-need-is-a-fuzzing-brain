# SPDX-License-Identifier: Apache-2.0
"""
Repository CRUD tests with mongomock.

Tests are organized by BUSINESS SCENARIOS, not by repository methods.
Each test exercises a real production workflow or edge case that could
break and cause actual damage.
"""

from bson import ObjectId

from fuzzingbrain.core.models import (
    Run,
    RunStatus,
    POC,
    Patch,
    VulnerabilityHypothesis,
    VHStatus,
    LogicGroup,
    LogicGroupStatus,
    RiskLevel,
    Worker,
    WorkerStatus,
    Fuzzer,
    FuzzerStatus,
    Function,
    CallGraphNode,
)
from fuzzingbrain.core.utils import generate_id


# =========================================================================
# Run Lifecycle
# =========================================================================


class TestRunLifecycle:
    """Run goes pending → running → collects POCs/patches → completed."""

    def test_run_accumulates_pocs_and_patches(self, repos):
        """As workers find PoCs and patches, they accumulate on the run."""
        run = Run(project_name="openssl")
        repos.runs.save(run)
        repos.runs.update_status(run.run_id, "running")

        poc1, poc2, patch1 = generate_id(), generate_id(), generate_id()
        repos.runs.add_poc(run.run_id, poc1)
        repos.runs.add_poc(run.run_id, poc2)
        repos.runs.add_patch(run.run_id, patch1)

        found = repos.runs.find_by_id(run.run_id)
        assert found.status == RunStatus.RUNNING
        assert len(found.poc_ids) == 2
        assert len(found.patch_ids) == 1
        assert poc1 in found.poc_ids
        assert poc2 in found.poc_ids

    def test_find_by_status_only_returns_matching(self, repos):
        """Dispatcher queries pending runs to launch them."""
        pending = Run(project_name="proj1", status=RunStatus.PENDING)
        running = Run(project_name="proj2", status=RunStatus.RUNNING)
        done = Run(project_name="proj3", status=RunStatus.COMPLETED)
        for t in [pending, running, done]:
            repos.runs.save(t)

        result = repos.runs.find_by_status("pending")
        assert len(result) == 1
        assert result[0].project_name == "proj1"

    def test_find_by_project_isolates_runs(self, repos):
        """Multiple runs for different projects don't cross-contaminate."""
        t1 = Run(project_name="openssl")
        t2 = Run(project_name="curl")
        for t in [t1, t2]:
            repos.runs.save(t)

        found = repos.runs.find_by_project("openssl")
        assert len(found) == 1
        assert found[0].run_id == t1.run_id

    def test_save_is_idempotent_upsert(self, repos):
        """Saving the same run twice doesn't create duplicates."""
        run = Run(project_name="test")
        repos.runs.save(run)
        run.project_name = "updated"
        repos.runs.save(run)

        assert repos.runs.count() == 1
        found = repos.runs.find_by_id(run.run_id)
        assert found.project_name == "updated"

    def test_delete_cleans_up_run(self, repos):
        run = Run()
        repos.runs.save(run)
        assert repos.runs.delete(run.run_id)
        assert repos.runs.find_by_id(run.run_id) is None


# =========================================================================
# VH Pipeline: The Core Business Flow
#
# Real flow: pending_verify → [claim] → verifying → [complete_verify] →
#   verified (false positive) OR pending_poc → [claim_for_poc] →
#   generating_poc → [complete_poc] → poc_generated / failed
# =========================================================================


class TestVHPipelineLifecycle:
    """End-to-end vulnerability hypothesis pipeline tests."""

    def _make_vh(self, run_id, **kwargs):
        defaults = dict(
            run_id=run_id,
            function_name="vuln_func",
            lg_id=generate_id(),
            description="heap-buffer-overflow in vuln_func",
            sources=[{"harness_name": "fuzz1", "sanitizer": "address"}],
        )
        defaults.update(kwargs)
        return VulnerabilityHypothesis(**defaults)

    def test_full_pipeline_verify_to_poc_success(self, repos):
        """VH flows through entire pipeline: create → verify → PoC success."""
        run_id = generate_id()
        vh = self._make_vh(run_id, score=0.8)
        repos.vulnerability_hypotheses.save(vh)

        # Step 1: Verifier agent claims
        claimed = repos.vulnerability_hypotheses.claim_for_verify(run_id, "verifier_1")
        assert claimed.vulnerability_hypothesis_id == vh.vulnerability_hypothesis_id
        assert claimed.status == VHStatus.VERIFYING.value

        # Step 2: Verifier confirms real, sends to PoC stage
        repos.vulnerability_hypotheses.complete_verify(
            vh.vulnerability_hypothesis_id,
            is_crash_found=True,
            score=0.95,
            notes="confirmed via manual analysis",
            proceed_to_poc=True,
        )
        found = repos.vulnerability_hypotheses.find_by_id(vh.vulnerability_hypothesis_id)
        assert found.status == VHStatus.PENDING_POC.value
        assert found.is_checked_by_verifier is True
        assert found.is_crash_found is True
        assert found.score == 0.95

        # Step 3: PoC worker claims
        poc_claimed = repos.vulnerability_hypotheses.claim_for_poc(
            run_id,
            "poc_worker_1",
            harness_name="fuzz1",
            sanitizer="address",
        )
        assert poc_claimed is not None
        assert poc_claimed.status == VHStatus.GENERATING_POC.value

        # Step 4: PoC worker succeeds
        poc_id = generate_id()
        result = repos.vulnerability_hypotheses.complete_poc(
            vh.vulnerability_hypothesis_id,
            poc_id=poc_id,
            success=True,
            harness_name="fuzz1",
            sanitizer="address",
        )
        assert result is True

        # Final state check
        final = repos.vulnerability_hypotheses.find_by_id(vh.vulnerability_hypothesis_id)
        assert final.status == VHStatus.POC_GENERATED.value
        assert final.poc_id == poc_id
        assert final.poc_success_by["harness_name"] == "fuzz1"

    def test_verify_false_positive_stays_terminal(self, repos):
        """VH verified as false positive → VERIFIED (terminal), not in PoC pipeline."""
        run_id = generate_id()
        vh = self._make_vh(run_id, score=0.4)
        repos.vulnerability_hypotheses.save(vh)

        repos.vulnerability_hypotheses.claim_for_verify(run_id, "verifier_1")
        repos.vulnerability_hypotheses.complete_verify(
            vh.vulnerability_hypothesis_id,
            is_crash_found=False,
            score=0.1,
            proceed_to_poc=False,
        )

        found = repos.vulnerability_hypotheses.find_by_id(vh.vulnerability_hypothesis_id)
        assert found.status == VHStatus.VERIFIED.value
        assert found.is_crash_found is False

        # Pipeline should consider this VH done
        assert repos.vulnerability_hypotheses.is_pipeline_complete(run_id) is True

    def test_all_workers_fail_poc_marks_failed(self, repos):
        """When every source worker fails PoC, VH transitions to FAILED."""
        run_id = generate_id()
        vh = self._make_vh(
            run_id,
            status=VHStatus.PENDING_POC.value,
            score=0.8,
            sources=[
                {"harness_name": "fuzzA", "sanitizer": "address"},
                {"harness_name": "fuzzB", "sanitizer": "address"},
            ],
        )
        repos.vulnerability_hypotheses.save(vh)

        # Worker A claims and fails
        repos.vulnerability_hypotheses.claim_for_poc(
            run_id, "wA", harness_name="fuzzA", sanitizer="address"
        )
        repos.vulnerability_hypotheses.complete_poc(
            vh.vulnerability_hypothesis_id,
            success=False,
            harness_name="fuzzA",
            sanitizer="address",
        )

        # VH should not be failed yet — worker B hasn't tried
        mid = repos.vulnerability_hypotheses.find_by_id(vh.vulnerability_hypothesis_id)
        assert mid.status != VHStatus.FAILED.value

        # Worker B claims and fails
        repos.vulnerability_hypotheses.claim_for_poc(
            run_id, "wB", harness_name="fuzzB", sanitizer="address"
        )
        repos.vulnerability_hypotheses.complete_poc(
            vh.vulnerability_hypothesis_id,
            success=False,
            harness_name="fuzzB",
            sanitizer="address",
        )

        # Now ALL sources have tried and failed → FAILED
        final = repos.vulnerability_hypotheses.find_by_id(vh.vulnerability_hypothesis_id)
        assert final.status == VHStatus.FAILED.value

    def test_release_claim_on_verifier_crash(self, repos):
        """If a verifier crashes, release_claim reverts VH so another agent can retry."""
        run_id = generate_id()
        vh = self._make_vh(run_id, score=0.7)
        repos.vulnerability_hypotheses.save(vh)

        # Agent claims
        claimed = repos.vulnerability_hypotheses.claim_for_verify(run_id, "agent_1")
        assert claimed.status == VHStatus.VERIFYING.value

        # Agent crashes → release with revert
        repos.vulnerability_hypotheses.release_claim(
            vh.vulnerability_hypothesis_id, revert_status=VHStatus.PENDING_VERIFY.value
        )

        found = repos.vulnerability_hypotheses.find_by_id(vh.vulnerability_hypothesis_id)
        assert found.status == VHStatus.PENDING_VERIFY.value

        # Another agent can now claim it
        reclaimed = repos.vulnerability_hypotheses.claim_for_verify(run_id, "agent_2")
        assert reclaimed is not None
        assert reclaimed.vulnerability_hypothesis_id == vh.vulnerability_hypothesis_id


class TestVHClaimScheduling:
    """VH claim priority and exclusion logic."""

    def _make_vh(self, run_id, **kwargs):
        defaults = dict(
            run_id=run_id,
            function_name="vuln_func",
            lg_id=generate_id(),
            description="overflow",
            sources=[{"harness_name": "fuzz1", "sanitizer": "address"}],
        )
        defaults.update(kwargs)
        return VulnerabilityHypothesis(**defaults)

    def test_claim_verify_respects_priority(self, repos):
        """Important VHs claimed before high-score, high-score before low."""
        run_id = generate_id()
        low = self._make_vh(run_id, score=0.3, priority=0.0)
        high = self._make_vh(run_id, score=0.9, priority=0.0)
        important = self._make_vh(run_id, score=0.5, priority=1.0)
        for vh in [low, high, important]:
            repos.vulnerability_hypotheses.save(vh)

        c1 = repos.vulnerability_hypotheses.claim_for_verify(run_id, "a1")
        assert c1.vulnerability_hypothesis_id == important.vulnerability_hypothesis_id

        c2 = repos.vulnerability_hypotheses.claim_for_verify(run_id, "a2")
        assert c2.vulnerability_hypothesis_id == high.vulnerability_hypothesis_id

        c3 = repos.vulnerability_hypotheses.claim_for_verify(run_id, "a3")
        assert c3.vulnerability_hypothesis_id == low.vulnerability_hypothesis_id

        # Nothing left
        assert repos.vulnerability_hypotheses.claim_for_verify(run_id, "a4") is None

    def test_claim_poc_excludes_already_attempted(self, repos):
        """Worker that already attempted PoC on this VH cannot claim it again."""
        run_id = generate_id()
        vh = self._make_vh(
            run_id,
            status=VHStatus.PENDING_POC.value,
            score=0.8,
            sources=[
                {"harness_name": "fuzzA", "sanitizer": "address"},
                {"harness_name": "fuzzB", "sanitizer": "address"},
            ],
        )
        repos.vulnerability_hypotheses.save(vh)

        # Worker A claims
        c1 = repos.vulnerability_hypotheses.claim_for_poc(
            run_id, "wA", harness_name="fuzzA", sanitizer="address"
        )
        assert c1 is not None

        # Worker A tries again → excluded
        c2 = repos.vulnerability_hypotheses.claim_for_poc(
            run_id, "wA", harness_name="fuzzA", sanitizer="address"
        )
        assert c2 is None

        # Worker B can still claim the same VH
        c3 = repos.vulnerability_hypotheses.claim_for_poc(
            run_id, "wB", harness_name="fuzzB", sanitizer="address"
        )
        assert c3 is not None

    def test_poc_first_success_wins_race(self, repos):
        """Two workers generate PoC simultaneously — only first success recorded."""
        run_id = generate_id()
        vh = self._make_vh(
            run_id,
            status=VHStatus.GENERATING_POC.value,
            score=0.8,
            sources=[
                {"harness_name": "fuzzA", "sanitizer": "address"},
                {"harness_name": "fuzzB", "sanitizer": "address"},
            ],
        )
        repos.vulnerability_hypotheses.save(vh)

        # Worker A succeeds
        assert (
            repos.vulnerability_hypotheses.complete_poc(
                vh.vulnerability_hypothesis_id,
                poc_id=generate_id(),
                success=True,
                harness_name="fuzzA",
                sanitizer="address",
            )
            is True
        )

        # Worker B also succeeds, but too late
        assert (
            repos.vulnerability_hypotheses.complete_poc(
                vh.vulnerability_hypothesis_id,
                poc_id=generate_id(),
                success=True,
                harness_name="fuzzB",
                sanitizer="address",
            )
            is False
        )

        final = repos.vulnerability_hypotheses.find_by_id(vh.vulnerability_hypothesis_id)
        assert final.poc_success_by["harness_name"] == "fuzzA"
        assert final.status == VHStatus.POC_GENERATED.value

    def test_poc_failure_does_not_clobber_concurrent_winner(self, repos, monkeypatch):
        """A late PoC failure must not revert a VH another worker already won.

        Reproduces the read-modify-write race in complete_poc's failure path:
        the failing worker acts on a stale snapshot (poc_success_by=None, all
        contributors "attempted") taken before the winner committed. The FAILED
        write must be guarded so it cannot overwrite POC_GENERATED.
        """
        run_id = generate_id()
        vh = self._make_vh(
            run_id,
            status=VHStatus.GENERATING_POC.value,
            score=0.8,
            sources=[
                {"harness_name": "fuzzA", "sanitizer": "address"},
                {"harness_name": "fuzzB", "sanitizer": "address"},
            ],
        )
        repos.vulnerability_hypotheses.save(vh)

        # Worker B wins first: the VH is POC_GENERATED in the DB.
        repos.vulnerability_hypotheses.complete_poc(
            vh.vulnerability_hypothesis_id,
            poc_id=generate_id(),
            success=True,
            harness_name="fuzzB",
            sanitizer="address",
        )

        # Worker A still holds a pre-win snapshot: no winner yet, both attempted.
        stale = repos.vulnerability_hypotheses.find_by_id(vh.vulnerability_hypothesis_id)
        stale.poc_success_by = None
        stale.poc_attempted_by = [
            {"harness_name": "fuzzA", "sanitizer": "address"},
            {"harness_name": "fuzzB", "sanitizer": "address"},
        ]
        monkeypatch.setattr(repos.vulnerability_hypotheses, "find_by_id", lambda _id: stale)

        # A reports failure. Pre-fix this unconditionally wrote FAILED.
        repos.vulnerability_hypotheses.complete_poc(
            vh.vulnerability_hypothesis_id,
            success=False,
            harness_name="fuzzA",
            sanitizer="address",
        )

        monkeypatch.undo()
        final = repos.vulnerability_hypotheses.find_by_id(vh.vulnerability_hypothesis_id)
        assert final.status == VHStatus.POC_GENERATED.value
        assert final.poc_success_by["harness_name"] == "fuzzB"

    def test_claim_poc_respects_min_score(self, repos):
        """VHs below min_score are not claimable for PoC."""
        run_id = generate_id()
        low_score = self._make_vh(
            run_id,
            status=VHStatus.PENDING_POC.value,
            score=0.3,
        )
        repos.vulnerability_hypotheses.save(low_score)

        # Default min_score=0.5, so score 0.3 should not be claimable
        claimed = repos.vulnerability_hypotheses.claim_for_poc(
            run_id,
            "w1",
            harness_name="fuzz1",
            sanitizer="address",
        )
        assert claimed is None

        # But with lower threshold, it should be claimable
        claimed2 = repos.vulnerability_hypotheses.claim_for_poc(
            run_id,
            "w1",
            min_score=0.2,
            harness_name="fuzz1",
            sanitizer="address",
        )
        assert claimed2 is not None


class TestVHSourceMerging:
    """When multiple fuzzers find the same VH, sources merge via $addToSet."""

    def test_same_source_not_duplicated(self, repos):
        """$addToSet prevents duplicate harness/sanitizer pairs."""
        run_id = generate_id()
        vh = VulnerabilityHypothesis(
            run_id=run_id,
            function_name="f",
            lg_id=generate_id(),
            description="d",
            sources=[],
        )
        repos.vulnerability_hypotheses.save(vh)

        repos.vulnerability_hypotheses.add_source(vh.vulnerability_hypothesis_id, "fuzz1", "address")
        repos.vulnerability_hypotheses.add_source(vh.vulnerability_hypothesis_id, "fuzz1", "address")
        repos.vulnerability_hypotheses.add_source(vh.vulnerability_hypothesis_id, "fuzz2", "address")

        found = repos.vulnerability_hypotheses.find_by_id(vh.vulnerability_hypothesis_id)
        assert len(found.sources) == 2  # fuzz1/addr + fuzz2/addr, not 3

    def test_merged_duplicate_records_original_info(self, repos):
        """When deduplicating VHs, the duplicate's metadata is preserved."""
        run_id = generate_id()
        primary = VulnerabilityHypothesis(
            run_id=run_id,
            function_name="f",
            lg_id=generate_id(),
            description="primary desc",
            sources=[{"harness_name": "fuzz1", "sanitizer": "address"}],
        )
        repos.vulnerability_hypotheses.save(primary)

        # Duplicate found by fuzz2 gets merged into primary
        repos.vulnerability_hypotheses.add_merged_duplicate(
            primary.vulnerability_hypothesis_id,
            description="duplicate desc from fuzz2",
            harness_name="fuzz2",
            sanitizer="address",
            score=0.7,
        )

        found = repos.vulnerability_hypotheses.find_by_id(primary.vulnerability_hypothesis_id)
        assert len(found.merged_duplicates) == 1
        assert found.merged_duplicates[0]["description"] == "duplicate desc from fuzz2"
        assert found.merged_duplicates[0]["harness_name"] == "fuzz2"


class TestVHPipelineCompletion:
    """Pipeline completion checks drive the worker termination decision."""

    def _make_vh(self, run_id, **kwargs):
        defaults = dict(
            run_id=run_id,
            function_name="f",
            lg_id=generate_id(),
            description="d",
            sources=[{"harness_name": "fuzz1", "sanitizer": "address"}],
        )
        defaults.update(kwargs)
        return VulnerabilityHypothesis(**defaults)

    def test_terminal_states_mean_complete(self, repos):
        """Pipeline is complete when all VHs are in terminal states."""
        run_id = generate_id()
        repos.vulnerability_hypotheses.save(
            self._make_vh(run_id, status=VHStatus.POC_GENERATED.value)
        )
        repos.vulnerability_hypotheses.save(
            self._make_vh(run_id, status=VHStatus.FAILED.value)
        )
        repos.vulnerability_hypotheses.save(
            self._make_vh(run_id, status=VHStatus.VERIFIED.value)
        )
        repos.vulnerability_hypotheses.save(
            self._make_vh(run_id, status=VHStatus.SKIPPED.value)
        )
        assert repos.vulnerability_hypotheses.is_pipeline_complete(run_id) is True

    def test_pending_vh_blocks_completion(self, repos):
        """One pending_verify VH means pipeline is NOT complete."""
        run_id = generate_id()
        repos.vulnerability_hypotheses.save(
            self._make_vh(run_id, status=VHStatus.POC_GENERATED.value)
        )
        repos.vulnerability_hypotheses.save(
            self._make_vh(run_id, status=VHStatus.PENDING_VERIFY.value)
        )
        assert repos.vulnerability_hypotheses.is_pipeline_complete(run_id) is False

    def test_worker_specific_completion(self, repos):
        """Worker checks completion for its own harness/sanitizer only."""
        run_id = generate_id()
        # VH that only fuzz1 cares about — still pending
        vh_fuzz1 = self._make_vh(
            run_id,
            status=VHStatus.PENDING_VERIFY.value,
            sources=[{"harness_name": "fuzz1", "sanitizer": "address"}],
        )
        # VH that only fuzz2 cares about — done
        vh_fuzz2 = self._make_vh(
            run_id,
            status=VHStatus.POC_GENERATED.value,
            sources=[{"harness_name": "fuzz2", "sanitizer": "address"}],
        )
        repos.vulnerability_hypotheses.save(vh_fuzz1)
        repos.vulnerability_hypotheses.save(vh_fuzz2)

        # fuzz2/address is done (its VHs are all terminal)
        assert (
            repos.vulnerability_hypotheses.is_pipeline_complete(
                run_id, harness_name="fuzz2", sanitizer="address"
            )
            is True
        )

        # fuzz1/address is NOT done (still has pending_verify)
        assert (
            repos.vulnerability_hypotheses.is_pipeline_complete(
                run_id, harness_name="fuzz1", sanitizer="address"
            )
            is False
        )

    def test_worker_specific_poc_stage_completion(self, repos):
        """Worker's PoC pipeline is complete once it has attempted all its VHs.

        The PoC-stage query checks: contributor + not succeeded + not attempted.
        After a worker attempts a PoC (even if it fails), that VH is "done"
        for that worker.
        """
        run_id = generate_id()
        vh = self._make_vh(
            run_id,
            status=VHStatus.PENDING_POC.value,
            score=0.8,
            sources=[
                {"harness_name": "fuzzA", "sanitizer": "address"},
                {"harness_name": "fuzzB", "sanitizer": "address"},
            ],
        )
        repos.vulnerability_hypotheses.save(vh)

        # fuzzA has un-attempted VHs → NOT complete
        assert (
            repos.vulnerability_hypotheses.is_pipeline_complete(
                run_id, harness_name="fuzzA", sanitizer="address"
            )
            is False
        )

        # fuzzA claims and fails
        repos.vulnerability_hypotheses.claim_for_poc(
            run_id, "wA", harness_name="fuzzA", sanitizer="address"
        )
        repos.vulnerability_hypotheses.complete_poc(
            vh.vulnerability_hypothesis_id,
            success=False,
            harness_name="fuzzA",
            sanitizer="address",
        )

        # fuzzA has now attempted its only VH → complete for fuzzA
        assert (
            repos.vulnerability_hypotheses.is_pipeline_complete(
                run_id, harness_name="fuzzA", sanitizer="address"
            )
            is True
        )

        # But fuzzB still hasn't attempted → NOT complete for fuzzB
        assert (
            repos.vulnerability_hypotheses.is_pipeline_complete(
                run_id, harness_name="fuzzB", sanitizer="address"
            )
            is False
        )

    def test_count_by_status_breakdown(self, repos):
        """Status counts drive the dashboard and scheduling decisions."""
        run_id = generate_id()
        repos.vulnerability_hypotheses.save(
            self._make_vh(run_id, is_checked_by_verifier=True, is_crash_found=True, priority=1.0)
        )
        repos.vulnerability_hypotheses.save(
            self._make_vh(run_id, is_checked_by_verifier=True, is_crash_found=False)
        )
        repos.vulnerability_hypotheses.save(self._make_vh(run_id, is_checked_by_verifier=False))

        counts = repos.vulnerability_hypotheses.count_by_status(run_id)
        assert counts["total"] == 3
        assert counts["checked"] == 2
        assert counts["unchecked"] == 1
        assert counts["real"] == 1
        assert counts["false_positive"] == 1
        assert counts["important"] == 3  # proceed-count (recall-first): all pass by default


# =========================================================================
# Logic group → VH Find Workflow
# =========================================================================


class TestLogicGroupWorkflow:
    """Logic groups represent analysis plans that agents claim and execute."""

    def _make_dir(self, run_id, **kwargs):
        defaults = dict(
            run_id=run_id,
            fuzzer="fuzz_target",
            name="check_null_deref_in_parser",
            risk_level=RiskLevel.MEDIUM.value,
        )
        defaults.update(kwargs)
        return LogicGroup(**defaults)

    def test_claim_respects_risk_priority(self, repos):
        """High-risk logic groups are claimed before low-risk."""
        run_id = generate_id()
        low = self._make_dir(
            run_id, name="low_risk_dir", risk_level=RiskLevel.LOW.value
        )
        high = self._make_dir(
            run_id, name="high_risk_dir", risk_level=RiskLevel.HIGH.value
        )
        # Save low first to prove order doesn't matter
        repos.logic_groups.save(low)
        repos.logic_groups.save(high)

        claimed = repos.logic_groups.claim(run_id, "fuzz_target", "agent_1")
        assert claimed.lg_id == high.lg_id
        assert claimed.status == LogicGroupStatus.IN_PROGRESS.value

    def test_complete_records_analysis_results(self, repos):
        """After analyzing a logic group, vh_count and functions_analyzed are recorded."""
        run_id = generate_id()
        d = self._make_dir(run_id)
        repos.logic_groups.save(d)
        repos.logic_groups.claim(run_id, "fuzz_target", "agent_1")

        repos.logic_groups.complete(d.lg_id, vh_count=7, functions_analyzed=42)
        found = repos.logic_groups.find_by_id(d.lg_id)
        assert found.status == LogicGroupStatus.COMPLETED.value
        assert found.vh_count == 7
        assert found.functions_analyzed == 42

    def test_skip_low_value_logic_group(self, repos):
        """Agent can skip a logic group deemed not worth analyzing."""
        run_id = generate_id()
        d = self._make_dir(run_id, risk_level=RiskLevel.LOW.value)
        repos.logic_groups.save(d)

        repos.logic_groups.skip(d.lg_id, reason="too simple")
        found = repos.logic_groups.find_by_id(d.lg_id)
        assert found.status == LogicGroupStatus.SKIPPED.value

    def test_release_claim_on_agent_crash(self, repos):
        """If an agent crashes, its claimed logic group returns to PENDING."""
        run_id = generate_id()
        d = self._make_dir(run_id)
        repos.logic_groups.save(d)
        repos.logic_groups.claim(run_id, "fuzz_target", "agent_1")

        repos.logic_groups.release_claim(d.lg_id)

        found = repos.logic_groups.find_by_id(d.lg_id)
        assert found.status == LogicGroupStatus.PENDING.value
        # Another agent can now claim it
        reclaimed = repos.logic_groups.claim(run_id, "fuzz_target", "agent_2")
        assert reclaimed is not None

    def test_is_all_complete_mixed_states(self, repos):
        """is_all_complete only True when no PENDING or IN_PROGRESS remain."""
        run_id = generate_id()
        d1 = self._make_dir(run_id, name="d1")
        d2 = self._make_dir(run_id, name="d2")
        d3 = self._make_dir(run_id, name="d3")
        for d in [d1, d2, d3]:
            repos.logic_groups.save(d)

        assert repos.logic_groups.is_all_complete(run_id) is False

        repos.logic_groups.complete(d1.lg_id)
        repos.logic_groups.skip(d2.lg_id)
        # d3 still pending
        assert repos.logic_groups.is_all_complete(run_id) is False

        repos.logic_groups.complete(d3.lg_id)
        assert repos.logic_groups.is_all_complete(run_id) is True

    def test_find_by_fuzzer_isolates_fuzzers(self, repos):
        """Logic groups from different fuzzers don't mix."""
        run_id = generate_id()
        d1 = self._make_dir(run_id, fuzzer="fuzz1", name="dir_for_fuzz1")
        d2 = self._make_dir(run_id, fuzzer="fuzz2", name="dir_for_fuzz2")
        repos.logic_groups.save(d1)
        repos.logic_groups.save(d2)

        found = repos.logic_groups.find_by_fuzzer(run_id, "fuzz1")
        assert len(found) == 1
        assert found[0].lg_id == d1.lg_id

    def test_delete_by_run_removes_all(self, repos):
        """Cleaning up after run cancellation."""
        run_id = generate_id()
        for i in range(3):
            repos.logic_groups.save(self._make_dir(run_id, name=f"dir_{i}"))

        deleted = repos.logic_groups.delete_by_run(run_id)
        assert deleted == 3
        assert repos.logic_groups.count({"run_id": ObjectId(run_id)}) == 0


# =========================================================================
# PoC Discovery and Reporting
# =========================================================================


class TestPOCDiscovery:
    """PoC repository serves the PoC discovery and deduplication pipeline."""

    def test_find_by_run_uses_objectid(self, repos):
        """PoCs stored with ObjectId(run_id) must be findable by string run_id."""
        run_id = generate_id()
        other_run = generate_id()
        p1 = POC(run_id=run_id, harness_name="h1")
        p2 = POC(run_id=run_id, harness_name="h2")
        p_other = POC(run_id=other_run, harness_name="h1")
        for p in [p1, p2, p_other]:
            repos.pocs.save(p)

        found = repos.pocs.find_by_run(run_id)
        assert len(found) == 2
        assert {p.poc_id for p in found} == {p1.poc_id, p2.poc_id}

    def test_successful_excludes_inactive_and_failed(self, repos):
        """Only active + successful PoCs count toward run score."""
        run_id = generate_id()
        active_success = POC(run_id=run_id, is_active=True, is_successful=True)
        active_fail = POC(run_id=run_id, is_active=True, is_successful=False)
        inactive_success = POC(run_id=run_id, is_active=False, is_successful=True)
        for p in [active_success, active_fail, inactive_success]:
            repos.pocs.save(p)

        found = repos.pocs.find_successful_by_run(run_id)
        assert len(found) == 1
        assert found[0].poc_id == active_success.poc_id

    def test_find_by_harness_for_worker_isolation(self, repos):
        """Each worker queries PoCs for its own harness."""
        run_id = generate_id()
        p1 = POC(run_id=run_id, harness_name="fuzz_target1")
        p2 = POC(run_id=run_id, harness_name="fuzz_target2")
        repos.pocs.save(p1)
        repos.pocs.save(p2)

        found = repos.pocs.find_by_harness(run_id, "fuzz_target1")
        assert len(found) == 1
        assert found[0].harness_name == "fuzz_target1"

    def test_deactivate_removes_from_active_query(self, repos):
        """Deactivated PoC no longer appears in active/successful queries."""
        run_id = generate_id()
        poc = POC(run_id=run_id, is_active=True, is_successful=True)
        repos.pocs.save(poc)

        repos.pocs.deactivate(poc.poc_id)

        assert len(repos.pocs.find_active_by_run(run_id)) == 0
        assert len(repos.pocs.find_successful_by_run(run_id)) == 0

        # But still findable by direct ID
        found = repos.pocs.find_by_id(poc.poc_id)
        assert found is not None
        assert found.is_active is False


# =========================================================================
# Patch Verification Pipeline
# =========================================================================


class TestPatchVerification:
    """Patches go through apply → compile → poc → test checks."""

    def test_only_fully_verified_patches_are_valid(self, repos):
        """find_valid_by_run requires all 4 checks to be True."""
        run_id = generate_id()
        full_pass = Patch(
            run_id=run_id,
            apply_check=True,
            compilation_check=True,
            poc_check=True,
            test_check=True,
        )
        partial_pass = Patch(
            run_id=run_id,
            apply_check=True,
            compilation_check=True,
            poc_check=True,
            test_check=False,  # test failed
        )
        repos.patches.save(full_pass)
        repos.patches.save(partial_pass)

        valid = repos.patches.find_valid_by_run(run_id)
        assert len(valid) == 1
        assert valid[0].patch_id == full_pass.patch_id

    def test_inactive_patch_excluded_from_valid(self, repos):
        """Deactivated patches are not returned even if all checks pass."""
        run_id = generate_id()
        pa = Patch(
            run_id=run_id,
            apply_check=True,
            compilation_check=True,
            poc_check=True,
            test_check=True,
            is_active=False,
        )
        repos.patches.save(pa)

        assert len(repos.patches.find_valid_by_run(run_id)) == 0

    def test_incremental_check_updates(self, repos):
        """Checks are updated incrementally as each stage completes."""
        run_id = generate_id()
        pa = Patch(run_id=run_id)
        repos.patches.save(pa)

        # Stage 1: apply check passes
        repos.patches.update_checks(pa.patch_id, apply=True)
        found = repos.patches.find_by_id(pa.patch_id)
        assert found.apply_check is True
        assert found.compilation_check is False

        # Stage 2: compile check passes
        repos.patches.update_checks(pa.patch_id, compile=True)
        found = repos.patches.find_by_id(pa.patch_id)
        assert found.apply_check is True
        assert found.compilation_check is True
        assert found.poc_check is False


# =========================================================================
# Worker Lifecycle
# =========================================================================


class TestWorkerLifecycle:
    """Workers progress: pending → building → running → completed."""

    def test_worker_state_progression_with_results(self, repos):
        """Worker goes through states and accumulates results."""
        run_id = generate_id()
        w = Worker(
            run_id=run_id, fuzzer="fuzz1", sanitizer="address", project_name="openssl"
        )
        repos.workers.save(w)

        repos.workers.update_status(w.worker_id, "running")
        repos.workers.update_strategy(w.worker_id, "fullscan")
        repos.workers.update_strategy(w.worker_id, "poc_targeted")
        repos.workers.update_results(w.worker_id, pocs=3, patches=1)

        found = repos.workers.find_by_id(w.worker_id)
        assert found.status == WorkerStatus.RUNNING
        assert found.current_strategy == "poc_targeted"
        assert found.strategy_history == ["fullscan", "poc_targeted"]
        assert found.poc_generated == 3
        assert found.patch_generated == 1

    def test_find_by_fuzzer_exact_match(self, repos):
        """find_by_fuzzer matches on run_id + fuzzer + sanitizer triple."""
        run_id = generate_id()
        w_addr = Worker(run_id=run_id, fuzzer="fuzz1", sanitizer="address")
        w_mem = Worker(run_id=run_id, fuzzer="fuzz1", sanitizer="memory")
        repos.workers.save(w_addr)
        repos.workers.save(w_mem)

        found = repos.workers.find_by_fuzzer(run_id, "fuzz1", "address")
        assert found.worker_id == w_addr.worker_id

        assert repos.workers.find_by_fuzzer(run_id, "fuzz1", "undefined") is None

    def test_find_by_run_isolates_runs(self, repos):
        """Workers from different runs don't mix."""
        tid_a = generate_id()
        tid_b = generate_id()
        w1 = Worker(run_id=tid_a, fuzzer="f1")
        w2 = Worker(run_id=tid_a, fuzzer="f2")
        w_other = Worker(run_id=tid_b, fuzzer="f1")
        for w in [w1, w2, w_other]:
            repos.workers.save(w)

        found = repos.workers.find_by_run(tid_a)
        assert len(found) == 2


# =========================================================================
# Fuzzer Build Tracking
# =========================================================================


class TestFuzzerBuild:
    """Fuzzer build status drives which fuzzers are available for analysis."""

    def test_find_successful_excludes_failed(self, repos):
        """Only fuzzers with status='success' are used for analysis."""
        run_id = generate_id()
        f_ok = Fuzzer(run_id=run_id, fuzzer_name="f1", status=FuzzerStatus.SUCCESS)
        f_fail = Fuzzer(run_id=run_id, fuzzer_name="f2", status=FuzzerStatus.FAILED)
        f_building = Fuzzer(
            run_id=run_id, fuzzer_name="f3", status=FuzzerStatus.BUILDING
        )
        for f in [f_ok, f_fail, f_building]:
            repos.fuzzers.save(f)

        found = repos.fuzzers.find_successful_by_run(run_id)
        assert len(found) == 1
        assert found[0].fuzzer_name == "f1"

    def test_find_by_name_with_objectid_run(self, repos):
        """find_by_name correctly queries with ObjectId(run_id)."""
        run_id = generate_id()
        f = Fuzzer(run_id=run_id, fuzzer_name="fuzz_target1")
        repos.fuzzers.save(f)

        found = repos.fuzzers.find_by_name(run_id, "fuzz_target1")
        assert found is not None
        assert found.fuzzer_id == f.fuzzer_id
        assert found.run_id == run_id

    def test_update_status_records_binary_path(self, repos):
        """After successful build, binary_path is stored for fuzzer execution."""
        f = Fuzzer(run_id=generate_id(), fuzzer_name="fuzz1")
        repos.fuzzers.save(f)

        repos.fuzzers.update_status(f.fuzzer_id, "success", binary_path="/out/fuzz1")
        found = repos.fuzzers.find_by_id(f.fuzzer_id)
        assert found.status == FuzzerStatus.SUCCESS
        assert found.binary_path == "/out/fuzz1"


# =========================================================================
# Function Analysis Tracking (composite string key)
# =========================================================================


class TestFunctionAnalysis:
    """Functions track which logic groups have analyzed them to avoid redundant work."""

    def test_composite_key_lookup(self, repos):
        """Function._id = '{run_id}_{name}', find_by_name constructs this key."""
        run_id = generate_id()
        fn = Function(
            run_id=run_id,
            name="vuln_func",
            file_path="src/vuln.c",
            start_line=10,
            end_line=50,
            content="void vuln_func() {}",
            reached_by_fuzzers=["fuzz1"],
        )
        repos.functions.save(fn)

        assert fn.function_id == f"{run_id}_vuln_func"
        found = repos.functions.find_by_name(run_id, "vuln_func")
        assert found is not None
        assert found.run_id == run_id
        assert found.name == "vuln_func"

    def test_analysis_priority_ordering(self, repos):
        """get_functions_for_analysis returns unanalyzed functions first.

        This drives coverage efficiency: agents analyze new functions before
        re-visiting already-analyzed ones.
        Priority: never analyzed > analyzed by other logic group > analyzed by this logic group.
        """
        run_id = generate_id()
        dir_a = generate_id()
        dir_b = generate_id()

        fn_fresh = Function(
            run_id=run_id,
            name="fresh_func",
            file_path="a.c",
            reached_by_fuzzers=["fuzz1"],
        )
        fn_other = Function(
            run_id=run_id,
            name="analyzed_by_other",
            file_path="a.c",
            reached_by_fuzzers=["fuzz1"],
            analyzed_by_logic_groups=[dir_b],
        )
        fn_done = Function(
            run_id=run_id,
            name="already_analyzed",
            file_path="a.c",
            reached_by_fuzzers=["fuzz1"],
            analyzed_by_logic_groups=[dir_a],
        )
        for fn in [fn_fresh, fn_other, fn_done]:
            repos.functions.save(fn)

        results = repos.functions.get_functions_for_analysis(run_id, "fuzz1", dir_a)
        assert len(results) == 3
        assert results[0].name == "fresh_func"
        assert results[1].name == "analyzed_by_other"
        assert results[2].name == "already_analyzed"

    def test_mark_analyzed_is_idempotent(self, repos):
        """$addToSet ensures marking the same logic group twice doesn't duplicate."""
        run_id = generate_id()
        lg_id = generate_id()
        fn = Function(
            run_id=run_id,
            name="func_a",
            file_path="a.c",
            reached_by_fuzzers=["fuzz1"],
        )
        repos.functions.save(fn)

        repos.functions.mark_analyzed_by_logic_group(fn.function_id, lg_id)
        repos.functions.mark_analyzed_by_logic_group(fn.function_id, lg_id)

        found = repos.functions.find_by_name(run_id, "func_a")
        assert len(found.analyzed_by_logic_groups) == 1

    def test_mark_many_analyzed_batch(self, repos):
        """Batch-mark multiple functions as analyzed by one logic group."""
        run_id = generate_id()
        lg_id = generate_id()
        f1 = Function(
            run_id=run_id, name="f1", file_path="a.c", reached_by_fuzzers=["fuzz1"]
        )
        f2 = Function(
            run_id=run_id, name="f2", file_path="a.c", reached_by_fuzzers=["fuzz1"]
        )
        for fn in [f1, f2]:
            repos.functions.save(fn)

        updated = repos.functions.mark_many_analyzed(
            [f1.function_id, f2.function_id],
            lg_id,
        )
        assert updated == 2

        for fn_id in [f1.function_id, f2.function_id]:
            found = repos.functions.find_by_id(fn_id)
            assert lg_id in found.analyzed_by_logic_groups

    def test_delete_by_run_cleans_up(self, repos):
        """When a run is re-run, old function data is cleaned out."""
        run_id = generate_id()
        for i in range(3):
            repos.functions.save(
                Function(
                    run_id=run_id,
                    name=f"f{i}",
                    file_path="a.c",
                    reached_by_fuzzers=["fuzz1"],
                )
            )

        deleted = repos.functions.delete_by_run(run_id)
        assert deleted == 3
        assert repos.functions.find_by_run(run_id) == []


# =========================================================================
# Call Graph (composite string key, fuzzer_id as string)
# =========================================================================


class TestCallGraph:
    """Call graph tracks caller/callee relationships per fuzzer.

    In production, fuzzer_id is typically the fuzzer name (e.g., 'fuzz_target1'),
    not a 24-char ObjectId hex. Tests use fuzzer names to match real usage.
    """

    def test_composite_key_lookup(self, repos):
        """node_id = '{run_id}_{fuzzer_id}_{function_name}'."""
        run_id = generate_id()
        node = CallGraphNode(
            run_id=run_id,
            fuzzer_id="fuzz_target1",
            fuzzer_name="fuzz_target1",
            function_name="main",
            callers=[],
            callees=["parse_input"],
            call_depth=0,
        )
        repos.callgraph_nodes.save(node)

        found = repos.callgraph_nodes.find_by_function(run_id, "fuzz_target1", "main")
        assert found is not None
        assert found.callees == ["parse_input"]

    def test_callers_and_callees_traversal(self, repos):
        """find_callers/find_callees return the adjacency lists."""
        run_id = generate_id()
        node = CallGraphNode(
            run_id=run_id,
            fuzzer_id="fuzz1",
            fuzzer_name="fuzz1",
            function_name="process",
            callers=["main", "init"],
            callees=["read_buf", "write_out"],
            call_depth=1,
        )
        repos.callgraph_nodes.save(node)

        assert set(repos.callgraph_nodes.find_callers(run_id, "fuzz1", "process")) == {
            "main",
            "init",
        }
        assert set(repos.callgraph_nodes.find_callees(run_id, "fuzz1", "process")) == {
            "read_buf",
            "write_out",
        }

    def test_find_by_depth_filters_correctly(self, repos):
        """find_by_depth returns only nodes at the specified depth."""
        run_id = generate_id()
        fid = "fuzz1"
        for depth, name in [(0, "main"), (1, "parse"), (1, "read"), (2, "memcpy")]:
            repos.callgraph_nodes.save(
                CallGraphNode(
                    run_id=run_id,
                    fuzzer_id=fid,
                    fuzzer_name=fid,
                    function_name=name,
                    call_depth=depth,
                )
            )

        depth1 = repos.callgraph_nodes.find_by_depth(run_id, fid, 1)
        assert len(depth1) == 2
        assert all(n.call_depth == 1 for n in depth1)

    def test_delete_by_fuzzer_isolates(self, repos):
        """Deleting one fuzzer's call graph doesn't affect another's."""
        run_id = generate_id()
        repos.callgraph_nodes.save(
            CallGraphNode(
                run_id=run_id,
                fuzzer_id="fuzz_a",
                fuzzer_name="a",
                function_name="fn1",
                call_depth=0,
            )
        )
        repos.callgraph_nodes.save(
            CallGraphNode(
                run_id=run_id,
                fuzzer_id="fuzz_b",
                fuzzer_name="b",
                function_name="fn2",
                call_depth=0,
            )
        )

        deleted = repos.callgraph_nodes.delete_by_fuzzer(run_id, "fuzz_a")
        assert deleted == 1

        remaining = repos.callgraph_nodes.find_by_run(run_id)
        assert len(remaining) == 1
        assert remaining[0].fuzzer_id == "fuzz_b"


# =========================================================================
# Cross-Cutting Concerns
# =========================================================================


class TestObjectIdRoundtrip:
    """Verify str→ObjectId→str survives round-trip for all model types.

    This is THE most common source of bugs: code stores ObjectId in MongoDB
    but queries with string, or vice versa.
    """

    def test_run_roundtrip(self, repos):
        run = Run(project_name="test")
        repos.runs.save(run)
        found = repos.runs.find_by_id(run.run_id)
        assert found.run_id == run.run_id

    def test_worker_roundtrip(self, repos):
        w = Worker(run_id=generate_id(), fuzzer="f1")
        repos.workers.save(w)
        found = repos.workers.find_by_id(w.worker_id)
        assert found.worker_id == w.worker_id

    def test_vh_roundtrip(self, repos):
        vh = VulnerabilityHypothesis(
            run_id=generate_id(),
            function_name="f",
            lg_id=generate_id(),
            description="d",
        )
        repos.vulnerability_hypotheses.save(vh)
        found = repos.vulnerability_hypotheses.find_by_id(vh.vulnerability_hypothesis_id)
        assert found.vulnerability_hypothesis_id == vh.vulnerability_hypothesis_id
        assert found.run_id == vh.run_id
        assert found.lg_id == vh.lg_id

    def test_logic_group_roundtrip(self, repos):
        d = LogicGroup(run_id=generate_id(), fuzzer="f", name="d")
        repos.logic_groups.save(d)
        found = repos.logic_groups.find_by_id(d.lg_id)
        assert found.lg_id == d.lg_id

    def test_function_composite_key_roundtrip(self, repos):
        """Function uses '{run_id}_{name}' as _id, not ObjectId."""
        run_id = generate_id()
        fn = Function(
            run_id=run_id, name="func", file_path="a.c", reached_by_fuzzers=["f1"]
        )
        repos.functions.save(fn)
        found = repos.functions.find_by_id(fn.function_id)
        assert found.function_id == fn.function_id
        assert found.run_id == run_id


class TestRepositoryManager:
    def test_lazy_singleton_per_repo(self, repos):
        """Each property returns the same instance on repeated access."""
        assert repos.runs is repos.runs
        assert repos.pocs is repos.pocs
        assert repos.vulnerability_hypotheses is repos.vulnerability_hypotheses

    def test_all_nine_repos_accessible(self, repos):
        """All 9 repository types are accessible."""
        repo_names = [
            "runs",
            "pocs",
            "patches",
            "vulnerability_hypotheses",
            "logic_groups",
            "workers",
            "fuzzers",
            "functions",
            "callgraph_nodes",
        ]
        for name in repo_names:
            assert getattr(repos, name) is not None
