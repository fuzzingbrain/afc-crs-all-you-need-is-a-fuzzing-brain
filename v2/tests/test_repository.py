"""
Repository CRUD tests with mongomock.

Tests are organized by BUSINESS SCENARIOS, not by repository methods.
Each test exercises a real production workflow or edge case that could
break and cause actual damage.
"""

import pytest
from bson import ObjectId

from fuzzingbrain.core.models import (
    Task,
    TaskStatus,
    POV,
    Patch,
    SuspiciousPoint,
    SPStatus,
    Direction,
    DirectionStatus,
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
# Task Lifecycle
# =========================================================================


class TestTaskLifecycle:
    """Task goes pending → running → collects POVs/patches → completed."""

    def test_task_accumulates_povs_and_patches(self, repos):
        """As workers find POVs and patches, they accumulate on the task."""
        task = Task(project_name="openssl")
        repos.tasks.save(task)
        repos.tasks.update_status(task.task_id, "running")

        pov1, pov2, patch1 = generate_id(), generate_id(), generate_id()
        repos.tasks.add_pov(task.task_id, pov1)
        repos.tasks.add_pov(task.task_id, pov2)
        repos.tasks.add_patch(task.task_id, patch1)

        found = repos.tasks.find_by_id(task.task_id)
        assert found.status == TaskStatus.RUNNING
        assert len(found.pov_ids) == 2
        assert len(found.patch_ids) == 1
        assert pov1 in found.pov_ids
        assert pov2 in found.pov_ids

    def test_find_by_status_only_returns_matching(self, repos):
        """Dispatcher queries pending tasks to launch them."""
        pending = Task(project_name="proj1", status=TaskStatus.PENDING)
        running = Task(project_name="proj2", status=TaskStatus.RUNNING)
        done = Task(project_name="proj3", status=TaskStatus.COMPLETED)
        for t in [pending, running, done]:
            repos.tasks.save(t)

        result = repos.tasks.find_by_status("pending")
        assert len(result) == 1
        assert result[0].project_name == "proj1"

    def test_find_by_project_isolates_tasks(self, repos):
        """Multiple tasks for different projects don't cross-contaminate."""
        t1 = Task(project_name="openssl")
        t2 = Task(project_name="curl")
        for t in [t1, t2]:
            repos.tasks.save(t)

        found = repos.tasks.find_by_project("openssl")
        assert len(found) == 1
        assert found[0].task_id == t1.task_id

    def test_save_is_idempotent_upsert(self, repos):
        """Saving the same task twice doesn't create duplicates."""
        task = Task(project_name="test")
        repos.tasks.save(task)
        task.project_name = "updated"
        repos.tasks.save(task)

        assert repos.tasks.count() == 1
        found = repos.tasks.find_by_id(task.task_id)
        assert found.project_name == "updated"

    def test_delete_cleans_up_task(self, repos):
        task = Task()
        repos.tasks.save(task)
        assert repos.tasks.delete(task.task_id)
        assert repos.tasks.find_by_id(task.task_id) is None


# =========================================================================
# SP Pipeline: The Core Business Flow
#
# Real flow: pending_verify → [claim] → verifying → [complete_verify] →
#   verified (false positive) OR pending_pov → [claim_for_pov] →
#   generating_pov → [complete_pov] → pov_generated / failed
# =========================================================================


class TestSPPipelineLifecycle:
    """End-to-end suspicious point pipeline tests."""

    def _make_sp(self, task_id, **kwargs):
        defaults = dict(
            task_id=task_id,
            function_name="vuln_func",
            direction_id=generate_id(),
            description="heap-buffer-overflow in vuln_func",
            vuln_type="heap-buffer-overflow",
            sources=[{"harness_name": "fuzz1", "sanitizer": "address"}],
        )
        defaults.update(kwargs)
        return SuspiciousPoint(**defaults)

    def test_full_pipeline_verify_to_pov_success(self, repos):
        """SP flows through entire pipeline: create → verify → POV success."""
        task_id = generate_id()
        sp = self._make_sp(task_id, score=0.8)
        repos.suspicious_points.save(sp)

        # Step 1: Verifier agent claims
        claimed = repos.suspicious_points.claim_for_verify(task_id, "verifier_1")
        assert claimed.suspicious_point_id == sp.suspicious_point_id
        assert claimed.status == SPStatus.VERIFYING.value

        # Step 2: Verifier confirms real, sends to POV stage
        repos.suspicious_points.complete_verify(
            sp.suspicious_point_id, is_real=True, score=0.95,
            notes="confirmed via manual analysis", proceed_to_pov=True,
        )
        found = repos.suspicious_points.find_by_id(sp.suspicious_point_id)
        assert found.status == SPStatus.PENDING_POV.value
        assert found.is_checked is True
        assert found.is_real is True
        assert found.score == 0.95

        # Step 3: POV worker claims
        pov_claimed = repos.suspicious_points.claim_for_pov(
            task_id, "pov_worker_1",
            harness_name="fuzz1", sanitizer="address",
        )
        assert pov_claimed is not None
        assert pov_claimed.status == SPStatus.GENERATING_POV.value

        # Step 4: POV worker succeeds
        pov_id = generate_id()
        result = repos.suspicious_points.complete_pov(
            sp.suspicious_point_id, pov_id=pov_id, success=True,
            harness_name="fuzz1", sanitizer="address",
        )
        assert result is True

        # Final state check
        final = repos.suspicious_points.find_by_id(sp.suspicious_point_id)
        assert final.status == SPStatus.POV_GENERATED.value
        assert final.pov_id == pov_id
        assert final.pov_success_by["harness_name"] == "fuzz1"

    def test_verify_false_positive_stays_terminal(self, repos):
        """SP verified as false positive → VERIFIED (terminal), not in POV pipeline."""
        task_id = generate_id()
        sp = self._make_sp(task_id, score=0.4)
        repos.suspicious_points.save(sp)

        repos.suspicious_points.claim_for_verify(task_id, "verifier_1")
        repos.suspicious_points.complete_verify(
            sp.suspicious_point_id, is_real=False, score=0.1,
            proceed_to_pov=False,
        )

        found = repos.suspicious_points.find_by_id(sp.suspicious_point_id)
        assert found.status == SPStatus.VERIFIED.value
        assert found.is_real is False

        # Pipeline should consider this SP done
        assert repos.suspicious_points.is_pipeline_complete(task_id) is True

    def test_all_workers_fail_pov_marks_failed(self, repos):
        """When every source worker fails POV, SP transitions to FAILED."""
        task_id = generate_id()
        sp = self._make_sp(
            task_id,
            status=SPStatus.PENDING_POV.value,
            score=0.8,
            sources=[
                {"harness_name": "fuzzA", "sanitizer": "address"},
                {"harness_name": "fuzzB", "sanitizer": "address"},
            ],
        )
        repos.suspicious_points.save(sp)

        # Worker A claims and fails
        repos.suspicious_points.claim_for_pov(
            task_id, "wA", harness_name="fuzzA", sanitizer="address"
        )
        repos.suspicious_points.complete_pov(
            sp.suspicious_point_id, success=False,
            harness_name="fuzzA", sanitizer="address",
        )

        # SP should not be failed yet — worker B hasn't tried
        mid = repos.suspicious_points.find_by_id(sp.suspicious_point_id)
        assert mid.status != SPStatus.FAILED.value

        # Worker B claims and fails
        repos.suspicious_points.claim_for_pov(
            task_id, "wB", harness_name="fuzzB", sanitizer="address"
        )
        repos.suspicious_points.complete_pov(
            sp.suspicious_point_id, success=False,
            harness_name="fuzzB", sanitizer="address",
        )

        # Now ALL sources have tried and failed → FAILED
        final = repos.suspicious_points.find_by_id(sp.suspicious_point_id)
        assert final.status == SPStatus.FAILED.value


    def test_release_claim_on_verifier_crash(self, repos):
        """If a verifier crashes, release_claim reverts SP so another agent can retry."""
        task_id = generate_id()
        sp = self._make_sp(task_id, score=0.7)
        repos.suspicious_points.save(sp)

        # Agent claims
        claimed = repos.suspicious_points.claim_for_verify(task_id, "agent_1")
        assert claimed.status == SPStatus.VERIFYING.value

        # Agent crashes → release with revert
        repos.suspicious_points.release_claim(
            sp.suspicious_point_id, revert_status=SPStatus.PENDING_VERIFY.value
        )

        found = repos.suspicious_points.find_by_id(sp.suspicious_point_id)
        assert found.status == SPStatus.PENDING_VERIFY.value

        # Another agent can now claim it
        reclaimed = repos.suspicious_points.claim_for_verify(task_id, "agent_2")
        assert reclaimed is not None
        assert reclaimed.suspicious_point_id == sp.suspicious_point_id


class TestSPClaimScheduling:
    """SP claim priority and exclusion logic."""

    def _make_sp(self, task_id, **kwargs):
        defaults = dict(
            task_id=task_id,
            function_name="vuln_func",
            direction_id=generate_id(),
            description="overflow",
            vuln_type="heap-buffer-overflow",
            sources=[{"harness_name": "fuzz1", "sanitizer": "address"}],
        )
        defaults.update(kwargs)
        return SuspiciousPoint(**defaults)

    def test_claim_verify_respects_priority(self, repos):
        """Important SPs claimed before high-score, high-score before low."""
        task_id = generate_id()
        low = self._make_sp(task_id, score=0.3, is_important=False)
        high = self._make_sp(task_id, score=0.9, is_important=False)
        important = self._make_sp(task_id, score=0.5, is_important=True)
        for sp in [low, high, important]:
            repos.suspicious_points.save(sp)

        c1 = repos.suspicious_points.claim_for_verify(task_id, "a1")
        assert c1.suspicious_point_id == important.suspicious_point_id

        c2 = repos.suspicious_points.claim_for_verify(task_id, "a2")
        assert c2.suspicious_point_id == high.suspicious_point_id

        c3 = repos.suspicious_points.claim_for_verify(task_id, "a3")
        assert c3.suspicious_point_id == low.suspicious_point_id

        # Nothing left
        assert repos.suspicious_points.claim_for_verify(task_id, "a4") is None

    def test_claim_pov_excludes_already_attempted(self, repos):
        """Worker that already attempted POV on this SP cannot claim it again."""
        task_id = generate_id()
        sp = self._make_sp(
            task_id,
            status=SPStatus.PENDING_POV.value,
            score=0.8,
            sources=[
                {"harness_name": "fuzzA", "sanitizer": "address"},
                {"harness_name": "fuzzB", "sanitizer": "address"},
            ],
        )
        repos.suspicious_points.save(sp)

        # Worker A claims
        c1 = repos.suspicious_points.claim_for_pov(
            task_id, "wA", harness_name="fuzzA", sanitizer="address"
        )
        assert c1 is not None

        # Worker A tries again → excluded
        c2 = repos.suspicious_points.claim_for_pov(
            task_id, "wA", harness_name="fuzzA", sanitizer="address"
        )
        assert c2 is None

        # Worker B can still claim the same SP
        c3 = repos.suspicious_points.claim_for_pov(
            task_id, "wB", harness_name="fuzzB", sanitizer="address"
        )
        assert c3 is not None

    def test_pov_first_success_wins_race(self, repos):
        """Two workers generate POV simultaneously — only first success recorded."""
        task_id = generate_id()
        sp = self._make_sp(
            task_id,
            status=SPStatus.GENERATING_POV.value,
            score=0.8,
            sources=[
                {"harness_name": "fuzzA", "sanitizer": "address"},
                {"harness_name": "fuzzB", "sanitizer": "address"},
            ],
        )
        repos.suspicious_points.save(sp)

        # Worker A succeeds
        assert repos.suspicious_points.complete_pov(
            sp.suspicious_point_id, pov_id=generate_id(), success=True,
            harness_name="fuzzA", sanitizer="address",
        ) is True

        # Worker B also succeeds, but too late
        assert repos.suspicious_points.complete_pov(
            sp.suspicious_point_id, pov_id=generate_id(), success=True,
            harness_name="fuzzB", sanitizer="address",
        ) is False

        final = repos.suspicious_points.find_by_id(sp.suspicious_point_id)
        assert final.pov_success_by["harness_name"] == "fuzzA"
        assert final.status == SPStatus.POV_GENERATED.value

    def test_claim_pov_respects_min_score(self, repos):
        """SPs below min_score are not claimable for POV."""
        task_id = generate_id()
        low_score = self._make_sp(
            task_id, status=SPStatus.PENDING_POV.value, score=0.3,
        )
        repos.suspicious_points.save(low_score)

        # Default min_score=0.5, so score 0.3 should not be claimable
        claimed = repos.suspicious_points.claim_for_pov(
            task_id, "w1", harness_name="fuzz1", sanitizer="address",
        )
        assert claimed is None

        # But with lower threshold, it should be claimable
        claimed2 = repos.suspicious_points.claim_for_pov(
            task_id, "w1", min_score=0.2,
            harness_name="fuzz1", sanitizer="address",
        )
        assert claimed2 is not None


class TestSPSourceMerging:
    """When multiple fuzzers find the same SP, sources merge via $addToSet."""

    def test_same_source_not_duplicated(self, repos):
        """$addToSet prevents duplicate harness/sanitizer pairs."""
        task_id = generate_id()
        sp = SuspiciousPoint(
            task_id=task_id, function_name="f",
            direction_id=generate_id(),
            description="d", vuln_type="v",
            sources=[],
        )
        repos.suspicious_points.save(sp)

        repos.suspicious_points.add_source(sp.suspicious_point_id, "fuzz1", "address")
        repos.suspicious_points.add_source(sp.suspicious_point_id, "fuzz1", "address")
        repos.suspicious_points.add_source(sp.suspicious_point_id, "fuzz2", "address")

        found = repos.suspicious_points.find_by_id(sp.suspicious_point_id)
        assert len(found.sources) == 2  # fuzz1/addr + fuzz2/addr, not 3

    def test_merged_duplicate_records_original_info(self, repos):
        """When deduplicating SPs, the duplicate's metadata is preserved."""
        task_id = generate_id()
        primary = SuspiciousPoint(
            task_id=task_id, function_name="f",
            direction_id=generate_id(),
            description="primary desc", vuln_type="heap-overflow",
            sources=[{"harness_name": "fuzz1", "sanitizer": "address"}],
        )
        repos.suspicious_points.save(primary)

        # Duplicate found by fuzz2 gets merged into primary
        repos.suspicious_points.add_merged_duplicate(
            primary.suspicious_point_id,
            description="duplicate desc from fuzz2",
            vuln_type="heap-buffer-overflow",
            harness_name="fuzz2", sanitizer="address",
            score=0.7,
        )

        found = repos.suspicious_points.find_by_id(primary.suspicious_point_id)
        assert len(found.merged_duplicates) == 1
        assert found.merged_duplicates[0]["description"] == "duplicate desc from fuzz2"
        assert found.merged_duplicates[0]["harness_name"] == "fuzz2"


class TestSPPipelineCompletion:
    """Pipeline completion checks drive the worker termination decision."""

    def _make_sp(self, task_id, **kwargs):
        defaults = dict(
            task_id=task_id, function_name="f",
            direction_id=generate_id(),
            description="d", vuln_type="v",
            sources=[{"harness_name": "fuzz1", "sanitizer": "address"}],
        )
        defaults.update(kwargs)
        return SuspiciousPoint(**defaults)

    def test_terminal_states_mean_complete(self, repos):
        """Pipeline is complete when all SPs are in terminal states."""
        task_id = generate_id()
        repos.suspicious_points.save(
            self._make_sp(task_id, status=SPStatus.POV_GENERATED.value)
        )
        repos.suspicious_points.save(
            self._make_sp(task_id, status=SPStatus.FAILED.value)
        )
        repos.suspicious_points.save(
            self._make_sp(task_id, status=SPStatus.VERIFIED.value)
        )
        repos.suspicious_points.save(
            self._make_sp(task_id, status=SPStatus.SKIPPED.value)
        )
        assert repos.suspicious_points.is_pipeline_complete(task_id) is True

    def test_pending_sp_blocks_completion(self, repos):
        """One pending_verify SP means pipeline is NOT complete."""
        task_id = generate_id()
        repos.suspicious_points.save(
            self._make_sp(task_id, status=SPStatus.POV_GENERATED.value)
        )
        repos.suspicious_points.save(
            self._make_sp(task_id, status=SPStatus.PENDING_VERIFY.value)
        )
        assert repos.suspicious_points.is_pipeline_complete(task_id) is False

    def test_worker_specific_completion(self, repos):
        """Worker checks completion for its own harness/sanitizer only."""
        task_id = generate_id()
        # SP that only fuzz1 cares about — still pending
        sp_fuzz1 = self._make_sp(
            task_id, status=SPStatus.PENDING_VERIFY.value,
            sources=[{"harness_name": "fuzz1", "sanitizer": "address"}],
        )
        # SP that only fuzz2 cares about — done
        sp_fuzz2 = self._make_sp(
            task_id, status=SPStatus.POV_GENERATED.value,
            sources=[{"harness_name": "fuzz2", "sanitizer": "address"}],
        )
        repos.suspicious_points.save(sp_fuzz1)
        repos.suspicious_points.save(sp_fuzz2)

        # fuzz2/address is done (its SPs are all terminal)
        assert repos.suspicious_points.is_pipeline_complete(
            task_id, harness_name="fuzz2", sanitizer="address"
        ) is True

        # fuzz1/address is NOT done (still has pending_verify)
        assert repos.suspicious_points.is_pipeline_complete(
            task_id, harness_name="fuzz1", sanitizer="address"
        ) is False

    def test_worker_specific_pov_stage_completion(self, repos):
        """Worker's POV pipeline is complete once it has attempted all its SPs.

        The POV-stage query checks: contributor + not succeeded + not attempted.
        After a worker attempts a POV (even if it fails), that SP is "done"
        for that worker.
        """
        task_id = generate_id()
        sp = self._make_sp(
            task_id,
            status=SPStatus.PENDING_POV.value,
            score=0.8,
            sources=[
                {"harness_name": "fuzzA", "sanitizer": "address"},
                {"harness_name": "fuzzB", "sanitizer": "address"},
            ],
        )
        repos.suspicious_points.save(sp)

        # fuzzA has un-attempted SPs → NOT complete
        assert repos.suspicious_points.is_pipeline_complete(
            task_id, harness_name="fuzzA", sanitizer="address"
        ) is False

        # fuzzA claims and fails
        repos.suspicious_points.claim_for_pov(
            task_id, "wA", harness_name="fuzzA", sanitizer="address"
        )
        repos.suspicious_points.complete_pov(
            sp.suspicious_point_id, success=False,
            harness_name="fuzzA", sanitizer="address",
        )

        # fuzzA has now attempted its only SP → complete for fuzzA
        assert repos.suspicious_points.is_pipeline_complete(
            task_id, harness_name="fuzzA", sanitizer="address"
        ) is True

        # But fuzzB still hasn't attempted → NOT complete for fuzzB
        assert repos.suspicious_points.is_pipeline_complete(
            task_id, harness_name="fuzzB", sanitizer="address"
        ) is False

    def test_count_by_status_breakdown(self, repos):
        """Status counts drive the dashboard and scheduling decisions."""
        task_id = generate_id()
        repos.suspicious_points.save(
            self._make_sp(task_id, is_checked=True, is_real=True, is_important=True)
        )
        repos.suspicious_points.save(
            self._make_sp(task_id, is_checked=True, is_real=False)
        )
        repos.suspicious_points.save(
            self._make_sp(task_id, is_checked=False)
        )

        counts = repos.suspicious_points.count_by_status(task_id)
        assert counts["total"] == 3
        assert counts["checked"] == 2
        assert counts["unchecked"] == 1
        assert counts["real"] == 1
        assert counts["false_positive"] == 1
        assert counts["important"] == 1


# =========================================================================
# Direction → SP Find Workflow
# =========================================================================


class TestDirectionWorkflow:
    """Directions represent analysis plans that agents claim and execute."""

    def _make_dir(self, task_id, **kwargs):
        defaults = dict(
            task_id=task_id, fuzzer="fuzz_target",
            name="check_null_deref_in_parser",
            risk_level=RiskLevel.MEDIUM.value,
        )
        defaults.update(kwargs)
        return Direction(**defaults)

    def test_claim_respects_risk_priority(self, repos):
        """High-risk directions are claimed before low-risk."""
        task_id = generate_id()
        low = self._make_dir(task_id, name="low_risk_dir", risk_level=RiskLevel.LOW.value)
        high = self._make_dir(task_id, name="high_risk_dir", risk_level=RiskLevel.HIGH.value)
        # Save low first to prove order doesn't matter
        repos.directions.save(low)
        repos.directions.save(high)

        claimed = repos.directions.claim(task_id, "fuzz_target", "agent_1")
        assert claimed.direction_id == high.direction_id
        assert claimed.status == DirectionStatus.IN_PROGRESS.value

    def test_complete_records_analysis_results(self, repos):
        """After analyzing a direction, sp_count and functions_analyzed are recorded."""
        task_id = generate_id()
        d = self._make_dir(task_id)
        repos.directions.save(d)
        repos.directions.claim(task_id, "fuzz_target", "agent_1")

        repos.directions.complete(d.direction_id, sp_count=7, functions_analyzed=42)
        found = repos.directions.find_by_id(d.direction_id)
        assert found.status == DirectionStatus.COMPLETED.value
        assert found.sp_count == 7
        assert found.functions_analyzed == 42

    def test_skip_low_value_direction(self, repos):
        """Agent can skip a direction deemed not worth analyzing."""
        task_id = generate_id()
        d = self._make_dir(task_id, risk_level=RiskLevel.LOW.value)
        repos.directions.save(d)

        repos.directions.skip(d.direction_id, reason="too simple")
        found = repos.directions.find_by_id(d.direction_id)
        assert found.status == DirectionStatus.SKIPPED.value

    def test_release_claim_on_agent_crash(self, repos):
        """If an agent crashes, its claimed direction returns to PENDING."""
        task_id = generate_id()
        d = self._make_dir(task_id)
        repos.directions.save(d)
        repos.directions.claim(task_id, "fuzz_target", "agent_1")

        repos.directions.release_claim(d.direction_id)

        found = repos.directions.find_by_id(d.direction_id)
        assert found.status == DirectionStatus.PENDING.value
        # Another agent can now claim it
        reclaimed = repos.directions.claim(task_id, "fuzz_target", "agent_2")
        assert reclaimed is not None

    def test_is_all_complete_mixed_states(self, repos):
        """is_all_complete only True when no PENDING or IN_PROGRESS remain."""
        task_id = generate_id()
        d1 = self._make_dir(task_id, name="d1")
        d2 = self._make_dir(task_id, name="d2")
        d3 = self._make_dir(task_id, name="d3")
        for d in [d1, d2, d3]:
            repos.directions.save(d)

        assert repos.directions.is_all_complete(task_id) is False

        repos.directions.complete(d1.direction_id)
        repos.directions.skip(d2.direction_id)
        # d3 still pending
        assert repos.directions.is_all_complete(task_id) is False

        repos.directions.complete(d3.direction_id)
        assert repos.directions.is_all_complete(task_id) is True

    def test_find_by_fuzzer_isolates_fuzzers(self, repos):
        """Directions from different fuzzers don't mix."""
        task_id = generate_id()
        d1 = self._make_dir(task_id, fuzzer="fuzz1", name="dir_for_fuzz1")
        d2 = self._make_dir(task_id, fuzzer="fuzz2", name="dir_for_fuzz2")
        repos.directions.save(d1)
        repos.directions.save(d2)

        found = repos.directions.find_by_fuzzer(task_id, "fuzz1")
        assert len(found) == 1
        assert found[0].direction_id == d1.direction_id

    def test_delete_by_task_removes_all(self, repos):
        """Cleaning up after task cancellation."""
        task_id = generate_id()
        for i in range(3):
            repos.directions.save(self._make_dir(task_id, name=f"dir_{i}"))

        deleted = repos.directions.delete_by_task(task_id)
        assert deleted == 3
        assert repos.directions.count({"task_id": ObjectId(task_id)}) == 0


# =========================================================================
# POV Discovery and Reporting
# =========================================================================


class TestPOVDiscovery:
    """POV repository serves the POV discovery and deduplication pipeline."""

    def test_find_by_task_uses_objectid(self, repos):
        """POVs stored with ObjectId(task_id) must be findable by string task_id."""
        task_id = generate_id()
        other_task = generate_id()
        p1 = POV(task_id=task_id, harness_name="h1")
        p2 = POV(task_id=task_id, harness_name="h2")
        p_other = POV(task_id=other_task, harness_name="h1")
        for p in [p1, p2, p_other]:
            repos.povs.save(p)

        found = repos.povs.find_by_task(task_id)
        assert len(found) == 2
        assert {p.pov_id for p in found} == {p1.pov_id, p2.pov_id}

    def test_successful_excludes_inactive_and_failed(self, repos):
        """Only active + successful POVs count toward task score."""
        task_id = generate_id()
        active_success = POV(task_id=task_id, is_active=True, is_successful=True)
        active_fail = POV(task_id=task_id, is_active=True, is_successful=False)
        inactive_success = POV(task_id=task_id, is_active=False, is_successful=True)
        for p in [active_success, active_fail, inactive_success]:
            repos.povs.save(p)

        found = repos.povs.find_successful_by_task(task_id)
        assert len(found) == 1
        assert found[0].pov_id == active_success.pov_id

    def test_find_by_harness_for_worker_isolation(self, repos):
        """Each worker queries POVs for its own harness."""
        task_id = generate_id()
        p1 = POV(task_id=task_id, harness_name="fuzz_target1")
        p2 = POV(task_id=task_id, harness_name="fuzz_target2")
        repos.povs.save(p1)
        repos.povs.save(p2)

        found = repos.povs.find_by_harness(task_id, "fuzz_target1")
        assert len(found) == 1
        assert found[0].harness_name == "fuzz_target1"

    def test_deactivate_removes_from_active_query(self, repos):
        """Deactivated POV no longer appears in active/successful queries."""
        task_id = generate_id()
        pov = POV(task_id=task_id, is_active=True, is_successful=True)
        repos.povs.save(pov)

        repos.povs.deactivate(pov.pov_id)

        assert len(repos.povs.find_active_by_task(task_id)) == 0
        assert len(repos.povs.find_successful_by_task(task_id)) == 0

        # But still findable by direct ID
        found = repos.povs.find_by_id(pov.pov_id)
        assert found is not None
        assert found.is_active is False


# =========================================================================
# Patch Verification Pipeline
# =========================================================================


class TestPatchVerification:
    """Patches go through apply → compile → pov → test checks."""

    def test_only_fully_verified_patches_are_valid(self, repos):
        """find_valid_by_task requires all 4 checks to be True."""
        task_id = generate_id()
        full_pass = Patch(
            task_id=task_id, apply_check=True, compilation_check=True,
            pov_check=True, test_check=True,
        )
        partial_pass = Patch(
            task_id=task_id, apply_check=True, compilation_check=True,
            pov_check=True, test_check=False,  # test failed
        )
        repos.patches.save(full_pass)
        repos.patches.save(partial_pass)

        valid = repos.patches.find_valid_by_task(task_id)
        assert len(valid) == 1
        assert valid[0].patch_id == full_pass.patch_id

    def test_inactive_patch_excluded_from_valid(self, repos):
        """Deactivated patches are not returned even if all checks pass."""
        task_id = generate_id()
        pa = Patch(
            task_id=task_id, apply_check=True, compilation_check=True,
            pov_check=True, test_check=True, is_active=False,
        )
        repos.patches.save(pa)

        assert len(repos.patches.find_valid_by_task(task_id)) == 0

    def test_incremental_check_updates(self, repos):
        """Checks are updated incrementally as each stage completes."""
        task_id = generate_id()
        pa = Patch(task_id=task_id)
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
        assert found.pov_check is False


# =========================================================================
# Worker Lifecycle
# =========================================================================


class TestWorkerLifecycle:
    """Workers progress: pending → building → running → completed."""

    def test_worker_state_progression_with_results(self, repos):
        """Worker goes through states and accumulates results."""
        task_id = generate_id()
        w = Worker(task_id=task_id, fuzzer="fuzz1", sanitizer="address",
                   project_name="openssl")
        repos.workers.save(w)

        repos.workers.update_status(w.worker_id, "running")
        repos.workers.update_strategy(w.worker_id, "fullscan")
        repos.workers.update_strategy(w.worker_id, "pov_targeted")
        repos.workers.update_results(w.worker_id, povs=3, patches=1)

        found = repos.workers.find_by_id(w.worker_id)
        assert found.status == WorkerStatus.RUNNING
        assert found.current_strategy == "pov_targeted"
        assert found.strategy_history == ["fullscan", "pov_targeted"]
        assert found.pov_generated == 3
        assert found.patch_generated == 1

    def test_find_by_fuzzer_exact_match(self, repos):
        """find_by_fuzzer matches on task_id + fuzzer + sanitizer triple."""
        task_id = generate_id()
        w_addr = Worker(task_id=task_id, fuzzer="fuzz1", sanitizer="address")
        w_mem = Worker(task_id=task_id, fuzzer="fuzz1", sanitizer="memory")
        repos.workers.save(w_addr)
        repos.workers.save(w_mem)

        found = repos.workers.find_by_fuzzer(task_id, "fuzz1", "address")
        assert found.worker_id == w_addr.worker_id

        assert repos.workers.find_by_fuzzer(task_id, "fuzz1", "undefined") is None

    def test_find_by_task_isolates_tasks(self, repos):
        """Workers from different tasks don't mix."""
        tid_a = generate_id()
        tid_b = generate_id()
        w1 = Worker(task_id=tid_a, fuzzer="f1")
        w2 = Worker(task_id=tid_a, fuzzer="f2")
        w_other = Worker(task_id=tid_b, fuzzer="f1")
        for w in [w1, w2, w_other]:
            repos.workers.save(w)

        found = repos.workers.find_by_task(tid_a)
        assert len(found) == 2


# =========================================================================
# Fuzzer Build Tracking
# =========================================================================


class TestFuzzerBuild:
    """Fuzzer build status drives which fuzzers are available for analysis."""

    def test_find_successful_excludes_failed(self, repos):
        """Only fuzzers with status='success' are used for analysis."""
        task_id = generate_id()
        f_ok = Fuzzer(task_id=task_id, fuzzer_name="f1", status=FuzzerStatus.SUCCESS)
        f_fail = Fuzzer(task_id=task_id, fuzzer_name="f2", status=FuzzerStatus.FAILED)
        f_building = Fuzzer(task_id=task_id, fuzzer_name="f3", status=FuzzerStatus.BUILDING)
        for f in [f_ok, f_fail, f_building]:
            repos.fuzzers.save(f)

        found = repos.fuzzers.find_successful_by_task(task_id)
        assert len(found) == 1
        assert found[0].fuzzer_name == "f1"

    def test_find_by_name_with_objectid_task(self, repos):
        """find_by_name correctly queries with ObjectId(task_id)."""
        task_id = generate_id()
        f = Fuzzer(task_id=task_id, fuzzer_name="fuzz_target1")
        repos.fuzzers.save(f)

        found = repos.fuzzers.find_by_name(task_id, "fuzz_target1")
        assert found is not None
        assert found.fuzzer_id == f.fuzzer_id
        assert found.task_id == task_id

    def test_update_status_records_binary_path(self, repos):
        """After successful build, binary_path is stored for fuzzer execution."""
        f = Fuzzer(task_id=generate_id(), fuzzer_name="fuzz1")
        repos.fuzzers.save(f)

        repos.fuzzers.update_status(f.fuzzer_id, "success", binary_path="/out/fuzz1")
        found = repos.fuzzers.find_by_id(f.fuzzer_id)
        assert found.status == FuzzerStatus.SUCCESS
        assert found.binary_path == "/out/fuzz1"


# =========================================================================
# Function Analysis Tracking (composite string key)
# =========================================================================


class TestFunctionAnalysis:
    """Functions track which directions have analyzed them to avoid redundant work."""

    def test_composite_key_lookup(self, repos):
        """Function._id = '{task_id}_{name}', find_by_name constructs this key."""
        task_id = generate_id()
        fn = Function(
            task_id=task_id, name="vuln_func", file_path="src/vuln.c",
            start_line=10, end_line=50, content="void vuln_func() {}",
            reached_by_fuzzers=["fuzz1"],
        )
        repos.functions.save(fn)

        assert fn.function_id == f"{task_id}_vuln_func"
        found = repos.functions.find_by_name(task_id, "vuln_func")
        assert found is not None
        assert found.task_id == task_id
        assert found.name == "vuln_func"

    def test_analysis_priority_ordering(self, repos):
        """get_functions_for_analysis returns unanalyzed functions first.

        This drives coverage efficiency: agents analyze new functions before
        re-visiting already-analyzed ones.
        Priority: never analyzed > analyzed by other direction > analyzed by this direction.
        """
        task_id = generate_id()
        dir_a = generate_id()
        dir_b = generate_id()

        fn_fresh = Function(
            task_id=task_id, name="fresh_func", file_path="a.c",
            reached_by_fuzzers=["fuzz1"],
        )
        fn_other = Function(
            task_id=task_id, name="analyzed_by_other", file_path="a.c",
            reached_by_fuzzers=["fuzz1"],
            analyzed_by_directions=[dir_b],
        )
        fn_done = Function(
            task_id=task_id, name="already_analyzed", file_path="a.c",
            reached_by_fuzzers=["fuzz1"],
            analyzed_by_directions=[dir_a],
        )
        for fn in [fn_fresh, fn_other, fn_done]:
            repos.functions.save(fn)

        results = repos.functions.get_functions_for_analysis(task_id, "fuzz1", dir_a)
        assert len(results) == 3
        assert results[0].name == "fresh_func"
        assert results[1].name == "analyzed_by_other"
        assert results[2].name == "already_analyzed"

    def test_mark_analyzed_is_idempotent(self, repos):
        """$addToSet ensures marking the same direction twice doesn't duplicate."""
        task_id = generate_id()
        direction_id = generate_id()
        fn = Function(
            task_id=task_id, name="func_a", file_path="a.c",
            reached_by_fuzzers=["fuzz1"],
        )
        repos.functions.save(fn)

        repos.functions.mark_analyzed_by_direction(fn.function_id, direction_id)
        repos.functions.mark_analyzed_by_direction(fn.function_id, direction_id)

        found = repos.functions.find_by_name(task_id, "func_a")
        assert len(found.analyzed_by_directions) == 1

    def test_mark_many_analyzed_batch(self, repos):
        """Batch-mark multiple functions as analyzed by one direction."""
        task_id = generate_id()
        direction_id = generate_id()
        f1 = Function(task_id=task_id, name="f1", file_path="a.c",
                      reached_by_fuzzers=["fuzz1"])
        f2 = Function(task_id=task_id, name="f2", file_path="a.c",
                      reached_by_fuzzers=["fuzz1"])
        for fn in [f1, f2]:
            repos.functions.save(fn)

        updated = repos.functions.mark_many_analyzed(
            [f1.function_id, f2.function_id], direction_id,
        )
        assert updated == 2

        for fn_id in [f1.function_id, f2.function_id]:
            found = repos.functions.find_by_id(fn_id)
            assert direction_id in found.analyzed_by_directions

    def test_delete_by_task_cleans_up(self, repos):
        """When a task is re-run, old function data is cleaned out."""
        task_id = generate_id()
        for i in range(3):
            repos.functions.save(
                Function(task_id=task_id, name=f"f{i}", file_path="a.c",
                         reached_by_fuzzers=["fuzz1"])
            )

        deleted = repos.functions.delete_by_task(task_id)
        assert deleted == 3
        assert repos.functions.find_by_task(task_id) == []


# =========================================================================
# Call Graph (composite string key, fuzzer_id as string)
# =========================================================================


class TestCallGraph:
    """Call graph tracks caller/callee relationships per fuzzer.

    In production, fuzzer_id is typically the fuzzer name (e.g., 'fuzz_target1'),
    not a 24-char ObjectId hex. Tests use fuzzer names to match real usage.
    """

    def test_composite_key_lookup(self, repos):
        """node_id = '{task_id}_{fuzzer_id}_{function_name}'."""
        task_id = generate_id()
        node = CallGraphNode(
            task_id=task_id, fuzzer_id="fuzz_target1",
            fuzzer_name="fuzz_target1", function_name="main",
            callers=[], callees=["parse_input"], call_depth=0,
        )
        repos.callgraph_nodes.save(node)

        found = repos.callgraph_nodes.find_by_function(task_id, "fuzz_target1", "main")
        assert found is not None
        assert found.callees == ["parse_input"]

    def test_callers_and_callees_traversal(self, repos):
        """find_callers/find_callees return the adjacency lists."""
        task_id = generate_id()
        node = CallGraphNode(
            task_id=task_id, fuzzer_id="fuzz1",
            fuzzer_name="fuzz1", function_name="process",
            callers=["main", "init"], callees=["read_buf", "write_out"],
            call_depth=1,
        )
        repos.callgraph_nodes.save(node)

        assert set(repos.callgraph_nodes.find_callers(task_id, "fuzz1", "process")) == {"main", "init"}
        assert set(repos.callgraph_nodes.find_callees(task_id, "fuzz1", "process")) == {"read_buf", "write_out"}

    def test_find_by_depth_filters_correctly(self, repos):
        """find_by_depth returns only nodes at the specified depth."""
        task_id = generate_id()
        fid = "fuzz1"
        for depth, name in [(0, "main"), (1, "parse"), (1, "read"), (2, "memcpy")]:
            repos.callgraph_nodes.save(
                CallGraphNode(
                    task_id=task_id, fuzzer_id=fid, fuzzer_name=fid,
                    function_name=name, call_depth=depth,
                )
            )

        depth1 = repos.callgraph_nodes.find_by_depth(task_id, fid, 1)
        assert len(depth1) == 2
        assert all(n.call_depth == 1 for n in depth1)

    def test_delete_by_fuzzer_isolates(self, repos):
        """Deleting one fuzzer's call graph doesn't affect another's."""
        task_id = generate_id()
        repos.callgraph_nodes.save(
            CallGraphNode(task_id=task_id, fuzzer_id="fuzz_a",
                          fuzzer_name="a", function_name="fn1", call_depth=0)
        )
        repos.callgraph_nodes.save(
            CallGraphNode(task_id=task_id, fuzzer_id="fuzz_b",
                          fuzzer_name="b", function_name="fn2", call_depth=0)
        )

        deleted = repos.callgraph_nodes.delete_by_fuzzer(task_id, "fuzz_a")
        assert deleted == 1

        remaining = repos.callgraph_nodes.find_by_task(task_id)
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

    def test_task_roundtrip(self, repos):
        task = Task(project_name="test")
        repos.tasks.save(task)
        found = repos.tasks.find_by_id(task.task_id)
        assert found.task_id == task.task_id

    def test_worker_roundtrip(self, repos):
        w = Worker(task_id=generate_id(), fuzzer="f1")
        repos.workers.save(w)
        found = repos.workers.find_by_id(w.worker_id)
        assert found.worker_id == w.worker_id

    def test_sp_roundtrip(self, repos):
        sp = SuspiciousPoint(
            task_id=generate_id(), function_name="f",
            direction_id=generate_id(),
            description="d", vuln_type="v",
        )
        repos.suspicious_points.save(sp)
        found = repos.suspicious_points.find_by_id(sp.suspicious_point_id)
        assert found.suspicious_point_id == sp.suspicious_point_id
        assert found.task_id == sp.task_id
        assert found.direction_id == sp.direction_id

    def test_direction_roundtrip(self, repos):
        d = Direction(task_id=generate_id(), fuzzer="f", name="d")
        repos.directions.save(d)
        found = repos.directions.find_by_id(d.direction_id)
        assert found.direction_id == d.direction_id

    def test_function_composite_key_roundtrip(self, repos):
        """Function uses '{task_id}_{name}' as _id, not ObjectId."""
        task_id = generate_id()
        fn = Function(task_id=task_id, name="func", file_path="a.c",
                      reached_by_fuzzers=["f1"])
        repos.functions.save(fn)
        found = repos.functions.find_by_id(fn.function_id)
        assert found.function_id == fn.function_id
        assert found.task_id == task_id


class TestRepositoryManager:
    def test_lazy_singleton_per_repo(self, repos):
        """Each property returns the same instance on repeated access."""
        assert repos.tasks is repos.tasks
        assert repos.povs is repos.povs
        assert repos.suspicious_points is repos.suspicious_points

    def test_all_nine_repos_accessible(self, repos):
        """All 9 repository types are accessible."""
        repo_names = [
            "tasks", "povs", "patches", "suspicious_points",
            "directions", "workers", "fuzzers", "functions", "callgraph_nodes",
        ]
        for name in repo_names:
            assert getattr(repos, name) is not None
