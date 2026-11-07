# SPDX-License-Identifier: Apache-2.0
"""
Pipeline Chain Integration Tests — Bug-Hunting Probes

Each test asserts the CORRECT invariant (what the code SHOULD do).
Tests marked @pytest.mark.xfail are known bugs — they FAIL today,
proving the bug exists. When the bug is fixed, they will PASS and
pytest will report them as XPASS (unexpectedly passing), signaling
the xfail marker should be removed.

Known bugs:
  1. __exit__ pops registry BEFORE DB save → zombie worker/agent on save failure
  2. increment_*() counters are read-modify-write without lock → lost updates
  3. claim_for_verify() has no recovery → orphaned VHs stuck forever
  5. update_status() allows backward transitions (completed → running)
  6. __enter__() has no reentrance guard → started_at overwritten
"""

import threading
import time
from datetime import datetime
from unittest.mock import patch

import mongomock
import pytest
from bson import ObjectId

from fuzzingbrain.worker.context import (
    WorkerContext,
    _worker_contexts,
    _worker_contexts_lock,
    get_workers_by_run,
)
from fuzzingbrain.agents.context import (
    AgentContext,
    _agent_contexts,
    _agent_contexts_lock,
)
from fuzzingbrain.core.models import VHStatus
from fuzzingbrain.core.models.logic_group import LogicGroupStatus
from fuzzingbrain.db.repository import VulnerabilityHypothesisRepository, LogicGroupRepository


# All local imports in context.py use `from ..db import get_database`
# and `from ..llms.buffer import ...`, so we patch at the source module.
DB_PATCH = "fuzzingbrain.db.get_database"
LLM_BUFFER_PATCH = "fuzzingbrain.llms.buffer.WorkerLLMBuffer"
SET_BUFFER_PATCH = "fuzzingbrain.llms.buffer.set_worker_buffer"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def clean_registries():
    """Clear global in-memory registries before and after every test."""
    with _worker_contexts_lock:
        _worker_contexts.clear()
    with _agent_contexts_lock:
        _agent_contexts.clear()
    yield
    with _worker_contexts_lock:
        _worker_contexts.clear()
    with _agent_contexts_lock:
        _agent_contexts.clear()


@pytest.fixture
def mock_db():
    """Fresh mongomock database per test."""
    client = mongomock.MongoClient()
    db = client["fuzzingbrain_test"]
    yield db
    client.close()


@pytest.fixture
def patch_worker_db(mock_db):
    """Route WorkerContext._save_to_db through mongomock."""
    with patch(DB_PATCH, return_value=mock_db):
        with patch(LLM_BUFFER_PATCH):
            with patch(SET_BUFFER_PATCH):
                yield mock_db


@pytest.fixture
def patch_agent_db(mock_db):
    """Route AgentContext._save_to_db through mongomock."""
    with patch(DB_PATCH, return_value=mock_db):
        yield mock_db


@pytest.fixture
def run_id():
    """A stable run ObjectId string."""
    return str(ObjectId())


@pytest.fixture
def vh_repo(mock_db):
    """VulnerabilityHypothesisRepository backed by mongomock."""
    return VulnerabilityHypothesisRepository(mock_db)


@pytest.fixture
def dir_repo(mock_db):
    """LogicGroupRepository backed by mongomock."""
    return LogicGroupRepository(mock_db)


def _make_worker(run_id: str, **kwargs) -> WorkerContext:
    """Helper to build a WorkerContext with sensible defaults."""
    return WorkerContext(
        run_id=run_id,
        fuzzer=kwargs.get("fuzzer", "libfuzzer"),
        sanitizer=kwargs.get("sanitizer", "address"),
        project_name=kwargs.get("project_name", "test-project"),
    )


def _make_agent(run_id: str, worker_id: str, **kwargs) -> AgentContext:
    """Helper to build an AgentContext with sensible defaults."""
    return AgentContext(
        run_id=run_id,
        worker_id=worker_id,
        agent_type=kwargs.get("agent_type", "POCAgent"),
        fuzzer=kwargs.get("fuzzer", "libfuzzer"),
        sanitizer=kwargs.get("sanitizer", "address"),
    )


# =============================================================================
# Class 1: Ghost Worker/Agent on __exit__ save failure  (Bug 1 — SEVERE)
#
# Root cause: __exit__ used to pop from registry BEFORE saving to DB.
# If save failed, the worker was gone from both memory and DB (zombie).
# Fix: save first, only pop from registry if save succeeds. If save fails,
# the worker stays in memory so get_workers_by_run() returns correct status.
# =============================================================================


class TestWorkerGhostOnSaveFailure:
    """
    Invariant: After __exit__, the worker's final status (completed/failed)
    must be queryable — via DB if save succeeded, via in-memory if it didn't.
    """

    def test_worker_stays_in_registry_when_exit_save_fails(self, run_id, mock_db):
        """
        If __exit__'s DB save fails, the worker must stay in the
        in-memory registry so it remains queryable.
        """
        call_count = 0

        def controlled_get_db():
            nonlocal call_count
            call_count += 1
            # __enter__: 2 calls (LLM buffer + initial save) → succeed
            # __exit__: 3rd call → fail
            if call_count <= 2:
                return mock_db
            raise ConnectionError("DB down on exit")

        with patch(DB_PATCH, side_effect=controlled_get_db):
            with patch(LLM_BUFFER_PATCH):
                with patch(SET_BUFFER_PATCH):
                    ctx = _make_worker(run_id)
                    ctx.__enter__()
                    worker_id = ctx.worker_id
                    ctx.__exit__(None, None, None)

        # Worker must still be in memory registry (save failed → not popped)
        assert worker_id in _worker_contexts, (
            "Worker must stay in registry when final save fails"
        )
        # In-memory status must be the final status
        assert _worker_contexts[worker_id].status == "completed"

    def test_worker_query_returns_final_status_on_save_failure(self, run_id, mock_db):
        """
        get_workers_by_run must return the correct final status
        even when DB save failed — via in-memory merge.
        """
        call_count = 0

        def controlled_get_db():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return mock_db
            raise ConnectionError("DB down on exit")

        with patch(DB_PATCH, side_effect=controlled_get_db):
            with patch(LLM_BUFFER_PATCH):
                with patch(SET_BUFFER_PATCH):
                    ctx = _make_worker(run_id)
                    ctx.__enter__()
                    ctx.__exit__(None, None, None)

        # Query uses in-memory merge to override stale DB record
        with patch(DB_PATCH, return_value=mock_db):
            workers = get_workers_by_run(run_id)

        assert len(workers) == 1
        assert workers[0]["status"] in ("completed", "failed")

    def test_worker_exit_retries_save_on_transient_failure(self, run_id, mock_db):
        """
        If __exit__'s first DB save fails but the retry succeeds,
        the worker must be properly saved to DB and removed from registry.
        """
        call_count = 0

        def controlled_get_db():
            nonlocal call_count
            call_count += 1
            # __enter__: calls 1-2 succeed (buffer + initial save)
            # __exit__: call 3 fails (first attempt), call 4 succeeds (retry)
            if call_count == 3:
                raise ConnectionError("transient DB failure")
            return mock_db

        with patch(DB_PATCH, side_effect=controlled_get_db):
            with patch(LLM_BUFFER_PATCH):
                with patch(SET_BUFFER_PATCH):
                    ctx = _make_worker(run_id)
                    ctx.__enter__()
                    worker_id = ctx.worker_id
                    ctx.__exit__(None, None, None)

        # Retry succeeded → removed from registry
        assert worker_id not in _worker_contexts, (
            "Worker should be removed after retry succeeds"
        )
        # DB has correct final status
        doc = mock_db.workers.find_one({"_id": ObjectId(worker_id)})
        assert doc is not None
        assert doc["status"] == "completed"

    def test_worker_removed_from_registry_when_save_succeeds(
        self, patch_worker_db, run_id
    ):
        """
        Normal case: save succeeds → worker is removed from registry
        and DB has the correct final status.
        """
        ctx = _make_worker(run_id)
        ctx.__enter__()
        worker_id = ctx.worker_id
        ctx.__exit__(None, None, None)

        # Removed from memory
        assert worker_id not in _worker_contexts
        # DB has correct status
        doc = patch_worker_db.workers.find_one({"_id": ObjectId(worker_id)})
        assert doc["status"] == "completed"

    def test_agent_stays_in_registry_when_exit_save_fails(self, run_id, mock_db):
        """Same fix for AgentContext: stays in memory if save fails."""
        call_count = 0

        def controlled_get_db():
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                return mock_db
            raise ConnectionError("DB down on exit")

        worker_id = str(ObjectId())

        with patch(DB_PATCH, side_effect=controlled_get_db):
            ctx = _make_agent(run_id, worker_id)
            ctx.__enter__()
            agent_id = ctx.agent_id
            ctx.__exit__(None, None, None)

        # Agent must still be in memory registry
        assert agent_id in _agent_contexts, (
            "Agent must stay in registry when final save fails"
        )
        assert _agent_contexts[agent_id].status == "completed"


# =============================================================================
# Class 2: Counter Race Conditions  (Bug 2 — MEDIUM)
#
# Root cause: `self.agents_spawned += 1` is non-atomic read-modify-write.
# _save_lock only protects _save_to_db, not the counter increment.
# CPython GIL makes this hard to trigger, but the code is still wrong.
# =============================================================================


class TestCounterRaceConditions:
    """
    Invariant: N concurrent increments must produce counter == N.
    """

    def test_concurrent_increment_agents_spawned(self, patch_worker_db, run_id):
        """50 threads each increment once → counter must be exactly 50."""
        ctx = _make_worker(run_id)
        ctx.__enter__()

        n_threads = 50
        barrier = threading.Barrier(n_threads)
        errors = []

        def inc():
            try:
                barrier.wait(timeout=5)
                ctx.increment_agents_spawned()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=inc) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Thread errors: {errors}"
        # CORRECT invariant: counter == N
        # CPython GIL may mask the race, so xfail only if race is detected
        assert ctx.agents_spawned == n_threads, (
            f"Race condition: expected {n_threads}, got {ctx.agents_spawned} "
            f"(lost {n_threads - ctx.agents_spawned} updates)"
        )

        ctx.__exit__(None, None, None)

    def test_concurrent_increment_vh_found_with_force_save(
        self, patch_worker_db, run_id
    ):
        """
        increment_vh_found calls _save_to_db(force=True) → heavier lock
        contention makes the unprotected counter race more likely.
        """
        ctx = _make_worker(run_id)
        ctx.__enter__()

        n_threads = 20
        barrier = threading.Barrier(n_threads)
        errors = []

        def inc():
            try:
                barrier.wait(timeout=5)
                ctx.increment_vh_found(count=1)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=inc) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Thread errors: {errors}"
        assert ctx.vh_found == n_threads, (
            f"Race condition: expected {n_threads}, got {ctx.vh_found} "
            f"(lost {n_threads - ctx.vh_found} updates)"
        )

        ctx.__exit__(None, None, None)


# =============================================================================
# Class 3: Orphaned VH Claims  (Bug 3 — SEVERE)
#
# Root cause: claim_for_verify() sets status to "verifying" atomically,
# but there is no timeout, TTL, or reaper. If the agent crashes without
# calling release_claim(), the VH is stuck forever.
# =============================================================================


class TestOrphanedClaims:
    """
    Invariant: An orphaned claim (agent crashed after claim) must be
    recoverable by another agent without manual intervention.

    Tests all three claim types: verify, PoC, and logic group.
    """

    # ---- helpers ----

    def _insert_pending_verify_vh(self, mock_db, run_id: str) -> str:
        """Insert a pending_verify VH, return its ID."""
        vh_id = ObjectId()
        mock_db.vulnerability_hypotheses.insert_one(
            {
                "_id": vh_id,
                "run_id": ObjectId(run_id),
                "function_name": "vuln_func",
                "status": VHStatus.PENDING_VERIFY.value,
                "score": 0.8,
                "proceed": False,
                "is_checked_by_verifier": False,
                "is_crash_found": False,
                "sources": [{"harness_name": "fuzz_x", "sanitizer": "address"}],
                "created_at": datetime.now(),
            }
        )
        return str(vh_id)

    def _insert_pending_poc_vh(self, mock_db, run_id: str) -> str:
        """Insert a pending_poc VH, return its ID."""
        vh_id = ObjectId()
        mock_db.vulnerability_hypotheses.insert_one(
            {
                "_id": vh_id,
                "run_id": ObjectId(run_id),
                "function_name": "vuln_func",
                "status": VHStatus.PENDING_POC.value,
                "score": 0.9,
                "proceed": True,
                "is_checked_by_verifier": True,
                "is_crash_found": True,
                "poc_success_by": None,
                "poc_attempted_by": [],
                "sources": [{"harness_name": "fuzz_x", "sanitizer": "address"}],
                "created_at": datetime.now(),
            }
        )
        return str(vh_id)

    def _insert_pending_logic_group(
        self, mock_db, run_id: str, fuzzer: str = "fuzz_x"
    ) -> str:
        """Insert a pending logic group, return its ID."""
        dir_id = ObjectId()
        mock_db.logic_groups.insert_one(
            {
                "_id": dir_id,
                "run_id": ObjectId(run_id),
                "fuzzer": fuzzer,
                "name": "test_logic_group",
                "description": "test",
                "status": LogicGroupStatus.PENDING.value,
                "risk_level": "high",
                "core_functions": ["func_a"],
                "entry_functions": ["main"],
                "created_at": datetime.now(),
            }
        )
        return str(dir_id)

    # ---- Verify claim tests ----

    def test_verify_crash_releases_claim_via_finally(self, mock_db, run_id, vh_repo):
        """
        Simulate pipeline's finally block: agent crashes after claiming,
        finally calls release_claim, next agent can reclaim.

        This is the fix for Bug #3a: pipeline.py's try/finally ensures
        release_claim is always called, even on KeyboardInterrupt/CancelledError.
        """
        self._insert_pending_verify_vh(mock_db, run_id)

        claimed1 = vh_repo.claim_for_verify(run_id, processor_id="agent-001")
        assert claimed1 is not None
        assert claimed1.status == "verifying"

        # Agent 1 "crashes" — pipeline's finally block calls release_claim
        released = vh_repo.release_claim(
            claimed1.vulnerability_hypothesis_id, revert_status="pending_verify"
        )
        assert released is True

        # Agent 2 can now reclaim
        claimed2 = vh_repo.claim_for_verify(run_id, processor_id="agent-002")
        assert claimed2 is not None, (
            "VH must be reclaimable after release_claim in finally block"
        )

    def test_verify_release_claim_restores_to_pending(self, mock_db, run_id, vh_repo):
        """
        Explicit release_claim correctly restores the VH.
        Proves recovery path exists but requires manual intervention.
        """
        vh_id = self._insert_pending_verify_vh(mock_db, run_id)

        claimed = vh_repo.claim_for_verify(run_id, processor_id="agent-001")
        assert claimed is not None

        released = vh_repo.release_claim(vh_id, revert_status="pending_verify")
        assert released is True

        claimed2 = vh_repo.claim_for_verify(run_id, processor_id="agent-002")
        assert claimed2 is not None

    # ---- PoC claim tests ----

    def test_poc_orphaned_vh_reclaimable_by_different_worker(
        self, mock_db, run_id, vh_repo
    ):
        """
        PoC claim allows re-claiming by a DIFFERENT fuzzer/sanitizer combo
        because query matches both pending_poc and generating_poc.

        Note: claim_for_poc without harness_name/sanitizer skips the
        sources and poc_attempted_by filters, so any worker can reclaim.
        """
        self._insert_pending_poc_vh(mock_db, run_id)

        # Worker A claims (with source filter)
        claimed1 = vh_repo.claim_for_poc(
            run_id,
            processor_id="agent-001",
            harness_name="fuzz_x",
            sanitizer="address",
        )
        assert claimed1 is not None

        # Worker A "crashes" — VH stays in generating_poc

        # Worker B (no filter — simulates a different worker that can handle any VH)
        claimed2 = vh_repo.claim_for_poc(
            run_id,
            processor_id="agent-002",
        )
        assert claimed2 is not None, (
            "Orphaned PoC VH must be reclaimable by a different worker"
        )

    def test_poc_crash_releases_claim_and_attempted_by(self, mock_db, run_id, vh_repo):
        """
        Simulate pipeline's finally block for PoC: agent crashes after claiming,
        finally calls release_claim with harness_name/sanitizer to also clean
        poc_attempted_by, so the same worker can retry.

        This is the fix for Bug #3c: release_claim now accepts harness_name/sanitizer
        to remove the poc_attempted_by entry on crash recovery.
        """
        self._insert_pending_poc_vh(mock_db, run_id)

        # Worker A claims
        claimed1 = vh_repo.claim_for_poc(
            run_id,
            processor_id="agent-001",
            harness_name="fuzz_x",
            sanitizer="address",
        )
        assert claimed1 is not None

        # Worker A "crashes" — pipeline's finally block calls release_claim
        # with harness_name/sanitizer to clean poc_attempted_by
        released = vh_repo.release_claim(
            claimed1.vulnerability_hypothesis_id,
            revert_status="pending_poc",
            harness_name="fuzz_x",
            sanitizer="address",
        )
        assert released is True

        # Same worker combo can now retry
        claimed2 = vh_repo.claim_for_poc(
            run_id,
            processor_id="agent-001",
            harness_name="fuzz_x",
            sanitizer="address",
        )
        assert claimed2 is not None, (
            "Same worker should be able to retry after crash with poc_attempted_by cleanup"
        )

    # ---- Logic group claim tests ----

    def test_logic_group_crash_releases_claim(self, mock_db, run_id, dir_repo):
        """
        After an agent claims a logic group and crashes, release_claim
        restores it to pending so another agent can reclaim.

        Note: logic_groups.claim() is currently not called in production code
        (fullscan uses find_pending() directly), but this tests the mechanism
        in case it's wired up in the future.
        """
        dir_id = self._insert_pending_logic_group(mock_db, run_id)

        claimed1 = dir_repo.claim(run_id, fuzzer="fuzz_x", processor_id="agent-001")
        assert claimed1 is not None

        # Agent "crashes" — release_claim restores to pending
        released = dir_repo.release_claim(dir_id)
        assert released is True

        # Another agent can now reclaim
        claimed2 = dir_repo.claim(run_id, fuzzer="fuzz_x", processor_id="agent-002")
        assert claimed2 is not None, "Logic group must be reclaimable after release_claim"

    def test_logic_group_release_claim_restores_to_pending(
        self, mock_db, run_id, dir_repo
    ):
        """
        Explicit release_claim correctly restores the logic group.
        Proves recovery path exists but requires manual invocation.
        """
        dir_id = self._insert_pending_logic_group(mock_db, run_id)

        claimed = dir_repo.claim(run_id, fuzzer="fuzz_x", processor_id="agent-001")
        assert claimed is not None

        released = dir_repo.release_claim(dir_id)
        assert released is True

        claimed2 = dir_repo.claim(run_id, fuzzer="fuzz_x", processor_id="agent-002")
        assert claimed2 is not None


# =============================================================================
# Class 4: ObjectId Chain Integrity
# =============================================================================


class TestObjectIdChainIntegrity:
    """
    Invariant: Run → Worker → Agent chain must be fully traceable via DB,
    and query APIs must not produce duplicates regardless of argument type.
    """

    def test_full_chain_run_worker_agent_trace(
        self, patch_worker_db, patch_agent_db, run_id
    ):
        """
        Create 1 Run → 2 Workers → 2 Agents each.
        Verify the full chain is traceable through DB queries.
        """
        db = patch_agent_db

        worker_ids = []

        for i in range(2):
            w_ctx = _make_worker(run_id, fuzzer=f"fuzzer_{i}")
            w_ctx.__enter__()
            worker_ids.append(w_ctx.worker_id)

            for j in range(2):
                a_ctx = _make_agent(
                    run_id, w_ctx.worker_id, agent_type=f"Agent_{i}_{j}"
                )
                a_ctx.__enter__()
                a_ctx.__exit__(None, None, None)

            w_ctx.__exit__(None, None, None)

        # Verify workers found by run_id
        worker_docs = list(db.workers.find({"run_id": ObjectId(run_id)}))
        assert len(worker_docs) == 2, f"Expected 2 workers, got {len(worker_docs)}"

        # Verify agents found by worker_id
        for wid in worker_ids:
            agent_docs = list(db.agents.find({"worker_id": ObjectId(wid)}))
            assert len(agent_docs) == 2, (
                f"Expected 2 agents for worker {wid[:8]}, got {len(agent_docs)}"
            )

        # Verify total agents found by run_id
        all_agents = list(db.agents.find({"run_id": ObjectId(run_id)}))
        assert len(all_agents) == 4, f"Expected 4 agents total, got {len(all_agents)}"

    def test_get_workers_by_run_no_duplicates_with_objectid_arg(
        self, patch_worker_db, run_id
    ):
        """
        Passing ObjectId(run_id) to get_workers_by_run must not
        produce duplicate entries for a running worker.
        """
        ctx = _make_worker(run_id)
        ctx.__enter__()
        worker_id = ctx.worker_id

        workers = get_workers_by_run(ObjectId(run_id))
        wids = [w["worker_id"] for w in workers]

        ctx.__exit__(None, None, None)

        assert wids.count(worker_id) == 1, f"Duplicate workers returned: {wids}"

    def test_get_workers_by_run_no_duplicates_with_str_arg(
        self, patch_worker_db, run_id
    ):
        """Control: passing str(run_id) must also not produce duplicates."""
        ctx = _make_worker(run_id)
        ctx.__enter__()
        worker_id = ctx.worker_id

        workers = get_workers_by_run(str(run_id))
        wids = [w["worker_id"] for w in workers]

        ctx.__exit__(None, None, None)

        assert wids.count(worker_id) == 1, f"Duplicate workers returned: {wids}"


# =============================================================================
# Class 5: Status Transition Guards  (Bug 5 — LOW)
#
# Root cause: update_status() does `self.status = status` with no validation.
# =============================================================================


class TestStatusTransitionGuards:
    """
    Invariant: Status transitions must be monotonic
    (pending → running → completed|failed). Backward transitions
    should be rejected.
    """

    def test_update_status_rejects_backward_transition(self, patch_worker_db, run_id):
        """
        Once a worker is 'completed', calling update_status('running')
        should be rejected (status stays 'completed').
        """
        ctx = _make_worker(run_id)
        ctx.__enter__()

        ctx.status = "completed"
        ctx.update_status("running")

        # CORRECT invariant: backward transition rejected
        assert ctx.status == "completed", (
            "Status should remain 'completed' — backward transition not allowed"
        )

        ctx.__exit__(None, None, None)

    def test_double_exit_preserves_first_status(self, patch_worker_db, run_id):
        """
        After a clean __exit__ (completed), a second __exit__ with error
        should not flip the status to 'failed'.
        """
        ctx = _make_worker(run_id)
        ctx.__enter__()

        ctx.__exit__(None, None, None)
        doc = patch_worker_db.workers.find_one({"_id": ObjectId(ctx.worker_id)})
        assert doc["status"] == "completed"

        # Second exit with error — should be ignored
        ctx.__exit__(RuntimeError, RuntimeError("oops"), None)
        doc = patch_worker_db.workers.find_one({"_id": ObjectId(ctx.worker_id)})

        # CORRECT invariant: first exit wins
        assert doc["status"] == "completed"


# =============================================================================
# Class 6: Context Reentrance  (Bug 6 — LOW)
#
# Root cause: __enter__() has no guard against being called twice.
# =============================================================================


class TestContextReentrance:
    """
    Invariant: __enter__ should be idempotent (return same context,
    preserve started_at) or raise on re-entry.
    """

    def test_worker_double_enter_preserves_started_at(self, patch_worker_db, run_id):
        """Second __enter__ should not overwrite started_at."""
        ctx = _make_worker(run_id)

        ctx.__enter__()
        first_started = ctx.started_at

        time.sleep(0.01)

        ctx.__enter__()

        # CORRECT invariant: started_at preserved
        assert ctx.started_at == first_started, "started_at must not change on re-entry"

        ctx.__exit__(None, None, None)

    def test_agent_double_enter_preserves_started_at(self, patch_agent_db, run_id):
        """Same invariant for AgentContext."""
        worker_id = str(ObjectId())
        ctx = _make_agent(run_id, worker_id)

        ctx.__enter__()
        first_started = ctx.started_at

        time.sleep(0.01)

        ctx.__enter__()

        assert ctx.started_at == first_started, "started_at must not change on re-entry"

        ctx.__exit__(None, None, None)

    def test_exit_without_enter_does_not_crash(self, patch_worker_db, run_id):
        """__exit__ without __enter__ should not raise."""
        ctx = _make_worker(run_id)

        try:
            ctx.__exit__(None, None, None)
        except Exception as e:
            pytest.fail(f"__exit__ without __enter__ raised: {e}")

    def test_agent_exit_without_enter_does_not_crash(self, patch_agent_db, run_id):
        """Same for AgentContext."""
        worker_id = str(ObjectId())
        ctx = _make_agent(run_id, worker_id)

        try:
            ctx.__exit__(None, None, None)
        except Exception as e:
            pytest.fail(f"AgentContext.__exit__ without __enter__ raised: {e}")
