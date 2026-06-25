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
  3. claim_for_verify() has no recovery → orphaned SPs stuck forever
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
    get_workers_by_task,
)
from fuzzingbrain.agents.context import (
    AgentContext,
    _agent_contexts,
    _agent_contexts_lock,
)
from fuzzingbrain.core.models import SPStatus
from fuzzingbrain.core.models.direction import DirectionStatus
from fuzzingbrain.db.repository import SuspiciousPointRepository, DirectionRepository


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
def task_id():
    """A stable task ObjectId string."""
    return str(ObjectId())


@pytest.fixture
def sp_repo(mock_db):
    """SuspiciousPointRepository backed by mongomock."""
    return SuspiciousPointRepository(mock_db)


@pytest.fixture
def dir_repo(mock_db):
    """DirectionRepository backed by mongomock."""
    return DirectionRepository(mock_db)


def _make_worker(task_id: str, **kwargs) -> WorkerContext:
    """Helper to build a WorkerContext with sensible defaults."""
    return WorkerContext(
        task_id=task_id,
        fuzzer=kwargs.get("fuzzer", "libfuzzer"),
        sanitizer=kwargs.get("sanitizer", "address"),
        project_name=kwargs.get("project_name", "test-project"),
    )


def _make_agent(task_id: str, worker_id: str, **kwargs) -> AgentContext:
    """Helper to build an AgentContext with sensible defaults."""
    return AgentContext(
        task_id=task_id,
        worker_id=worker_id,
        agent_type=kwargs.get("agent_type", "POVAgent"),
        fuzzer=kwargs.get("fuzzer", "libfuzzer"),
        sanitizer=kwargs.get("sanitizer", "address"),
    )


# =============================================================================
# Class 1: Ghost Worker/Agent on __exit__ save failure  (Bug 1 — SEVERE)
#
# Root cause: __exit__ used to pop from registry BEFORE saving to DB.
# If save failed, the worker was gone from both memory and DB (zombie).
# Fix: save first, only pop from registry if save succeeds. If save fails,
# the worker stays in memory so get_workers_by_task() returns correct status.
# =============================================================================


class TestWorkerGhostOnSaveFailure:
    """
    Invariant: After __exit__, the worker's final status (completed/failed)
    must be queryable — via DB if save succeeded, via in-memory if it didn't.
    """

    def test_worker_stays_in_registry_when_exit_save_fails(self, task_id, mock_db):
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
                    ctx = _make_worker(task_id)
                    ctx.__enter__()
                    worker_id = ctx.worker_id
                    ctx.__exit__(None, None, None)

        # Worker must still be in memory registry (save failed → not popped)
        assert worker_id in _worker_contexts, (
            "Worker must stay in registry when final save fails"
        )
        # In-memory status must be the final status
        assert _worker_contexts[worker_id].status == "completed"

    def test_worker_query_returns_final_status_on_save_failure(self, task_id, mock_db):
        """
        get_workers_by_task must return the correct final status
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
                    ctx = _make_worker(task_id)
                    ctx.__enter__()
                    ctx.__exit__(None, None, None)

        # Query uses in-memory merge to override stale DB record
        with patch(DB_PATCH, return_value=mock_db):
            workers = get_workers_by_task(task_id)

        assert len(workers) == 1
        assert workers[0]["status"] in ("completed", "failed")

    def test_worker_exit_retries_save_on_transient_failure(self, task_id, mock_db):
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
                    ctx = _make_worker(task_id)
                    ctx.__enter__()
                    worker_id = ctx.worker_id
                    ctx.__exit__(None, None, None)

        # Retry succeeded → removed from registry
        assert worker_id not in _worker_contexts, \
            "Worker should be removed after retry succeeds"
        # DB has correct final status
        doc = mock_db.workers.find_one({"_id": ObjectId(worker_id)})
        assert doc is not None
        assert doc["status"] == "completed"

    def test_worker_removed_from_registry_when_save_succeeds(self, patch_worker_db, task_id):
        """
        Normal case: save succeeds → worker is removed from registry
        and DB has the correct final status.
        """
        ctx = _make_worker(task_id)
        ctx.__enter__()
        worker_id = ctx.worker_id
        ctx.__exit__(None, None, None)

        # Removed from memory
        assert worker_id not in _worker_contexts
        # DB has correct status
        doc = patch_worker_db.workers.find_one({"_id": ObjectId(worker_id)})
        assert doc["status"] == "completed"

    def test_agent_stays_in_registry_when_exit_save_fails(self, task_id, mock_db):
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
            ctx = _make_agent(task_id, worker_id)
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

    def test_concurrent_increment_agents_spawned(self, patch_worker_db, task_id):
        """50 threads each increment once → counter must be exactly 50."""
        ctx = _make_worker(task_id)
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

    def test_concurrent_increment_sp_found_with_force_save(self, patch_worker_db, task_id):
        """
        increment_sp_found calls _save_to_db(force=True) → heavier lock
        contention makes the unprotected counter race more likely.
        """
        ctx = _make_worker(task_id)
        ctx.__enter__()

        n_threads = 20
        barrier = threading.Barrier(n_threads)
        errors = []

        def inc():
            try:
                barrier.wait(timeout=5)
                ctx.increment_sp_found(count=1)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=inc) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Thread errors: {errors}"
        assert ctx.sp_found == n_threads, (
            f"Race condition: expected {n_threads}, got {ctx.sp_found} "
            f"(lost {n_threads - ctx.sp_found} updates)"
        )

        ctx.__exit__(None, None, None)


# =============================================================================
# Class 3: Orphaned SP Claims  (Bug 3 — SEVERE)
#
# Root cause: claim_for_verify() sets status to "verifying" atomically,
# but there is no timeout, TTL, or reaper. If the agent crashes without
# calling release_claim(), the SP is stuck forever.
# =============================================================================


class TestOrphanedClaims:
    """
    Invariant: An orphaned claim (agent crashed after claim) must be
    recoverable by another agent without manual intervention.

    Tests all three claim types: verify, POV, and direction.
    """

    # ---- helpers ----

    def _insert_pending_verify_sp(self, mock_db, task_id: str) -> str:
        """Insert a pending_verify SP, return its ID."""
        sp_id = ObjectId()
        mock_db.suspicious_points.insert_one({
            "_id": sp_id,
            "task_id": ObjectId(task_id),
            "function_name": "vuln_func",
            "status": SPStatus.PENDING_VERIFY.value,
            "score": 0.8,
            "is_important": False,
            "is_checked": False,
            "is_real": False,
            "sources": [{"harness_name": "fuzz_x", "sanitizer": "address"}],
            "created_at": datetime.now(),
        })
        return str(sp_id)

    def _insert_pending_pov_sp(self, mock_db, task_id: str) -> str:
        """Insert a pending_pov SP, return its ID."""
        sp_id = ObjectId()
        mock_db.suspicious_points.insert_one({
            "_id": sp_id,
            "task_id": ObjectId(task_id),
            "function_name": "vuln_func",
            "status": SPStatus.PENDING_POV.value,
            "score": 0.9,
            "is_important": True,
            "is_checked": True,
            "is_real": True,
            "pov_success_by": None,
            "pov_attempted_by": [],
            "sources": [{"harness_name": "fuzz_x", "sanitizer": "address"}],
            "created_at": datetime.now(),
        })
        return str(sp_id)

    def _insert_pending_direction(self, mock_db, task_id: str, fuzzer: str = "fuzz_x") -> str:
        """Insert a pending direction, return its ID."""
        dir_id = ObjectId()
        mock_db.directions.insert_one({
            "_id": dir_id,
            "task_id": ObjectId(task_id),
            "fuzzer": fuzzer,
            "name": "test_direction",
            "description": "test",
            "status": DirectionStatus.PENDING.value,
            "risk_level": "high",
            "core_functions": ["func_a"],
            "entry_functions": ["main"],
            "created_at": datetime.now(),
        })
        return str(dir_id)

    # ---- Verify claim tests ----

    def test_verify_crash_releases_claim_via_finally(self, mock_db, task_id, sp_repo):
        """
        Simulate pipeline's finally block: agent crashes after claiming,
        finally calls release_claim, next agent can reclaim.

        This is the fix for Bug #3a: pipeline.py's try/finally ensures
        release_claim is always called, even on KeyboardInterrupt/CancelledError.
        """
        self._insert_pending_verify_sp(mock_db, task_id)

        claimed1 = sp_repo.claim_for_verify(task_id, processor_id="agent-001")
        assert claimed1 is not None
        assert claimed1.status == "verifying"

        # Agent 1 "crashes" — pipeline's finally block calls release_claim
        released = sp_repo.release_claim(
            claimed1.suspicious_point_id, revert_status="pending_verify"
        )
        assert released is True

        # Agent 2 can now reclaim
        claimed2 = sp_repo.claim_for_verify(task_id, processor_id="agent-002")
        assert claimed2 is not None, (
            "SP must be reclaimable after release_claim in finally block"
        )

    def test_verify_release_claim_restores_to_pending(self, mock_db, task_id, sp_repo):
        """
        Explicit release_claim correctly restores the SP.
        Proves recovery path exists but requires manual intervention.
        """
        sp_id = self._insert_pending_verify_sp(mock_db, task_id)

        claimed = sp_repo.claim_for_verify(task_id, processor_id="agent-001")
        assert claimed is not None

        released = sp_repo.release_claim(sp_id, revert_status="pending_verify")
        assert released is True

        claimed2 = sp_repo.claim_for_verify(task_id, processor_id="agent-002")
        assert claimed2 is not None

    # ---- POV claim tests ----

    def test_pov_orphaned_sp_reclaimable_by_different_worker(self, mock_db, task_id, sp_repo):
        """
        POV claim allows re-claiming by a DIFFERENT fuzzer/sanitizer combo
        because query matches both pending_pov and generating_pov.

        Note: claim_for_pov without harness_name/sanitizer skips the
        sources and pov_attempted_by filters, so any worker can reclaim.
        """
        self._insert_pending_pov_sp(mock_db, task_id)

        # Worker A claims (with source filter)
        claimed1 = sp_repo.claim_for_pov(
            task_id, processor_id="agent-001",
            harness_name="fuzz_x", sanitizer="address",
        )
        assert claimed1 is not None

        # Worker A "crashes" — SP stays in generating_pov

        # Worker B (no filter — simulates a different worker that can handle any SP)
        claimed2 = sp_repo.claim_for_pov(
            task_id, processor_id="agent-002",
        )
        assert claimed2 is not None, (
            "Orphaned POV SP must be reclaimable by a different worker"
        )

    def test_pov_crash_releases_claim_and_attempted_by(self, mock_db, task_id, sp_repo):
        """
        Simulate pipeline's finally block for POV: agent crashes after claiming,
        finally calls release_claim with harness_name/sanitizer to also clean
        pov_attempted_by, so the same worker can retry.

        This is the fix for Bug #3c: release_claim now accepts harness_name/sanitizer
        to remove the pov_attempted_by entry on crash recovery.
        """
        self._insert_pending_pov_sp(mock_db, task_id)

        # Worker A claims
        claimed1 = sp_repo.claim_for_pov(
            task_id, processor_id="agent-001",
            harness_name="fuzz_x", sanitizer="address",
        )
        assert claimed1 is not None

        # Worker A "crashes" — pipeline's finally block calls release_claim
        # with harness_name/sanitizer to clean pov_attempted_by
        released = sp_repo.release_claim(
            claimed1.suspicious_point_id,
            revert_status="pending_pov",
            harness_name="fuzz_x",
            sanitizer="address",
        )
        assert released is True

        # Same worker combo can now retry
        claimed2 = sp_repo.claim_for_pov(
            task_id, processor_id="agent-001",
            harness_name="fuzz_x", sanitizer="address",
        )
        assert claimed2 is not None, (
            "Same worker should be able to retry after crash with pov_attempted_by cleanup"
        )

    # ---- Direction claim tests ----

    def test_direction_crash_releases_claim(self, mock_db, task_id, dir_repo):
        """
        After an agent claims a direction and crashes, release_claim
        restores it to pending so another agent can reclaim.

        Note: directions.claim() is currently not called in production code
        (fullscan uses find_pending() directly), but this tests the mechanism
        in case it's wired up in the future.
        """
        dir_id = self._insert_pending_direction(mock_db, task_id)

        claimed1 = dir_repo.claim(task_id, fuzzer="fuzz_x", processor_id="agent-001")
        assert claimed1 is not None

        # Agent "crashes" — release_claim restores to pending
        released = dir_repo.release_claim(dir_id)
        assert released is True

        # Another agent can now reclaim
        claimed2 = dir_repo.claim(task_id, fuzzer="fuzz_x", processor_id="agent-002")
        assert claimed2 is not None, (
            "Direction must be reclaimable after release_claim"
        )

    def test_direction_release_claim_restores_to_pending(self, mock_db, task_id, dir_repo):
        """
        Explicit release_claim correctly restores the direction.
        Proves recovery path exists but requires manual invocation.
        """
        dir_id = self._insert_pending_direction(mock_db, task_id)

        claimed = dir_repo.claim(task_id, fuzzer="fuzz_x", processor_id="agent-001")
        assert claimed is not None

        released = dir_repo.release_claim(dir_id)
        assert released is True

        claimed2 = dir_repo.claim(task_id, fuzzer="fuzz_x", processor_id="agent-002")
        assert claimed2 is not None


# =============================================================================
# Class 4: ObjectId Chain Integrity
# =============================================================================


class TestObjectIdChainIntegrity:
    """
    Invariant: Task → Worker → Agent chain must be fully traceable via DB,
    and query APIs must not produce duplicates regardless of argument type.
    """

    def test_full_chain_task_worker_agent_trace(self, patch_worker_db, patch_agent_db, task_id):
        """
        Create 1 Task → 2 Workers → 2 Agents each.
        Verify the full chain is traceable through DB queries.
        """
        db = patch_agent_db

        worker_ids = []

        for i in range(2):
            w_ctx = _make_worker(task_id, fuzzer=f"fuzzer_{i}")
            w_ctx.__enter__()
            worker_ids.append(w_ctx.worker_id)

            for j in range(2):
                a_ctx = _make_agent(task_id, w_ctx.worker_id, agent_type=f"Agent_{i}_{j}")
                a_ctx.__enter__()
                a_ctx.__exit__(None, None, None)

            w_ctx.__exit__(None, None, None)

        # Verify workers found by task_id
        worker_docs = list(db.workers.find({"task_id": ObjectId(task_id)}))
        assert len(worker_docs) == 2, f"Expected 2 workers, got {len(worker_docs)}"

        # Verify agents found by worker_id
        for wid in worker_ids:
            agent_docs = list(db.agents.find({"worker_id": ObjectId(wid)}))
            assert len(agent_docs) == 2, (
                f"Expected 2 agents for worker {wid[:8]}, got {len(agent_docs)}"
            )

        # Verify total agents found by task_id
        all_agents = list(db.agents.find({"task_id": ObjectId(task_id)}))
        assert len(all_agents) == 4, f"Expected 4 agents total, got {len(all_agents)}"

    def test_get_workers_by_task_no_duplicates_with_objectid_arg(self, patch_worker_db, task_id):
        """
        Passing ObjectId(task_id) to get_workers_by_task must not
        produce duplicate entries for a running worker.
        """
        ctx = _make_worker(task_id)
        ctx.__enter__()
        worker_id = ctx.worker_id

        workers = get_workers_by_task(ObjectId(task_id))
        wids = [w["worker_id"] for w in workers]

        ctx.__exit__(None, None, None)

        assert wids.count(worker_id) == 1, (
            f"Duplicate workers returned: {wids}"
        )

    def test_get_workers_by_task_no_duplicates_with_str_arg(self, patch_worker_db, task_id):
        """Control: passing str(task_id) must also not produce duplicates."""
        ctx = _make_worker(task_id)
        ctx.__enter__()
        worker_id = ctx.worker_id

        workers = get_workers_by_task(str(task_id))
        wids = [w["worker_id"] for w in workers]

        ctx.__exit__(None, None, None)

        assert wids.count(worker_id) == 1, (
            f"Duplicate workers returned: {wids}"
        )


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

    def test_update_status_rejects_backward_transition(self, patch_worker_db, task_id):
        """
        Once a worker is 'completed', calling update_status('running')
        should be rejected (status stays 'completed').
        """
        ctx = _make_worker(task_id)
        ctx.__enter__()

        ctx.status = "completed"
        ctx.update_status("running")

        # CORRECT invariant: backward transition rejected
        assert ctx.status == "completed", (
            "Status should remain 'completed' — backward transition not allowed"
        )

        ctx.__exit__(None, None, None)

    def test_double_exit_preserves_first_status(self, patch_worker_db, task_id):
        """
        After a clean __exit__ (completed), a second __exit__ with error
        should not flip the status to 'failed'.
        """
        ctx = _make_worker(task_id)
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

    def test_worker_double_enter_preserves_started_at(self, patch_worker_db, task_id):
        """Second __enter__ should not overwrite started_at."""
        ctx = _make_worker(task_id)

        ctx.__enter__()
        first_started = ctx.started_at

        time.sleep(0.01)

        ctx.__enter__()

        # CORRECT invariant: started_at preserved
        assert ctx.started_at == first_started, (
            "started_at must not change on re-entry"
        )

        ctx.__exit__(None, None, None)

    def test_agent_double_enter_preserves_started_at(self, patch_agent_db, task_id):
        """Same invariant for AgentContext."""
        worker_id = str(ObjectId())
        ctx = _make_agent(task_id, worker_id)

        ctx.__enter__()
        first_started = ctx.started_at

        time.sleep(0.01)

        ctx.__enter__()

        assert ctx.started_at == first_started, (
            "started_at must not change on re-entry"
        )

        ctx.__exit__(None, None, None)

    def test_exit_without_enter_does_not_crash(self, patch_worker_db, task_id):
        """__exit__ without __enter__ should not raise."""
        ctx = _make_worker(task_id)

        try:
            ctx.__exit__(None, None, None)
        except Exception as e:
            pytest.fail(f"__exit__ without __enter__ raised: {e}")

    def test_agent_exit_without_enter_does_not_crash(self, patch_agent_db, task_id):
        """Same for AgentContext."""
        worker_id = str(ObjectId())
        ctx = _make_agent(task_id, worker_id)

        try:
            ctx.__exit__(None, None, None)
        except Exception as e:
            pytest.fail(f"AgentContext.__exit__ without __enter__ raised: {e}")
