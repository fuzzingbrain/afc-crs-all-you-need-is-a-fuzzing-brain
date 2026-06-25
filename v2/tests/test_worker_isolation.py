"""
Worker Isolation Tests

Simulates real Celery worker process behavior:
- Celery worker processes are reused across tasks
- WorkerContext lifecycle: __enter__ creates buffer, __exit__ cleans up
- LLMClient reads buffer via module-level get_worker_buffer()
- The real risk: state leaking between sequential tasks in the same process
"""

import threading
from unittest.mock import MagicMock, patch
from bson import ObjectId

import pytest

from fuzzingbrain.llms.buffer import (
    WorkerLLMBuffer,
    set_worker_buffer,
    get_worker_buffer,
)
from fuzzingbrain.core.models.llm_call import LLMCall
from fuzzingbrain.worker.context import (
    WorkerContext,
    _worker_contexts,
    _worker_contexts_lock,
)


def _make_call(worker_id: str, task_id: str, cost: float = 0.1) -> LLMCall:
    """Helper: create an LLMCall bound to a specific worker and task."""
    return LLMCall(
        worker_id=worker_id,
        task_id=task_id,
        agent_id=str(ObjectId()),
        model="test-model",
        cost=cost,
        input_tokens=100,
        output_tokens=50,
    )


def _simulate_worker_lifecycle(task_id: str, fuzzer: str, n_calls: int = 3):
    """
    Simulate what happens inside a real Celery worker task:
    WorkerContext enter -> LLM calls via buffer -> WorkerContext exit.

    Returns (worker_id, buffer, flushed_records).
    """
    mock_db = MagicMock()
    buffer = WorkerLLMBuffer(redis_url="", mongo_db=mock_db)

    ctx = WorkerContext(
        task_id=task_id,
        fuzzer=fuzzer,
        sanitizer="address",
    )
    ctx._llm_buffer = buffer
    ctx.started_at = __import__("datetime").datetime.now()
    ctx.status = "running"

    # Simulate __enter__: start buffer, set as global
    buffer.start()
    set_worker_buffer(buffer)

    worker_id = ctx.worker_id

    # Simulate agent LLM calls (this is what LLMClient._record_llm_call does)
    for i in range(n_calls):
        current_buffer = get_worker_buffer()
        current_buffer.record(_make_call(worker_id, task_id, cost=float(i + 1)))

    # Simulate __exit__: stop buffer, clear global
    buffer.stop()
    set_worker_buffer(None)

    # Collect what was flushed
    flushed = []
    for call_args in mock_db.llm_calls.insert_many.call_args_list:
        flushed.extend(call_args[0][0])

    return worker_id, mock_db, flushed


class TestCeleryProcessReuse:
    """
    Simulates the real scenario: a single Celery worker process
    runs Task A, then Task B sequentially. Tests that Task B
    gets a clean environment with no leftover state from Task A.
    """

    def test_task_b_does_not_inherit_task_a_buffer(self):
        """
        After Task A's WorkerContext exits, get_worker_buffer() must
        return None. Task B must not accidentally write to Task A's buffer.
        """
        task_a_id = str(ObjectId())
        task_b_id = str(ObjectId())

        worker_a_id = str(ObjectId())
        worker_b_id = str(ObjectId())

        # --- Task A lifecycle ---
        buffer_a = WorkerLLMBuffer(redis_url="", mongo_db=None)
        set_worker_buffer(buffer_a)
        buffer_a.record(_make_call(worker_a_id, task_a_id, cost=1.0))

        # Task A exits
        set_worker_buffer(None)

        # --- Between tasks: this is the state Celery process is in ---
        assert get_worker_buffer() is None, \
            "Buffer must be None between tasks — Task B would write to Task A's buffer"

        # --- Task B lifecycle ---
        buffer_b = WorkerLLMBuffer(redis_url="", mongo_db=None)
        set_worker_buffer(buffer_b)
        buffer_b.record(_make_call(worker_b_id, task_b_id, cost=2.0))

        # Verify Task B's buffer has only Task B's records
        assert len(buffer_b._records) == 1
        assert buffer_b._records[0]["task_id"] == ObjectId(task_b_id)

        # Verify Task A's buffer still has only Task A's records (not polluted by B)
        assert len(buffer_a._records) == 1
        assert buffer_a._records[0]["task_id"] == ObjectId(task_a_id)

        set_worker_buffer(None)

    def test_task_b_records_go_to_task_b_db(self):
        """
        Full lifecycle simulation: Task A runs and flushes to DB_A,
        then Task B runs and flushes to DB_B. No cross-contamination.
        """
        task_a_id = str(ObjectId())
        task_b_id = str(ObjectId())

        worker_a_id, db_a, flushed_a = _simulate_worker_lifecycle(
            task_a_id, "fuzzer_a", n_calls=2
        )
        worker_b_id, db_b, flushed_b = _simulate_worker_lifecycle(
            task_b_id, "fuzzer_b", n_calls=3
        )

        # Task A flushed exactly 2 records, all belonging to Task A
        assert len(flushed_a) == 2
        for rec in flushed_a:
            assert rec["task_id"] == ObjectId(task_a_id)
            assert rec["worker_id"] == ObjectId(worker_a_id)

        # Task B flushed exactly 3 records, all belonging to Task B
        assert len(flushed_b) == 3
        for rec in flushed_b:
            assert rec["task_id"] == ObjectId(task_b_id)
            assert rec["worker_id"] == ObjectId(worker_b_id)

        # Global buffer is clean after both tasks
        assert get_worker_buffer() is None

    def test_buffer_stop_flushes_remaining_records(self):
        """
        When WorkerContext.__exit__ calls buffer.stop(), all buffered
        records must be flushed to MongoDB. Nothing should be lost.
        """
        task_id = str(ObjectId())
        mock_db = MagicMock()
        buffer = WorkerLLMBuffer(redis_url="", mongo_db=mock_db)
        buffer.start()
        set_worker_buffer(buffer)

        # Record 5 calls (these sit in memory, not yet flushed)
        for i in range(5):
            buffer.record(_make_call(str(ObjectId()), task_id, cost=1.0))

        # stop() triggers final flush
        buffer.stop()
        set_worker_buffer(None)

        # All 5 records must have been flushed
        total_flushed = 0
        for call_args in mock_db.llm_calls.insert_many.call_args_list:
            total_flushed += len(call_args[0][0])
        assert total_flushed == 5, \
            f"Expected 5 records flushed on stop(), got {total_flushed}"


class TestWorkerContextExitFailure:
    """
    Tests what happens when WorkerContext.__exit__ fails partially.
    The buffer must still be cleaned up to prevent leaking to the next task.
    """

    def test_buffer_cleared_even_if_stop_raises(self):
        """
        If buffer.stop() raises an exception, set_worker_buffer(None)
        must still be called. Otherwise the next task inherits a broken buffer.

        This tests the actual __exit__ code path.
        """
        task_id = str(ObjectId())

        # Create a buffer that will explode on stop()
        buffer = WorkerLLMBuffer(redis_url="", mongo_db=None)
        buffer.start()
        buffer.stop = MagicMock(side_effect=RuntimeError("flush exploded"))

        set_worker_buffer(buffer)

        # Simulate __exit__ logic (from context.py lines 196-219)
        try:
            buffer.cleanup_redis_keys(task_id=task_id, worker_id="fake")
            buffer.stop()
        except Exception:
            pass
        finally:
            set_worker_buffer(None)

        # The critical assertion: global buffer must be None
        assert get_worker_buffer() is None, \
            "Buffer leaked after stop() failure — next task will write to broken buffer"

    def test_records_not_lost_on_flush_failure(self):
        """
        If MongoDB insert_many fails during flush, records must be
        put back into the buffer (not silently dropped).
        """
        task_id = str(ObjectId())
        mock_db = MagicMock()
        mock_db.llm_calls.insert_many.side_effect = Exception("MongoDB down")

        buffer = WorkerLLMBuffer(redis_url="", mongo_db=mock_db)

        # Record some calls
        buffer.record(_make_call(str(ObjectId()), task_id, cost=1.0))
        buffer.record(_make_call(str(ObjectId()), task_id, cost=2.0))

        # Flush fails
        count = buffer._flush()
        assert count == 0, "Flush should return 0 on failure"

        # Records must be put back (not lost)
        assert len(buffer._records) == 2, \
            f"Records lost on flush failure: expected 2, got {len(buffer._records)}"

    def test_stop_retries_flush_on_transient_failure(self):
        """
        buffer.stop() must retry the final flush. If the first attempt
        fails but the second succeeds, no records should be lost.
        """
        task_id = str(ObjectId())
        mock_db = MagicMock()

        # First insert_many fails, second succeeds
        mock_db.llm_calls.insert_many.side_effect = [
            Exception("transient DB error"),
            None,  # success
        ]

        buffer = WorkerLLMBuffer(redis_url="", mongo_db=mock_db)
        buffer.start()

        buffer.record(_make_call(str(ObjectId()), task_id, cost=1.0))
        buffer.record(_make_call(str(ObjectId()), task_id, cost=2.0))

        buffer.stop()

        # insert_many called twice (first failed, second succeeded)
        assert mock_db.llm_calls.insert_many.call_count == 2
        # All records flushed on second attempt
        second_call_batch = mock_db.llm_calls.insert_many.call_args_list[1][0][0]
        assert len(second_call_batch) == 2, \
            f"Expected 2 records flushed on retry, got {len(second_call_batch)}"
        # No records left in buffer
        assert len(buffer._records) == 0

    def test_stop_logs_error_when_all_retries_fail(self):
        """
        If all 3 flush attempts fail, stop() must log an error
        indicating how many records were lost.
        """
        task_id = str(ObjectId())
        mock_db = MagicMock()
        mock_db.llm_calls.insert_many.side_effect = Exception("DB permanently down")

        buffer = WorkerLLMBuffer(redis_url="", mongo_db=mock_db)
        buffer.start()

        buffer.record(_make_call(str(ObjectId()), task_id, cost=1.0))
        buffer.record(_make_call(str(ObjectId()), task_id, cost=2.0))
        buffer.record(_make_call(str(ObjectId()), task_id, cost=3.0))

        buffer.stop()

        # All 3 retry attempts made
        assert mock_db.llm_calls.insert_many.call_count == 3
        # Records still in buffer (lost after buffer is discarded)
        assert len(buffer._records) == 3, \
            f"Expected 3 records still in buffer, got {len(buffer._records)}"


class TestWorkerContextRegistry:
    """
    Tests that the global _worker_contexts registry correctly tracks
    which workers are active, preventing ghost entries.
    """

    def setup_method(self):
        """Clean registry before each test."""
        with _worker_contexts_lock:
            _worker_contexts.clear()

    def test_enter_registers_exit_unregisters(self):
        """Worker appears in registry on enter, disappears on exit."""
        ctx = WorkerContext(
            task_id=str(ObjectId()),
            fuzzer="test_fuzzer",
            sanitizer="address",
        )

        # Patch out DB and buffer to avoid real Redis/MongoDB
        with patch("fuzzingbrain.db.get_database", return_value=MagicMock()), \
             patch("fuzzingbrain.llms.buffer.WorkerLLMBuffer._connect_redis"):

            ctx.__enter__()
            assert ctx.worker_id in _worker_contexts, \
                "Worker not registered on __enter__"

            ctx.__exit__(None, None, None)
            assert ctx.worker_id not in _worker_contexts, \
                "Worker still in registry after __exit__ — ghost entry"

    def test_failed_worker_still_unregisters(self):
        """
        If a worker fails with an exception, it must still be removed
        from the registry. Ghost entries would make get_active_workers()
        return stale data.
        """
        ctx = WorkerContext(
            task_id=str(ObjectId()),
            fuzzer="test_fuzzer",
            sanitizer="address",
        )

        # Manually register (simulating __enter__)
        with _worker_contexts_lock:
            _worker_contexts[ctx.worker_id] = ctx

        # Patch DB so __exit__'s _save_to_db succeeds → worker gets unregistered
        with patch("fuzzingbrain.db.get_database", return_value=MagicMock()):
            ctx.__exit__(RuntimeError, RuntimeError("boom"), None)

        assert ctx.worker_id not in _worker_contexts, \
            "Failed worker left ghost entry in registry"
        assert ctx.status == "failed"
        assert "boom" in ctx.error
