# SPDX-License-Identifier: Apache-2.0
"""
LLM call buffer: one per worker process.

    LLM call  -> Redis INCRBYFLOAT (the run's cost, read by the budget check)
              -> memory (the call, its messages, its tool calls)
              -> PostgreSQL every FLUSH_INTERVAL seconds, from a daemon thread

A call's messages are stored once per run, keyed by their sha256
(llm_messages); the call keeps the list of ids it sent (llm_calls). A tool
call names the LLM call that asked for it by the key record() returned, which
the flush turns into the llm_calls id.
"""

import itertools
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from ..db.store import as_uuid, message_sha256


def _message(m: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
    return message_sha256(m), str(m.get("role") or "user"), m


class WorkerLLMBuffer:
    """Thread-safe: record() and record_tool_call() may come from any thread."""

    FLUSH_INTERVAL = 2.0
    COUNTER_PREFIX = "fuzzingbrain:counters"

    def __init__(self, redis_url: Optional[str], store):
        self.redis_url = redis_url
        self.store = store
        self._redis = None
        self._keys = itertools.count(1)
        # (key, row, input messages, output message)
        self._calls: List[Tuple[int, Dict[str, Any], list, Optional[tuple]]] = []
        self._tools: List[Tuple[int, Dict[str, Any], Optional[tuple]]] = []
        # key -> llm_calls id, for tool calls that arrive after their call flushed
        self._call_ids: Dict[int, int] = {}
        self._call_runs: Dict[int, str] = {}
        # sha256 -> llm_messages id, per run: a known message is not sent again
        self._message_ids: Dict[Tuple[str, str], int] = {}
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._stop = threading.Event()

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        if self._running:
            return
        self._connect_redis()
        self._running = True
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="llm-buffer-flush", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the thread and flush what is left (three tries)."""
        if not self._running:
            return
        self._running = False
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        for attempt in range(3):
            self.flush()
            with self._lock:
                left = len(self._calls) + len(self._tools)
            if not left:
                break
            time.sleep(0.5 * (attempt + 1))
        with self._lock:
            if self._calls or self._tools:
                logger.error(
                    f"LLM buffer: {len(self._calls)} calls and {len(self._tools)} "
                    f"tool calls could not be written"
                )
        if self._redis:
            try:
                self._redis.close()
            except Exception:
                pass
            self._redis = None

    def _connect_redis(self) -> None:
        if not self.redis_url:
            return
        try:
            import redis as sync_redis

            self._redis = sync_redis.Redis.from_url(
                self.redis_url, decode_responses=True, socket_connect_timeout=5
            )
            self._redis.ping()
        except Exception as e:
            logger.warning(f"LLM buffer: no Redis ({e}); the budget reads PostgreSQL only")
            self._redis = None

    def _loop(self) -> None:
        while not self._stop.wait(timeout=self.FLUSH_INTERVAL):
            try:
                self.flush()
            except Exception as e:
                logger.error(f"LLM buffer flush failed: {e}")

    # -------------------------------------------------------------- record

    def record(
        self,
        row: Dict[str, Any],
        messages: Optional[List[Dict[str, Any]]] = None,
        output: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Queue one llm_calls row; returns the key its tool calls refer to.

        `row` holds the llm_calls columns except id, the message ids and
        created_at; `messages` is what was sent, `output` the reply message.
        """
        cost = float(row.get("cost") or 0)
        run_id = row.get("run_id")
        if self._redis and cost > 0 and run_id:
            try:
                pipe = self._redis.pipeline(transaction=False)
                pipe.incrbyfloat(f"{self.COUNTER_PREFIX}:run:{run_id}:cost", cost)
                pipe.incr(f"{self.COUNTER_PREFIX}:run:{run_id}:calls")
                pipe.execute()
            except Exception as e:
                logger.warning(f"Redis cost update failed: {e}")
        key = next(self._keys)
        ins = [_message(m) for m in (messages or [])]
        out = _message(output) if output else None
        with self._lock:
            self._calls.append((key, dict(row), ins, out))
            self._call_runs[key] = str(run_id)
        return key

    def record_tool_call(
        self,
        call_key: int,
        tool_name: str,
        success: bool,
        latency_ms: int,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Queue one tool_calls row for the LLM call `call_key` asked for."""
        row = {
            "tool_name": tool_name,
            "success": bool(success),
            "error": (error or None) if not success else None,
            "latency_ms": max(int(latency_ms), 0),
        }
        with self._lock:
            self._tools.append((call_key, row, _message(result) if result else None))

    # --------------------------------------------------------------- flush

    def flush(self) -> int:
        """Write what is queued; on a failure the batch goes back in the queue."""
        if self.store is None:
            return 0
        with self._flush_lock:
            with self._lock:
                calls, self._calls = self._calls, []
                tools, self._tools = self._tools, []
            if not calls and not tools:
                return 0
            try:
                self._write(calls, tools)
            except Exception as e:
                logger.error(f"LLM buffer: write failed, will retry: {e}")
                with self._lock:
                    self._calls = calls + self._calls
                    self._tools = tools + self._tools
                return 0
            return len(calls) + len(tools)

    def _resolve(self, run_id, msgs: List[tuple]) -> None:
        """Make sure every message in `msgs` has an id in _message_ids."""
        rid = str(run_id)
        new = [m for m in msgs if (rid, m[0]) not in self._message_ids]
        if not new:
            return
        got = self.store.message_ids(run_id, new)
        for sha, mid in got.items():
            self._message_ids[(rid, sha)] = mid

    def _write(self, calls, tools) -> None:
        by_run: Dict[str, List[tuple]] = {}
        for key, row, ins, out in calls:
            by_run.setdefault(str(row["run_id"]), []).extend(ins + ([out] if out else []))
        for rid, msgs in by_run.items():
            self._resolve(rid, msgs)
        rows = []
        for key, row, ins, out in calls:
            rid = str(row["run_id"])
            r = dict(row)
            r["run_id"] = as_uuid(r["run_id"])
            r["worker_id"] = as_uuid(r.get("worker_id"))
            r["agent_id"] = as_uuid(r.get("agent_id"))
            r["input_message_ids"] = [self._message_ids[(rid, m[0])] for m in ins]
            r["output_message_id"] = self._message_ids[(rid, out[0])] if out else None
            rows.append(r)
        ids = self.store.insert_llm_calls(rows)
        for (key, _, _, _), cid in zip(calls, ids):
            self._call_ids[key] = cid

        ready, waiting = [], []
        for t in tools:
            (ready if t[0] in self._call_ids else waiting).append(t)
        if waiting:
            # Their call is not written yet: it is still queued.
            with self._lock:
                self._tools = waiting + self._tools
        if not ready:
            return
        results: Dict[str, List[tuple]] = {}
        for key, _, res in ready:
            if res is not None:
                results.setdefault(self._call_runs[key], []).append(res)
        for rid, msgs in results.items():
            self._resolve(rid, msgs)
        tool_rows = []
        for key, row, res in ready:
            r = dict(row)
            r["llm_call_id"] = self._call_ids[key]
            r["run_id"] = as_uuid(self._call_runs[key])
            r["result_message_id"] = None
            if res is not None:
                r["result_message_id"] = self._message_ids.get((self._call_runs[key], res[0]))
            tool_rows.append(r)
        self.store.insert_tool_calls(tool_rows)


# ------------------------------------------------- the process's buffer

_current_buffer: Optional[WorkerLLMBuffer] = None


def get_worker_buffer() -> Optional[WorkerLLMBuffer]:
    return _current_buffer


def set_worker_buffer(buffer: Optional[WorkerLLMBuffer]) -> None:
    global _current_buffer
    _current_buffer = buffer


def ensure_buffer(store=None, redis_url: Optional[str] = None) -> WorkerLLMBuffer:
    """The process's buffer, started on first use (the controller's calls too)."""
    global _current_buffer
    if _current_buffer is None:
        if store is None:
            from ..db.store import get_store

            store = get_store()
        _current_buffer = WorkerLLMBuffer(redis_url, store)
        _current_buffer.start()
    return _current_buffer
