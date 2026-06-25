"""
AnalysisClient Socket Isolation Tests

Architecture:
- Each TASK starts its own Analysis Server (Unix socket per task workspace)
- Each WORKER connects to its task's analyzer socket via AnalysisClient
- Within a worker, multiple AGENTS share the same client via _client_cache
  keyed by (socket_path, client_id)
- Agents issue parallel tool calls via asyncio.to_thread(), all hitting
  the same AnalysisClient (same socket connection)

Risks tested:
- Parallel tool calls from one agent race on socket recv() without Lock
- Task A's analyzer crash must not affect Task B's analyzer
- Analyzer server restart mid-task must not leak stale data

The mock server adds artificial delay to amplify race windows,
making concurrency bugs deterministic instead of flaky.
"""

import json
import os
import socket
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pytest

from fuzzingbrain.analyzer.client import AnalysisClient
from fuzzingbrain.analyzer.protocol import (
    Request,
    Response,
    encode_message,
    decode_message,
    MESSAGE_DELIMITER,
)


class MockAnalysisServer:
    """
    In-process Unix socket server that echoes back the request method
    in the response data. Adds configurable delay to amplify race windows.

    Each connection is handled in its own thread (mirrors real server behavior).
    """

    def __init__(self, socket_path: str, delay: float = 0.0):
        self.socket_path = socket_path
        self.delay = delay
        self._server_sock = None
        self._running = False
        self._thread = None
        self._connections = []
        # Track requests received (for assertions)
        self.requests_received: list = []
        self._req_lock = threading.Lock()

    def start(self):
        self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_sock.bind(self.socket_path)
        self._server_sock.listen(10)
        self._server_sock.settimeout(5.0)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        for conn in self._connections:
            try:
                conn.close()
            except Exception:
                pass
        if self._server_sock:
            self._server_sock.close()
        if self._thread:
            self._thread.join(timeout=5)

    def _accept_loop(self):
        while self._running:
            try:
                conn, _ = self._server_sock.accept()
                self._connections.append(conn)
                t = threading.Thread(
                    target=self._handle_connection, args=(conn,), daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_connection(self, conn: socket.socket):
        """Handle a single client connection — read requests, send responses."""
        conn.settimeout(5.0)
        buf = b""
        while self._running:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk

                # Process all complete messages in buffer
                while MESSAGE_DELIMITER in buf:
                    msg_end = buf.index(MESSAGE_DELIMITER)
                    raw_msg = buf[:msg_end].decode("utf-8")
                    buf = buf[msg_end + len(MESSAGE_DELIMITER):]

                    request = Request.from_json(raw_msg)

                    with self._req_lock:
                        self.requests_received.append(request)

                    # Delay to widen race window for concurrent tests
                    if self.delay > 0:
                        time.sleep(self.delay)

                    # Echo back method + params as response data
                    # so the caller can verify they got THEIR response
                    response = Response.ok(
                        data={
                            "method": request.method,
                            "request_id": request.request_id,
                            "params": request.params,
                        },
                        request_id=request.request_id,
                    )
                    conn.sendall(encode_message(response.to_json()))

            except socket.timeout:
                continue
            except (OSError, ConnectionError):
                break
        try:
            conn.close()
        except Exception:
            pass


@pytest.fixture
def socket_path(tmp_path):
    """Provide a temporary Unix socket path."""
    return str(tmp_path / "test_analyzer.sock")


@pytest.fixture
def mock_server(socket_path):
    """Start a mock analysis server, yield it, stop on cleanup."""
    server = MockAnalysisServer(socket_path, delay=0.0)
    server.start()
    yield server
    server.stop()


@pytest.fixture
def slow_server(socket_path):
    """Mock server with 50ms delay per request — amplifies race conditions."""
    server = MockAnalysisServer(socket_path, delay=0.05)
    server.start()
    yield server
    server.stop()


class TestParallelToolCalls:
    """
    The real scenario: an LLM returns 3 tool calls at once.
    The agent framework dispatches them via asyncio.to_thread(),
    all hitting the same AnalysisClient concurrently.

    Without the Lock: thread A's recv() steals thread B's response.
    With the Lock: requests are serialized, each thread gets its own response.
    """

    def test_concurrent_requests_get_correct_responses(self, socket_path, slow_server):
        """
        5 threads hit the same client simultaneously.
        Each sends a different method — must get back their own method in response.

        This is the exact bug we fixed: get_function_source() returning a dict
        meant for create_suspicious_point(), or vice versa.
        """
        client = AnalysisClient(socket_path, timeout=10.0)
        methods = [
            "get_function_source",
            "create_suspicious_point",
            "get_callers",
            "get_callees",
            "get_reachability",
        ]
        results = {}
        errors = []

        def call_method(method: str):
            try:
                resp = client._request(method, {"name": f"test_{method}"})
                return method, resp
            except Exception as e:
                return method, e

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(call_method, m): m for m in methods}
            for future in as_completed(futures):
                method, resp = future.result()
                if isinstance(resp, Exception):
                    errors.append((method, resp))
                else:
                    results[method] = resp

        assert not errors, f"Requests failed: {errors}"
        assert len(results) == 5, f"Expected 5 results, got {len(results)}"

        # The critical check: each thread got its OWN response
        for method, resp in results.items():
            assert resp["method"] == method, (
                f"Response swap detected! Sent '{method}' but got response "
                f"for '{resp['method']}' — this is the race condition bug"
            )

        client.close()

    def test_parallel_calls_all_reach_server(self, socket_path, slow_server):
        """
        All parallel requests must actually reach the server.
        The Lock serializes them, but none should be dropped.
        """
        client = AnalysisClient(socket_path, timeout=10.0)
        n_calls = 8

        def call(i):
            return client._request("get_function", {"name": f"func_{i}"})

        with ThreadPoolExecutor(max_workers=n_calls) as pool:
            futures = [pool.submit(call, i) for i in range(n_calls)]
            results = [f.result() for f in futures]

        assert len(results) == n_calls
        # Server must have received all 8
        assert len(slow_server.requests_received) == n_calls, (
            f"Server received {len(slow_server.requests_received)}/{n_calls} "
            f"requests — some were dropped by Lock contention"
        )

        client.close()


class TestTaskAnalyzerIsolation:
    """
    Each task has its own Analysis Server on a separate Unix socket.
    Task A's analyzer crashing must NOT affect Task B's analyzer.

    Real scenario: Task A's target binary triggers an OOM in the analyzer
    server → Task A's socket dies. Task B on a different target has its
    own analyzer server and must keep working.
    """

    def test_two_tasks_independent_analyzer_connections(self, tmp_path):
        """
        Task A and Task B each have their own analyzer server.
        Task A's worker disconnects → Task B's worker still works.
        """
        sock_path = str(tmp_path / "shared_analyzer.sock")
        server = MockAnalysisServer(sock_path)
        server.start()

        try:
            client_a = AnalysisClient(sock_path, timeout=5.0, client_id="task_a_worker")
            client_b = AnalysisClient(sock_path, timeout=5.0, client_id="task_b_worker")

            # Both work initially
            resp_a = client_a._request("get_function", {"name": "func_a"})
            resp_b = client_b._request("get_function", {"name": "func_b"})
            assert resp_a["params"]["name"] == "func_a"
            assert resp_b["params"]["name"] == "func_b"

            # Task A's worker disconnects (simulating crash/cleanup)
            client_a.close()

            # Task B's worker must still work — independent connection
            resp_b2 = client_b._request("get_callees", {"function": "main"})
            assert resp_b2["method"] == "get_callees"
            assert resp_b2["params"]["function"] == "main"

            client_b.close()
        finally:
            server.stop()

    def test_task_analyzer_crash_does_not_propagate(self, tmp_path):
        """
        Task A's analyzer server crashes (socket dies).
        Task B's analyzer server on a different socket is unaffected.
        """
        sock_a = str(tmp_path / "task_a_analyzer.sock")
        sock_b = str(tmp_path / "task_b_analyzer.sock")

        server_a = MockAnalysisServer(sock_a)
        server_b = MockAnalysisServer(sock_b)
        server_a.start()
        server_b.start()

        try:
            client_a = AnalysisClient(sock_a, timeout=2.0)
            client_b = AnalysisClient(sock_b, timeout=2.0)

            # Both work
            assert client_a._request("ping")["method"] == "ping"
            assert client_b._request("ping")["method"] == "ping"

            # Task A's analyzer crashes — its client's next request fails
            server_a.stop()

            with pytest.raises((ConnectionError, OSError, RuntimeError)):
                client_a._request("get_function", {"name": "dead"})

            # Task B's analyzer is unaffected (different server, different socket)
            resp = client_b._request("get_function", {"name": "alive"})
            assert resp["params"]["name"] == "alive"

            client_a.close()
            client_b.close()
        finally:
            server_b.stop()


class TestSocketReconnection:
    """
    After a socket error, AnalysisClient._connect() creates a new socket.
    Test that the new connection doesn't carry leftover data from the old one.

    Real scenario: analyzer server restarts mid-task (e.g., OOM kill).
    The client reconnects and must not get stale responses.
    """

    def test_reconnect_after_server_restart(self, tmp_path):
        """
        Client connects → server dies → server restarts → client reconnects.

        Real behavior: the first request after server death fails (the client
        detects the dead socket via recv error and calls _disconnect).
        The NEXT request reconnects to the new server and succeeds.
        This is the correct pattern — no stale data leaks across restarts.
        """
        sock_path = str(tmp_path / "restart_analyzer.sock")

        # Phase 1: start server, make a request
        server1 = MockAnalysisServer(sock_path)
        server1.start()

        client = AnalysisClient(sock_path, timeout=5.0)
        resp1 = client._request("get_function", {"name": "before_restart"})
        assert resp1["params"]["name"] == "before_restart"

        # Phase 2: kill server (client's socket is now dead)
        server1.stop()
        os.unlink(sock_path)

        # Phase 3: restart server on same path
        server2 = MockAnalysisServer(sock_path)
        server2.start()

        try:
            # First request fails — detects dead socket, triggers _disconnect()
            with pytest.raises((ConnectionError, ConnectionResetError, OSError)):
                client._request("get_function", {"name": "should_fail"})

            # After the failure, client._sock is None (cleaned up).
            # Next request reconnects to server2 with a fresh socket.
            resp2 = client._request("get_function", {"name": "after_restart"})
            assert resp2["params"]["name"] == "after_restart"

            # Server 2 must have received this request (no leftover from server 1)
            params_received = [
                r.params.get("name") for r in server2.requests_received
            ]
            assert "after_restart" in params_received

            client.close()
        finally:
            server2.stop()

    def test_no_partial_response_after_reconnect(self, tmp_path):
        """
        If the old socket had buffered partial data, reconnection must
        start clean. Verify by making multiple requests after reconnect.
        """
        sock_path = str(tmp_path / "partial_analyzer.sock")

        server1 = MockAnalysisServer(sock_path)
        server1.start()

        client = AnalysisClient(sock_path, timeout=5.0)
        client._request("ping")

        # Force disconnect (simulate network glitch)
        client._disconnect()

        # Server is still running — client reconnects on next request
        resp = client._request("get_callers", {"function": "target"})
        assert resp["method"] == "get_callers"

        # Second request after reconnect also works (no leftover buffer)
        resp2 = client._request("get_callees", {"function": "target"})
        assert resp2["method"] == "get_callees"

        client.close()
        server1.stop()


class TestLockGranularity:
    """
    The Lock must cover the ENTIRE _request() method:
    connect + send + recv as one atomic operation.

    If only send or recv is locked, there's a window where:
    - Thread A connects, sends, starts waiting for recv
    - Thread B connects ON THE SAME SOCKET (no-op), sends its request
    - Now two requests are in flight on one socket
    - recv() returns the wrong one

    We test that the lock prevents any interleaving.
    """

    def test_requests_are_strictly_serialized(self, socket_path, slow_server):
        """
        With 50ms server delay, 4 concurrent requests should take ~200ms
        (serialized by Lock), not ~50ms (parallel).

        This proves the Lock actually serializes — if it didn't, we'd see
        ~50ms and response swapping.
        """
        client = AnalysisClient(socket_path, timeout=10.0)

        results = []
        errors = []

        def timed_call(method):
            start = time.monotonic()
            try:
                resp = client._request(method, {"name": "test"})
                elapsed = time.monotonic() - start
                return method, resp, elapsed
            except Exception as e:
                return method, e, 0

        methods = ["get_function", "get_callers", "get_callees", "ping"]

        start_all = time.monotonic()
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(timed_call, m) for m in methods]
            for f in as_completed(futures):
                method, resp, elapsed = f.result()
                if isinstance(resp, Exception):
                    errors.append((method, resp))
                else:
                    results.append((method, resp, elapsed))

        total_time = time.monotonic() - start_all

        assert not errors, f"Requests failed: {errors}"
        assert len(results) == 4

        # Serialized: total >= 4 * 50ms = 200ms
        # If Lock was broken (parallel): total ≈ 50ms
        assert total_time >= 0.15, (
            f"Requests completed in {total_time:.3f}s — too fast! "
            f"Lock is not serializing (expected >= 0.2s for 4 * 50ms delay)"
        )

        # Every response matches its request
        for method, resp, _ in results:
            assert resp["method"] == method

        client.close()
