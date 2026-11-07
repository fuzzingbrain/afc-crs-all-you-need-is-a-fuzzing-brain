# SPDX-License-Identifier: Apache-2.0
"""
Analysis Client SDK

Client for communicating with the Analysis Server.
Used by Workers and Agents to query code analysis data.
"""

import socket
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .protocol import (
    Request,
    Response,
    Method,
    encode_message,
    decode_message,
    MESSAGE_DELIMITER,
    MAX_MESSAGE_SIZE,
)


class AnalysisClient:
    """
    Client for querying the Analysis Server.

    Usage:
        client = AnalysisClient("/path/to/run/analyzer.sock")
        func = client.get_function("png_read_info")
        callees = client.get_callees("png_read_info")
    """

    def __init__(
        self,
        socket_path: str,
        timeout: float = 30.0,
        client_id: str = None,
        harness: Optional[str] = None,
    ):
        """
        Initialize client.

        Args:
            socket_path: Path to Unix socket
            timeout: Request timeout in seconds
            client_id: Identifier for this client (e.g., "controller", "worker_fuzzer_address")
        """
        self.socket_path = Path(socket_path)
        self.timeout = timeout
        self.client_id = client_id
        # Graph queries are answered for this harness (what it reaches).
        self.harness = harness
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()  # Serialize access to socket

    def _connect(self):
        """Connect to server if not connected."""
        # Check if existing socket is still valid
        if self._sock is not None:
            try:
                fd = self._sock.fileno()
                if fd < 0:
                    self._disconnect()
                else:
                    return
            except (OSError, socket.error):
                self._disconnect()

        if not self.socket_path.exists():
            raise ConnectionError(f"Socket not found: {self.socket_path}")

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(self.timeout)
        self._sock.connect(str(self.socket_path))

    def _disconnect(self):
        """Disconnect from server."""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _request(self, method: str, params: Dict[str, Any] = None) -> Any:
        """
        Send request and get response.

        Thread-safe: uses a lock to prevent concurrent access to the socket.
        Without this lock, parallel tool calls from the same agent (via
        asyncio.to_thread) could race on recv(), causing response swapping
        (e.g., create_vulnerability_hypothesis gets a str from get_function_source).

        Args:
            method: RPC method name
            params: Method parameters

        Returns:
            Response data

        Raises:
            ConnectionError: If connection fails
            TimeoutError: If request times out
            RuntimeError: If request fails
        """
        request = Request(
            method=method,
            params=params or {},
            source=self.client_id,
            harness=self.harness,
        )

        with self._lock:
            try:
                self._connect()

                # Send request
                self._sock.sendall(encode_message(request.to_json()))

                # Receive response
                data = b""
                while MESSAGE_DELIMITER not in data:
                    chunk = self._sock.recv(4096)
                    if not chunk:
                        raise ConnectionError("Connection closed")
                    data += chunk
                    if len(data) > MAX_MESSAGE_SIZE:
                        raise RuntimeError("Response too large")

                raw_msg = decode_message(data)
                response = Response.from_json(raw_msg)

                if not response.success:
                    raise RuntimeError(response.error or "Request failed")

                return response.data

            except socket.timeout:
                self._disconnect()
                raise TimeoutError(f"Request timed out: {method}")
            except Exception:
                self._disconnect()
                raise

    def close(self):
        """Close the connection."""
        self._disconnect()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # =========================================================================
    # Server control
    # =========================================================================

    def ping(self) -> bool:
        """Check if server is alive."""
        try:
            result = self._request(Method.PING)
            return result == "pong"
        except Exception:
            return False

    def get_status(self) -> dict:
        """Get server status."""
        return self._request(Method.GET_STATUS)

    def shutdown(self):
        """Request server shutdown."""
        try:
            self._request(Method.SHUTDOWN)
        except Exception:
            pass  # Server may close connection immediately

    # =========================================================================
    # Function queries
    # =========================================================================

    def get_function(self, name: str) -> Optional[dict]:
        """
        Get function by name.

        Args:
            name: Function name

        Returns:
            Function info dict or None if not found
        """
        return self._request(Method.GET_FUNCTION, {"name": name})

    def get_functions_by_file(self, file_path: str) -> List[dict]:
        """
        Get all functions in a file.

        Args:
            file_path: File path (can be partial)

        Returns:
            List of function info dicts
        """
        return self._request(Method.GET_FUNCTIONS_BY_FILE, {"file_path": file_path})

    def search_functions(self, pattern: str, limit: int = 50) -> List[dict]:
        """
        Search functions by name pattern.

        Args:
            pattern: Regex pattern to match function names
            limit: Maximum results to return

        Returns:
            List of matching function info dicts
        """
        return self._request(
            Method.SEARCH_FUNCTIONS, {"pattern": pattern, "limit": limit}
        )

    def get_function_source(self, name: str) -> Optional[str]:
        """
        Get function source code.

        Args:
            name: Function name

        Returns:
            Source code string or None
        """
        return self._request(Method.GET_FUNCTION_SOURCE, {"name": name})

    # =========================================================================
    # Call graph queries
    # =========================================================================

    def get_callers(self, function: str) -> List[str]:
        """
        Get functions that call the given function.

        Args:
            function: Function name

        Returns:
            List of caller function names
        """
        return self._request(Method.GET_CALLERS, {"function": function})

    def get_callees(self, function: str) -> List[str]:
        """
        Get functions called by the given function.

        Args:
            function: Function name

        Returns:
            List of callee function names
        """
        return self._request(Method.GET_CALLEES, {"function": function})

    def get_call_graph(self, fuzzer: str, depth: int = 3) -> Dict[str, List[str]]:
        """
        Get call graph for a fuzzer.

        Args:
            fuzzer: Fuzzer entry point function
            depth: Maximum depth to traverse

        Returns:
            Dict mapping function names to their callees
        """
        return self._request(Method.GET_CALL_GRAPH, {"fuzzer": fuzzer, "depth": depth})

    def find_all_paths(
        self,
        func1: str,
        func2: str,
        max_depth: int = 10,
        max_paths: int = 100,
    ) -> dict:
        """
        Find all call paths from func1 to func2.

        Args:
            func1: Start function (e.g., fuzzer entry point)
            func2: End function (target function)
            max_depth: Maximum path length (default 10)
            max_paths: Maximum number of paths to return (default 100)

        Returns:
            {
                "func1": str,
                "func2": str,
                "max_depth": int,
                "path_count": int,
                "paths": [[func1, ..., func2], ...],
                "truncated": bool,
                "cached": bool,
            }
        """
        return self._request(
            Method.FIND_ALL_PATHS,
            {
                "func1": func1,
                "func2": func2,
                "max_depth": max_depth,
                "max_paths": max_paths,
            },
        )

    # =========================================================================
    # Reachability queries
    # =========================================================================

    def get_reachability(self, fuzzer: str, function: str) -> dict:
        """
        Check if function is reachable from fuzzer.

        Args:
            fuzzer: Fuzzer name
            function: Target function name

        Returns:
            Dict with 'reachable' (bool) and 'distance' (int) if reachable
        """
        return self._request(
            Method.GET_REACHABILITY, {"fuzzer": fuzzer, "function": function}
        )

    def is_reachable(self, fuzzer: str, function: str) -> bool:
        """
        Check if function is reachable from fuzzer.

        Args:
            fuzzer: Fuzzer name
            function: Target function name

        Returns:
            True if reachable
        """
        result = self.get_reachability(fuzzer, function)
        return result.get("reachable", False)

    def get_reachable_functions(self, fuzzer: str) -> List[str]:
        """
        Get all functions reachable from fuzzer.

        Args:
            fuzzer: Fuzzer name

        Returns:
            List of reachable function names
        """
        return self._request(Method.GET_REACHABLE_FUNCTIONS, {"fuzzer": fuzzer})

    def get_unreached_functions(self, fuzzer: str) -> List[str]:
        """
        Get functions not yet reached by fuzzer.

        Useful for coverage guidance.

        Args:
            fuzzer: Fuzzer name

        Returns:
            List of unreached function names
        """
        return self._request(Method.GET_UNREACHED_FUNCTIONS, {"fuzzer": fuzzer})

    # =========================================================================
    # Build info
    # =========================================================================

    def get_fuzzers(self) -> List[dict]:
        """
        Get list of built fuzzers.

        Returns:
            List of fuzzer info dicts
        """
        return self._request(Method.GET_FUZZERS)

    def get_fuzzer_source(self, fuzzer_name: str) -> dict:
        """
        Get fuzzer/harness source code.

        Args:
            fuzzer_name: Name of the fuzzer (e.g., 'libpng_read_fuzzer')

        Returns:
            Dict with fuzzer name, source_path, and source code content
        """
        return self._request(Method.GET_FUZZER_SOURCE, {"fuzzer_name": fuzzer_name})

    def get_build_paths(self) -> Dict[str, str]:
        """
        Get build output paths.

        Returns:
            Dict mapping sanitizer names to build paths
        """
        return self._request(Method.GET_BUILD_PATHS)


def connect(
    socket_path: str, timeout: float = 30.0, client_id: str = None
) -> AnalysisClient:
    """
    Create and connect to Analysis Server.

    Args:
        socket_path: Path to Unix socket
        timeout: Request timeout in seconds
        client_id: Identifier for this client

    Returns:
        Connected AnalysisClient
    """
    client = AnalysisClient(socket_path, timeout, client_id=client_id)
    if not client.ping():
        raise ConnectionError(f"Cannot connect to Analysis Server at {socket_path}")
    return client


def wait_for_server(
    socket_path: str,
    timeout: float = 300.0,
    poll_interval: float = 1.0,
    client_id: str = None,
) -> AnalysisClient:
    """
    Wait for Analysis Server to become available.

    Args:
        socket_path: Path to Unix socket
        timeout: Maximum time to wait in seconds
        poll_interval: Time between connection attempts
        client_id: Identifier for this client

    Returns:
        Connected AnalysisClient

    Raises:
        TimeoutError: If server doesn't become available within timeout
    """
    import time

    start = time.time()

    while time.time() - start < timeout:
        try:
            client = AnalysisClient(socket_path, client_id=client_id)
            if client.ping():
                return client
        except Exception:
            pass
        time.sleep(poll_interval)

    raise TimeoutError(f"Analysis Server not available after {timeout}s: {socket_path}")
