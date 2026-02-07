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
        client = AnalysisClient("/path/to/task/analyzer.sock")
        func = client.get_function("png_read_info")
        callees = client.get_callees("png_read_info")
    """

    def __init__(self, socket_path: str, timeout: float = 30.0, client_id: str = None):
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
        (e.g., create_suspicious_point gets a str from get_function_source).

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
        request = Request(method=method, params=params or {}, source=self.client_id)

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

    # =========================================================================
    # Suspicious point operations
    # =========================================================================

    def create_suspicious_point(
        self,
        function_name: str,
        description: str,
        vuln_type: str,
        score: float = 0.0,
        important_controlflow: List[dict] = None,
        harness_name: str = "",
        sanitizer: str = "",
        direction_id: str = "",
        agent_id: str = "",
    ) -> dict:
        """
        Create a new suspicious point.

        Args:
            function_name: Name of the function containing the suspicious code
            description: Description of the potential vulnerability (use control flow, not line numbers)
            vuln_type: Type of vulnerability (buffer-overflow, use-after-free, etc.)
            score: Initial score (0.0-1.0)
            important_controlflow: List of related functions/variables
            harness_name: Fuzzer harness name that created this SP
            sanitizer: Sanitizer type (address, memory, undefined)
            direction_id: Direction ID that this SP belongs to
            agent_id: Agent ObjectId that created this SP

        Returns:
            Dict with 'id' and 'created' status
        """
        return self._request(
            Method.CREATE_SUSPICIOUS_POINT,
            {
                "function_name": function_name,
                "description": description,
                "vuln_type": vuln_type,
                "score": score,
                "important_controlflow": important_controlflow or [],
                "harness_name": harness_name,
                "sanitizer": sanitizer,
                "direction_id": direction_id,
                "agent_id": agent_id,
            },
        )

    def update_suspicious_point(
        self,
        sp_id: str,
        is_checked: bool = None,
        is_real: bool = None,
        is_important: bool = None,
        score: float = None,
        verification_notes: str = None,
        pov_guidance: str = None,
        reachability_status: str = None,
        reachability_multiplier: float = None,
        reachability_reason: str = None,
        agent_id: str = "",
    ) -> dict:
        """
        Update a suspicious point.

        Args:
            sp_id: Suspicious point ID
            is_checked: Whether verification is complete
            is_real: Whether it's a real vulnerability
            is_important: Whether it's high priority
            score: Updated score
            verification_notes: Notes from verification
            pov_guidance: Guidance for POV agent (input directions, what to watch for)
            reachability_status: Reachability status (direct, pointer_call, unreachable)
            reachability_multiplier: Score multiplier based on reachability (0.0-1.0)
            reachability_reason: Explanation for reachability determination
            agent_id: Agent ObjectId that verified this SP

        Returns:
            Dict with 'updated' status
        """
        params = {"id": sp_id}
        if is_checked is not None:
            params["is_checked"] = is_checked
        if is_real is not None:
            params["is_real"] = is_real
        if is_important is not None:
            params["is_important"] = is_important
        if score is not None:
            params["score"] = score
        if verification_notes is not None:
            params["verification_notes"] = verification_notes
        if pov_guidance is not None:
            params["pov_guidance"] = pov_guidance
        if reachability_status is not None:
            params["reachability_status"] = reachability_status
        if reachability_multiplier is not None:
            params["reachability_multiplier"] = reachability_multiplier
        if reachability_reason is not None:
            params["reachability_reason"] = reachability_reason
        if agent_id:
            params["agent_id"] = agent_id
        return self._request(Method.UPDATE_SUSPICIOUS_POINT, params)

    def list_suspicious_points(
        self,
        filter_unchecked: bool = False,
        filter_real: bool = False,
        filter_important: bool = False,
    ) -> dict:
        """
        List suspicious points with optional filters.

        Args:
            filter_unchecked: Only return unchecked points
            filter_real: Only return verified real vulnerabilities
            filter_important: Only return high priority points

        Returns:
            Dict with 'suspicious_points', 'count', and 'stats'
        """
        return self._request(
            Method.LIST_SUSPICIOUS_POINTS,
            {
                "filter_unchecked": filter_unchecked,
                "filter_real": filter_real,
                "filter_important": filter_important,
            },
        )

    def get_suspicious_point(self, sp_id: str) -> Optional[dict]:
        """
        Get a single suspicious point by ID.

        Args:
            sp_id: Suspicious point ID

        Returns:
            Suspicious point dict or None
        """
        return self._request(Method.GET_SUSPICIOUS_POINT, {"id": sp_id})

    # =========================================================================
    # Direction operations (Full-scan)
    # =========================================================================

    def create_direction(
        self,
        name: str,
        risk_level: str,
        risk_reason: str,
        core_functions: List[str],
        entry_functions: List[str] = None,
        call_chain_summary: str = "",
        code_summary: str = "",
        fuzzer: str = "",
    ) -> dict:
        """
        Create a new direction for Full-scan analysis.

        Args:
            name: Direction name (e.g., "Chunk Handlers")
            risk_level: Security risk level ("high", "medium", "low")
            risk_reason: Why this risk level was assigned
            core_functions: Main functions in this direction
            entry_functions: How fuzzer input reaches this direction
            call_chain_summary: Summary of call paths
            code_summary: Brief description of what this code does
            fuzzer: Fuzzer name

        Returns:
            {"id": "...", "created": True}
        """
        return self._request(
            Method.CREATE_DIRECTION,
            {
                "name": name,
                "risk_level": risk_level,
                "risk_reason": risk_reason,
                "core_functions": core_functions,
                "entry_functions": entry_functions or [],
                "call_chain_summary": call_chain_summary,
                "code_summary": code_summary,
                "fuzzer": fuzzer,
            },
        )

    def list_directions(
        self,
        fuzzer: str = None,
        status: str = None,
    ) -> dict:
        """
        List directions with optional filters.

        Args:
            fuzzer: Filter by fuzzer name
            status: Filter by status ("pending", "in_progress", "completed")

        Returns:
            {"directions": [...], "count": N, "stats": {...}}
        """
        params = {}
        if fuzzer:
            params["fuzzer"] = fuzzer
        if status:
            params["status"] = status
        return self._request(Method.LIST_DIRECTIONS, params)

    def get_direction(self, direction_id: str) -> Optional[dict]:
        """
        Get a single direction by ID.

        Args:
            direction_id: Direction ID

        Returns:
            Direction dict or None
        """
        return self._request(Method.GET_DIRECTION, {"id": direction_id})

    def claim_direction(self, fuzzer: str, processor_id: str) -> Optional[dict]:
        """
        Claim a pending direction for analysis.

        Args:
            fuzzer: Fuzzer name
            processor_id: ID of the agent claiming

        Returns:
            Claimed direction dict or None if none available
        """
        return self._request(
            Method.CLAIM_DIRECTION,
            {
                "fuzzer": fuzzer,
                "processor_id": processor_id,
            },
        )

    def complete_direction(
        self,
        direction_id: str,
        sp_count: int = 0,
        functions_analyzed: int = 0,
    ) -> dict:
        """
        Mark a direction as completed.

        Args:
            direction_id: Direction ID
            sp_count: Number of SPs found
            functions_analyzed: Number of functions analyzed

        Returns:
            {"updated": True}
        """
        return self._request(
            Method.COMPLETE_DIRECTION,
            {
                "id": direction_id,
                "sp_count": sp_count,
                "functions_analyzed": functions_analyzed,
            },
        )


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
