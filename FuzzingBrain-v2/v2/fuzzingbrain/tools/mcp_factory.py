"""
MCP Server Factory

Creates isolated FastMCP server instances for each agent.
This prevents response mixing when multiple agents run concurrently.

Usage:
    from fuzzingbrain.tools.mcp_factory import create_isolated_mcp_server

    # Each agent gets its own MCP server
    mcp_server = create_isolated_mcp_server(agent_id="agent_1")
    async with Client(mcp_server) as client:
        result = await client.call_tool("get_function_source", {"function_name": "target_function"})
"""

from fastmcp import FastMCP
from typing import Any, Dict

from .utils import async_tool


def create_isolated_mcp_server(
    agent_id: str = "default",
    worker_id: str = None,
    include_pov_tools: bool = True,
    include_seed_tools: bool = False,
    include_sp_tools: bool = True,
    include_direction_tools: bool = True,
) -> FastMCP:
    """
    Create an isolated FastMCP server instance with all tools registered.

    Each agent should call this to get its own MCP server, preventing
    response mixing in concurrent execution.

    Args:
        agent_id: Unique identifier for this agent (used in server name)
        worker_id: Worker ID for context lookup (used by POV tools and seed tools)
        include_pov_tools: Whether to include POV tools (default True).
                          Set to False for SP/Verify agents that don't need POV tools.
        include_seed_tools: Whether to include seed generation tools (default False).
                           Set to True for SeedAgent. When True, SP/direction/POV tools
                           are excluded (SeedAgent only needs code analysis + create_seed).
        include_sp_tools: Whether to include suspicious point tools (default True).
                         Set to False for DirectionPlanningAgent.
        include_direction_tools: Whether to include direction tools (default True).
                                Set to False for agents that don't need directions.

    Returns:
        A new FastMCP instance with all tools registered
    """
    # Create a new FastMCP instance (NOT the singleton)
    mcp = FastMCP(f"FuzzingBrain-Tools-{agent_id}")

    # Register code analysis tools (always needed)
    _register_analyzer_tools(mcp)
    _register_code_viewer_tools(mcp)

    if include_seed_tools:
        # SeedAgent: only code analysis + create_seed
        # No SP, direction, POV, or coverage tools
        _register_seed_tools(mcp, worker_id=worker_id)
    else:
        # Register SP tools only if requested
        if include_sp_tools:
            _register_suspicious_point_tools(mcp)
        # Register direction tools only if requested
        if include_direction_tools:
            _register_direction_tools(mcp)
        if include_pov_tools:
            _register_pov_tools(mcp, worker_id=worker_id)
            _register_coverage_tools(mcp)

    return mcp


def _is_connection_error(e: Exception) -> bool:
    """Check if an exception is a connection-related error that should invalidate the client."""
    error_str = str(e).lower()
    connection_errors = [
        "bad file descriptor",
        "connection reset",
        "connection refused",
        "broken pipe",
        "connection closed",
        "[errno 9]",  # EBADF
        "[errno 104]",  # ECONNRESET
        "[errno 111]",  # ECONNREFUSED
    ]
    return any(err in error_str for err in connection_errors)


def _register_analyzer_tools(mcp: FastMCP) -> None:
    """Register analyzer tools (code analysis via Analysis Server)."""
    import time
    from loguru import logger

    # Import helper functions from analyzer module
    from .analyzer import (
        _get_client,
        _ensure_client,
        _client_cache,  # Thread-safe cache for debugging
        _invalidate_client,
        _analysis_socket_path,
        _client_id,
    )

    def _get_cache_key():
        """Get current cache key for client invalidation."""
        socket_path = _analysis_socket_path.get()
        client_id = _client_id.get()
        return (socket_path, client_id) if socket_path else None

    def _handle_client_error(e: Exception) -> Dict[str, Any]:
        """Handle client errors, invalidating cache if needed."""
        if _is_connection_error(e):
            cache_key = _get_cache_key()
            if cache_key:
                _invalidate_client(cache_key)
                logger.warning(f"Connection error, invalidated client cache: {e}")
        return {"success": False, "error": str(e)}

    @mcp.tool
    @async_tool
    def analyzer_status() -> Dict[str, Any]:
        """Get Analysis Server status."""
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            status = client.get_status()
            return {"success": True, "status": status}
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def get_function(function_name: str) -> Dict[str, Any]:
        """
        Get metadata about a function (file path, line numbers, complexity, parameters).

        Args:
            function_name: The exact name of the function to look up

        Returns:
            Function metadata: name, file_path, start_line, end_line, complexity, args, return_type
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            func = client.get_function(function_name)
            if func is None:
                return {
                    "success": False,
                    "error": f"Function '{function_name}' not found",
                }
            return {"success": True, "function": func}
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def get_functions_by_file(file_path: str) -> Dict[str, Any]:
        """
        Get all functions defined in a specific file.

        Args:
            file_path: File path (can be partial, e.g., "png.c")
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            functions = client.get_functions_by_file(file_path)
            total = len(functions)
            # Limit to 50 to save context
            return {
                "success": True,
                "count": total,
                "functions": functions[:50],
                "truncated": total > 50,
            }
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def search_functions(pattern: str, limit: int = 50) -> Dict[str, Any]:
        """
        Search for functions by name pattern.

        Args:
            pattern: Regex pattern to match function names
            limit: Maximum number of results
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            functions = client.search_functions(pattern, limit)
            return {
                "success": True,
                "pattern": pattern,
                "count": len(functions),
                "functions": functions,
            }
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def get_function_source(function_name: str) -> Dict[str, Any]:
        """
        Get the full source code of a function.

        Use this to read the implementation details of a specific function.
        For analyzing vulnerability patterns, always read the source code.

        Args:
            function_name: The exact name of the function

        Returns:
            source: The complete source code of the function
        """
        t0 = time.time()
        # Debug: Check cache state
        logger.debug(
            f"[TIMING] get_function_source({function_name}): cache_size={len(_client_cache)}"
        )

        err = _ensure_client()
        if err:
            return err
        t1 = time.time()
        try:
            client = _get_client()
            t2 = time.time()
            source = client.get_function_source(function_name)
            t3 = time.time()
            if source is None:
                return {
                    "success": False,
                    "error": f"Source not available for function '{function_name}'",
                }

            # Log timing if slow
            total = t3 - t0
            if total > 0.1:
                logger.debug(
                    f"[TIMING] get_function_source({function_name}): total={total:.3f}s ensure={t1 - t0:.3f}s get_client={t2 - t1:.3f}s query={t3 - t2:.3f}s"
                )

            return {"success": True, "function_name": function_name, "source": source}
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def get_callers(function_name: str) -> Dict[str, Any]:
        """
        Get all functions that call the specified function (who calls this function?).

        Use this to trace backwards in the call graph to understand how a function is reached.

        Args:
            function_name: The function to find callers for

        Returns:
            callers: List of function names that call this function
        """
        t0 = time.time()
        # Debug: Check cache state
        logger.debug(
            f"[TIMING] get_callers({function_name}): cache_size={len(_client_cache)}"
        )

        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            t1 = time.time()
            result = client.get_callers(function_name)
            t2 = time.time()
            callers = result.get("callers", []) if isinstance(result, dict) else result
            total = len(callers)

            # Log timing if slow
            if t2 - t0 > 0.1:
                logger.debug(
                    f"[TIMING] get_callers({function_name}): total={t2 - t0:.3f}s get_client={t1 - t0:.3f}s query={t2 - t1:.3f}s"
                )

            # Limit to 30 to save context
            return {
                "success": True,
                "count": total,
                "callers": callers[:30],
                "truncated": total > 30,
            }
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def get_callees(function_name: str) -> Dict[str, Any]:
        """
        Get all functions called by the specified function (what does this function call?).

        Use this to trace forwards in the call graph to understand what a function does.

        Args:
            function_name: The function to find callees for

        Returns:
            callees: List of function names called by this function
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            result = client.get_callees(function_name)
            callees = result.get("callees", []) if isinstance(result, dict) else result
            total = len(callees)
            # Limit to 30 to save context
            return {
                "success": True,
                "count": total,
                "callees": callees[:30],
                "truncated": total > 30,
            }
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def get_call_graph(fuzzer_name: str, depth: int = 3) -> Dict[str, Any]:
        """
        Get the call graph starting from a fuzzer entry point.

        Returns all functions reachable from the fuzzer up to the specified depth.

        Args:
            fuzzer_name: Name of the fuzzer
            depth: Maximum call depth to traverse (default: 3)

        Returns:
            call_graph: Dict mapping function names to their callees
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            graph = client.get_call_graph(fuzzer_name, depth)
            return {
                "success": True,
                "fuzzer_name": fuzzer_name,
                "depth": depth,
                "node_count": len(graph),
                "call_graph": graph,
            }
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def find_all_paths(
        from_function: str, to_function: str, max_depth: int = 10, max_paths: int = 20
    ) -> Dict[str, Any]:
        """
        Find all call paths from one function to another.

        Use this to understand how input flows from entry point to a target function.

        Args:
            from_function: Start function (e.g., fuzzer entry point)
            to_function: Target function to reach
            max_depth: Maximum path length (default: 10)
            max_paths: Maximum paths to return (default: 20)

        Returns:
            paths: List of function call chains from start to target
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            result = client.find_all_paths(
                from_function, to_function, max_depth, max_paths
            )
            paths = result.get("paths", [])
            return {"success": True, "path_count": len(paths), "paths": paths[:20]}
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def check_reachability(fuzzer_name: str, function_name: str) -> Dict[str, Any]:
        """
        Check if a function is reachable from a fuzzer entry point.

        Quick check to verify if fuzzer input can reach a target function.

        Args:
            fuzzer_name: Name of the fuzzer
            function_name: Target function to check

        Returns:
            reachable: True if function is reachable from fuzzer
            distance: Call depth from fuzzer to function (if reachable)
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            result = client.get_reachability(fuzzer_name, function_name)
            return {
                "success": True,
                "fuzzer_name": fuzzer_name,
                "function_name": function_name,
                "reachable": result.get("reachable", False),
                "distance": result.get("distance"),
            }
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def get_reachable_functions(fuzzer_name: str) -> Dict[str, Any]:
        """
        Get all functions reachable from a fuzzer entry point.

        Returns the complete list of functions that can be reached via the call graph.

        Args:
            fuzzer_name: Name of the fuzzer

        Returns:
            functions: List of all reachable function names
            count: Total number of reachable functions
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            functions = client.get_reachable_functions(fuzzer_name)
            return {
                "success": True,
                "fuzzer_name": fuzzer_name,
                "count": len(functions),
                "functions": functions,
            }
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def get_unreached_functions(fuzzer_name: str) -> Dict[str, Any]:
        """
        Get functions NOT reachable from a fuzzer (coverage gaps).

        Useful for identifying code that fuzzer cannot reach and may need harness improvements.

        Args:
            fuzzer_name: Name of the fuzzer

        Returns:
            functions: List of unreachable function names
            count: Total number of unreachable functions
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            functions = client.get_unreached_functions(fuzzer_name)
            return {
                "success": True,
                "fuzzer_name": fuzzer_name,
                "count": len(functions),
                "functions": functions,
            }
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def get_fuzzers() -> Dict[str, Any]:
        """Get list of all built fuzzers."""
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            fuzzers = client.get_fuzzers()
            return {"success": True, "count": len(fuzzers), "fuzzers": fuzzers}
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def get_fuzzer_source(fuzzer_name: str) -> Dict[str, Any]:
        """
        Get the source code of a fuzzer/harness.

        This is the MOST IMPORTANT tool to understand how input enters the target.
        ALWAYS read the fuzzer source code FIRST before analyzing any vulnerability.

        Args:
            fuzzer_name: Name of the fuzzer

        Returns:
            - fuzzer: Fuzzer name
            - source_path: Path to the fuzzer source file
            - source: The fuzzer source code (shows how input is processed)
        """
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            result = client.get_fuzzer_source(fuzzer_name)
            if "error" in result and "source" not in result:
                return {"success": False, **result}
            return {"success": True, **result}
        except Exception as e:
            return _handle_client_error(e)

    @mcp.tool
    @async_tool
    def get_build_paths() -> Dict[str, Any]:
        """Get build output paths for each sanitizer."""
        err = _ensure_client()
        if err:
            return err
        try:
            client = _get_client()
            paths = client.get_build_paths()
            return {"success": True, "build_paths": paths}
        except Exception as e:
            return _handle_client_error(e)


def _register_code_viewer_tools(mcp: FastMCP) -> None:
    """Register code viewer tools (file system operations)."""

    # Import the _impl functions that bypass MCP wrapper
    from .code_viewer import (
        get_diff_impl,
        get_file_content_impl,
        search_code_impl,
        list_files_impl,
    )

    @mcp.tool
    @async_tool
    def get_diff() -> Dict[str, Any]:
        """
        Read the diff file for the current task.
        Essential for delta-scan mode to understand what code changes were made.
        """
        return get_diff_impl()

    @mcp.tool
    @async_tool
    def get_file_content(
        file_path: str, start_line: int = None, end_line: int = None
    ) -> Dict[str, Any]:
        """
        Read the content of a file from the repository.

        Args:
            file_path: Relative path to the file within the repo
            start_line: Optional starting line number (1-indexed)
            end_line: Optional ending line number (1-indexed, inclusive)
        """
        return get_file_content_impl(file_path, start_line, end_line)

    @mcp.tool
    @async_tool
    def search_code(
        pattern: str,
        file_pattern: str = None,
        max_results: int = 50,
        context_lines: int = 2,
    ) -> Dict[str, Any]:
        """
        Search for a pattern in the repository source code.

        Args:
            pattern: Search pattern (supports regex)
            file_pattern: Optional glob pattern to filter files
            max_results: Maximum number of matches to return
            context_lines: Number of context lines around matches
        """
        return search_code_impl(pattern, file_pattern, max_results, context_lines)

    @mcp.tool
    @async_tool
    def list_files(
        directory: str = "", pattern: str = None, recursive: bool = False
    ) -> Dict[str, Any]:
        """
        List files in the repository.

        Args:
            directory: Subdirectory to list (relative to repo root)
            pattern: Optional glob pattern to filter files
            recursive: If True, list files recursively
        """
        return list_files_impl(directory, pattern, recursive)


def _register_suspicious_point_tools(mcp: FastMCP) -> None:
    """Register suspicious point tools."""

    @mcp.tool
    @async_tool
    def create_suspicious_point(
        function_name: str,
        vuln_type: str,
        description: str,
        score: float = 0.5,
        important_controlflow: list = None,
    ) -> Dict[str, Any]:
        """
        Create a new suspicious point for a potential vulnerability.

        Args:
            function_name: Name of the suspicious function
            vuln_type: Type of vulnerability (e.g., "buffer-overflow", "use-after-free")
            description: Detailed description of the potential vulnerability
            score: Confidence score (0.0-1.0)
            important_controlflow: List of related control flow elements
        """
        from .suspicious_points import create_suspicious_point_impl

        return create_suspicious_point_impl(
            function_name, vuln_type, description, score, important_controlflow
        )

    @mcp.tool
    @async_tool
    def update_suspicious_point(
        suspicious_point_id: str,
        score: float = None,
        is_checked: bool = None,
        is_real: bool = None,
        is_important: bool = None,
        verification_notes: str = None,
        pov_guidance: str = None,
        reachability_status: str = None,
        reachability_multiplier: float = None,
        reachability_reason: str = None,
    ) -> Dict[str, Any]:
        """
        Update an existing suspicious point after verification.

        Args:
            suspicious_point_id: ID of the suspicious point to update
            score: Updated confidence score
            is_checked: Whether the point has been verified
            is_real: Whether it's confirmed as a real vulnerability
            is_important: Whether it's high priority
            verification_notes: Notes from verification analysis
            pov_guidance: Guidance for POV agent (input direction, how to reach vuln)
            reachability_status: Reachability status (direct, pointer_call, unreachable)
            reachability_multiplier: Score multiplier based on reachability (0.0-1.0)
            reachability_reason: Explanation for reachability determination
        """
        from .suspicious_points import update_suspicious_point_impl

        return update_suspicious_point_impl(
            suspicious_point_id,
            score,
            is_checked,
            is_real,
            is_important,
            verification_notes,
            pov_guidance,
            reachability_status,
            reachability_multiplier,
            reachability_reason,
        )

    @mcp.tool
    @async_tool
    def list_suspicious_points() -> Dict[str, Any]:
        """List all suspicious points for the current task."""
        from .suspicious_points import list_suspicious_points_impl

        return list_suspicious_points_impl()

    @mcp.tool
    @async_tool
    def get_suspicious_point(suspicious_point_id: str) -> Dict[str, Any]:
        """
        Get details of a specific suspicious point.

        Args:
            suspicious_point_id: ID of the suspicious point
        """
        from .suspicious_points import get_suspicious_point_impl

        return get_suspicious_point_impl(suspicious_point_id)


def _register_direction_tools(mcp: FastMCP) -> None:
    """Register direction tools (Full-scan mode)."""

    @mcp.tool
    @async_tool
    def create_direction(
        name: str,
        risk_level: str,
        risk_reason: str,
        core_functions: list,
        entry_functions: list = None,
        code_summary: str = "",
    ) -> Dict[str, Any]:
        """
        Create a new analysis direction for Full-scan mode.

        Args:
            name: Direction name (e.g., "Input Parsing", "Memory Management")
            risk_level: Risk level ("high", "medium", "low")
            risk_reason: Explanation of why this risk level
            core_functions: List of main functions in this direction
            entry_functions: How fuzzer input reaches this direction
            code_summary: Brief description of what this code does
        """
        from .directions import create_direction_impl

        return create_direction_impl(
            name, risk_level, risk_reason, core_functions, entry_functions, code_summary
        )

    @mcp.tool
    @async_tool
    def list_directions() -> Dict[str, Any]:
        """List all directions for the current task."""
        from .directions import list_directions_impl

        return list_directions_impl()

    @mcp.tool
    @async_tool
    def get_direction(direction_id: str) -> Dict[str, Any]:
        """
        Get details of a specific direction.

        Args:
            direction_id: ID of the direction
        """
        from .directions import get_direction_impl

        return get_direction_impl(direction_id)


def _register_pov_tools(mcp: FastMCP, worker_id: str = None) -> None:
    """
    Register POV tools with worker_id bound via closure.

    Args:
        mcp: FastMCP instance to register tools to
        worker_id: Worker ID for context lookup (bound to tool functions)
    """
    # Capture worker_id in closure - each tool will use this specific worker_id
    bound_worker_id = worker_id

    @mcp.tool
    @async_tool
    def get_fuzzer_info() -> Dict[str, Any]:
        """
        Get fuzzer source code and sanitizer info.
        Use this to refresh your memory about how input enters the target.
        """
        from .pov import get_fuzzer_info_impl

        return get_fuzzer_info_impl(worker_id=bound_worker_id)

    @mcp.tool
    @async_tool
    def create_pov(generator_code: str) -> Dict[str, Any]:
        """
        Generate test input blobs using Python code.

        Args:
            generator_code: Python code with a generate() function that returns bytes
        """
        from .pov import create_pov_impl

        return create_pov_impl(generator_code, worker_id=bound_worker_id)

    @mcp.tool
    @async_tool
    def verify_pov(pov_id: str) -> Dict[str, Any]:
        """
        Test if a POV triggers a crash.

        Args:
            pov_id: ID of the POV to verify
        """
        from .pov import verify_pov_impl

        return verify_pov_impl(pov_id, worker_id=bound_worker_id)

    @mcp.tool
    @async_tool
    def trace_pov(
        generator_code: str, target_functions: list = None, agent_msg: str = None
    ) -> Dict[str, Any]:
        """
        Trace execution path of ONE blob to see which functions it reaches. An LLM will analyze the trace and provide suggestions.

        Args:
            generator_code: Python code with generate() -> bytes (single blob, no variant param)
            target_functions: Functions to check if reached (e.g. ["vuln_func"])
            agent_msg: Question to the LLM (e.g. "why is size check failing?")
        """
        from .pov import trace_pov_impl

        return trace_pov_impl(
            generator_code, target_functions, agent_msg, worker_id=bound_worker_id
        )


def _register_coverage_tools(mcp: FastMCP) -> None:
    """Register coverage analysis tools."""

    @mcp.tool
    @async_tool
    def run_coverage(
        fuzzer_name: str,
        input_data_base64: str,
        target_functions: list = None,
        target_files: list = None,
    ) -> Dict[str, Any]:
        """
        Run coverage analysis on an input to check code path execution.

        Args:
            fuzzer_name: Name of the fuzzer binary
            input_data_base64: Base64 encoded input data to analyze
            target_functions: Optional list of function names to check for coverage
            target_files: Optional list of filenames to filter coverage display
        """
        from .coverage import run_coverage_impl

        return run_coverage_impl(
            fuzzer_name, input_data_base64, target_functions, target_files
        )

    @mcp.tool
    @async_tool
    def check_pov_reaches_target(
        fuzzer_name: str,
        pov_data_base64: str,
        target_function: str,
    ) -> Dict[str, Any]:
        """
        Check if a POV reaches a specific target function.

        Args:
            fuzzer_name: Name of the fuzzer binary
            pov_data_base64: Base64 encoded POV input
            target_function: The function name to check
        """
        from .coverage import check_pov_reaches_target_impl

        return check_pov_reaches_target_impl(
            fuzzer_name, pov_data_base64, target_function
        )

    @mcp.tool
    @async_tool
    def list_available_fuzzers() -> Dict[str, Any]:
        """
        List all available coverage-instrumented fuzzers.
        """
        from .coverage import list_fuzzers_impl

        return list_fuzzers_impl()

    @mcp.tool
    @async_tool
    def get_coverage_feedback(
        fuzzer_name: str,
        input_data_base64: str,
        target_files: list = None,
    ) -> Dict[str, Any]:
        """
        Get coverage feedback for LLM prompt enhancement.

        Args:
            fuzzer_name: Name of the fuzzer binary
            input_data_base64: Base64 encoded input data
            target_files: Optional list of filenames to focus on
        """
        from .coverage import get_feedback_impl

        return get_feedback_impl(fuzzer_name, input_data_base64, target_files)


def _register_seed_tools(mcp: FastMCP, worker_id: str = None) -> None:
    """
    Register seed generation tools with worker_id bound via closure.

    Args:
        mcp: FastMCP instance to register tools to
        worker_id: Worker ID for context lookup (bound to tool functions)
    """
    from typing import Dict, Any

    # Capture worker_id in closure
    bound_worker_id = worker_id

    @mcp.tool
    @async_tool
    def create_seed(
        generator_code: str,
        num_seeds: int = 5,
    ) -> Dict[str, Any]:
        """
        Generate fuzzer seeds to improve coverage based on analysis direction.

        Write Python code with a generate(seed_num: int) function that returns bytes.
        The function receives seed number (1, 2, ..., num_seeds) and should return
        DIFFERENT seeds for each number to maximize coverage exploration.

        These seeds are added to the Global Fuzzer's corpus for mutation.

        Args:
            generator_code: Python code with generate(seed_num) function.
                Example 1 - Different sizes:
                ```python
                def generate(seed_num: int) -> bytes:
                    # Generate seeds with increasing sizes
                    sizes = [16, 64, 256, 1024, 4096]
                    size = sizes[(seed_num - 1) % len(sizes)]
                    return b'A' * size
                ```

                Example 2 - XML/structured data:
                ```python
                def generate(seed_num: int) -> bytes:
                    templates = [
                        b'<root></root>',
                        b'<root><child/></root>',
                        b'<root attr="value"></root>',
                        b'<root>text</root>',
                        b'<?xml version="1.0"?><root/>',
                    ]
                    return templates[(seed_num - 1) % len(templates)]
                ```
            num_seeds: Number of seeds to generate (default 5)

        Returns:
            {
                "success": True,
                "seeds_generated": N,
                "seed_type": "direction" or "delta",
                "seed_paths": ["path1", "path2", ...],
            }
        """
        from ..fuzzer.seed_tools import create_seed_impl, get_seed_context

        # Determine seed_type from context (delta or direction)
        wid = bound_worker_id
        ctx = get_seed_context(wid) if wid else {}
        if ctx.get("delta_id"):
            seed_type = "delta"
        elif ctx.get("direction_id"):
            seed_type = "direction"
        else:
            seed_type = "direction"  # Default fallback

        return create_seed_impl(
            generator_code=generator_code,
            num_seeds=num_seeds,
            seed_type=seed_type,
            worker_id=bound_worker_id,
        )


# Export
__all__ = ["create_isolated_mcp_server"]
