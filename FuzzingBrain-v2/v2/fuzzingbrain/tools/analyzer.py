"""
Analyzer Tools

MCP tools for querying the Analysis Server.
Provides code analysis capabilities to AI agents.

These tools wrap the AnalysisClient SDK for use via MCP protocol.
"""

from contextvars import ContextVar
from typing import Any, Dict, Optional

from loguru import logger

from . import tools_mcp
from ..analyzer import AnalysisClient


# =============================================================================
# Context for analyzer tools
# Using ContextVar for async task isolation (each asyncio.Task has its own context)
# =============================================================================

_analysis_socket_path: ContextVar[Optional[str]] = ContextVar('analyzer_socket_path', default=None)
_analysis_client: ContextVar[Optional[AnalysisClient]] = ContextVar('analyzer_client', default=None)
_client_id: ContextVar[str] = ContextVar('analyzer_client_id', default="mcp_agent")


def set_analyzer_context(socket_path: str, client_id: str = "mcp_agent") -> None:
    """
    Set the context for analyzer tools.

    Uses ContextVar for proper isolation in async/parallel execution.

    Args:
        socket_path: Path to Analysis Server Unix socket
        client_id: Identifier for this client (for query logging)
    """
    _analysis_socket_path.set(socket_path)
    _client_id.set(client_id)
    _analysis_client.set(None)  # Reset client to reconnect with new settings


def get_analyzer_context() -> Optional[str]:
    """Get the current analyzer socket path."""
    return _analysis_socket_path.get()


def _get_client() -> Optional[AnalysisClient]:
    """Get or create the Analysis Client."""
    socket_path = _analysis_socket_path.get()
    if socket_path is None:
        return None

    client = _analysis_client.get()
    if client is None:
        try:
            client = AnalysisClient(
                socket_path,
                client_id=_client_id.get(),
            )
            if not client.ping():
                logger.warning("Analysis Server not responding")
                client = None
            else:
                _analysis_client.set(client)
        except Exception as e:
            logger.warning(f"Failed to connect to Analysis Server: {e}")
            client = None

    return client


def _ensure_client() -> Dict[str, Any]:
    """Ensure client is available, return error dict if not."""
    client = _get_client()
    if client is None:
        return {
            "success": False,
            "error": "Analysis Server not available. Socket path not set or server not running.",
        }
    return None


# =============================================================================
# Server Control Tools
# =============================================================================

@tools_mcp.tool
def analyzer_status() -> Dict[str, Any]:
    """
    Get Analysis Server status.

    Returns server status including query count, uptime, and available functions.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        status = client.get_status()
        return {
            "success": True,
            "status": status,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


# =============================================================================
# Function Query Tools
# =============================================================================

@tools_mcp.tool
def get_function(name: str) -> Dict[str, Any]:
    """
    Get detailed information about a function by name.

    Tries OSS_FUZZ_ prefix variants if exact name not found.

    Args:
        name: Function name to look up (e.g. 'png_read_info' or 'OSS_FUZZ_png_read_info')

    Returns:
        Function metadata including:
        - name: Function name
        - file: Source file path
        - line_start, line_end: Line range
        - complexity: Cyclomatic complexity
        - arg_count: Number of arguments
        - return_type: Return type
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        func = client.get_function(name)
        if func is None:
            return {
                "success": False,
                "error": f"Function '{name}' not found",
            }
        return {
            "success": True,
            "function": func,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def get_functions_by_file(file_path: str) -> Dict[str, Any]:
    """
    Get all functions defined in a specific file.

    Args:
        file_path: File path (can be partial, e.g., "png.c")

    Returns:
        List of functions in the file with their metadata.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        functions = client.get_functions_by_file(file_path)
        return {
            "success": True,
            "file_path": file_path,
            "count": len(functions),
            "functions": functions,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def search_functions(pattern: str, limit: int = 50) -> Dict[str, Any]:
    """
    Search for functions by name pattern.

    Args:
        pattern: Regex pattern to match function names (e.g., "png_read.*")
        limit: Maximum number of results (default: 50)

    Returns:
        List of matching functions with their metadata.
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
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def get_function_source(name: str) -> Dict[str, Any]:
    """
    Get the source code of a function.

    Tries OSS_FUZZ_ prefix variants if exact name not found.

    Args:
        name: Function name (e.g. 'png_read_info' or 'OSS_FUZZ_png_read_info')

    Returns:
        Source code of the function.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        source = client.get_function_source(name)
        if source is None:
            return {
                "success": False,
                "error": f"Source not available for function '{name}'",
            }
        return {
            "success": True,
            "function": name,
            "source": source,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


# =============================================================================
# Call Graph Tools
# =============================================================================

@tools_mcp.tool
def get_callers(function: str) -> Dict[str, Any]:
    """
    Get all functions that call the specified function.

    Tries OSS_FUZZ_ prefix variants if exact name not found.

    Args:
        function: Target function name (e.g. 'png_read_info' or 'OSS_FUZZ_png_read_info')

    Returns:
        List of function names that call the target.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        result = client.get_callers(function)
        callers = result.get("callers", []) if isinstance(result, dict) else result
        response = {
            "success": True,
            "function": result.get("function", function) if isinstance(result, dict) else function,
            "count": len(callers),
            "callers": callers,
        }
        # Include original query if it was mapped to a different name
        if isinstance(result, dict) and result.get("queried_as"):
            response["queried_as"] = result["queried_as"]
        return response
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def get_callees(function: str) -> Dict[str, Any]:
    """
    Get all functions called by the specified function.

    Tries OSS_FUZZ_ prefix variants if exact name not found.

    Args:
        function: Source function name (e.g. 'png_read_info' or 'OSS_FUZZ_png_read_info')

    Returns:
        List of function names called by the source.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        result = client.get_callees(function)
        callees = result.get("callees", []) if isinstance(result, dict) else result
        response = {
            "success": True,
            "function": result.get("function", function) if isinstance(result, dict) else function,
            "count": len(callees),
            "callees": callees,
        }
        # Include original query if it was mapped to a different name
        if isinstance(result, dict) and result.get("queried_as"):
            response["queried_as"] = result["queried_as"]
        return response
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def get_call_graph(fuzzer: str, depth: int = 3) -> Dict[str, Any]:
    """
    Get the call graph starting from a fuzzer entry point.

    Args:
        fuzzer: Fuzzer name (entry point function)
        depth: Maximum depth to traverse (default: 3)

    Returns:
        Call graph as a dict mapping function names to their callees.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        graph = client.get_call_graph(fuzzer, depth)
        return {
            "success": True,
            "fuzzer": fuzzer,
            "depth": depth,
            "node_count": len(graph),
            "call_graph": graph,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def find_all_paths(
    func1: str,
    func2: str,
    max_depth: int = 10,
    max_paths: int = 100,
) -> Dict[str, Any]:
    """
    Find all call paths from func1 to func2.

    Useful for understanding how data flows from a fuzzer entry point
    to a specific target function.

    Args:
        func1: Start function. Use 'LLVMFuzzerTestOneInput' to start from all
               fuzzer entry points (call_depth=0 functions).
        func2: End function (target function to analyze)
        max_depth: Maximum path length (default: 10)
        max_paths: Maximum number of paths to return (default: 100)

    Returns:
        - paths: List of call paths, each path is a list of function names
        - path_count: Number of paths found
        - truncated: True if more paths exist but hit max_paths limit
        - cached: True if result was served from cache
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        result = client.find_all_paths(func1, func2, max_depth, max_paths)
        return {
            "success": True,
            **result,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


# =============================================================================
# Reachability Tools
# =============================================================================

@tools_mcp.tool
def check_reachability(fuzzer: str, function: str) -> Dict[str, Any]:
    """
    Check if a function is reachable from a fuzzer.

    Args:
        fuzzer: Fuzzer name (e.g. 'libpng_read_fuzzer') or entry point function
                name 'LLVMFuzzerTestOneInput'. If 'LLVMFuzzerTestOneInput' is
                passed, all fuzzers will be searched.
        function: Target function to check

    Returns:
        Whether the function is reachable and the distance (call depth).
        If 'LLVMFuzzerTestOneInput' was used, also returns the actual fuzzer name.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        result = client.get_reachability(fuzzer, function)
        response = {
            "success": True,
            "fuzzer": result.get("fuzzer", fuzzer),  # Use actual fuzzer if returned
            "function": function,
            "reachable": result.get("reachable", False),
            "distance": result.get("distance"),
        }
        # Include original query fuzzer if it was mapped to a different one
        if result.get("fuzzer") and result["fuzzer"] != fuzzer:
            response["queried_as"] = fuzzer
        return response
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def get_reachable_functions(fuzzer: str) -> Dict[str, Any]:
    """
    Get all functions reachable from a fuzzer.

    Args:
        fuzzer: Fuzzer name (e.g. 'libpng_read_fuzzer') or 'LLVMFuzzerTestOneInput'
                to get all reachable functions across all fuzzers.

    Returns:
        List of all reachable function names.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        functions = client.get_reachable_functions(fuzzer)
        return {
            "success": True,
            "fuzzer": fuzzer,
            "count": len(functions),
            "functions": functions,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def get_unreached_functions(fuzzer: str) -> Dict[str, Any]:
    """
    Get functions not yet covered by a fuzzer.

    Useful for identifying coverage gaps and guiding fuzzing strategy.

    Args:
        fuzzer: Fuzzer name (e.g. 'libpng_read_fuzzer') or 'LLVMFuzzerTestOneInput'
                to compare against all reachable functions across all fuzzers.

    Returns:
        List of function names not yet reached.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        functions = client.get_unreached_functions(fuzzer)
        return {
            "success": True,
            "fuzzer": fuzzer,
            "count": len(functions),
            "functions": functions,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


# =============================================================================
# Build Info Tools
# =============================================================================

@tools_mcp.tool
def get_fuzzers() -> Dict[str, Any]:
    """
    Get list of all built fuzzers.

    Returns:
        List of fuzzer info including name, sanitizer, and binary path.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        fuzzers = client.get_fuzzers()
        return {
            "success": True,
            "count": len(fuzzers),
            "fuzzers": fuzzers,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def get_fuzzer_source(fuzzer_name: str) -> Dict[str, Any]:
    """
    Get the source code of a fuzzer/harness.

    This is the MOST IMPORTANT tool to understand how input enters the target.
    ALWAYS read the fuzzer source code FIRST before analyzing any vulnerability.

    Args:
        fuzzer_name: Name of the fuzzer (e.g., 'libpng_read_fuzzer')

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
            return {
                "success": False,
                **result,
            }
        return {
            "success": True,
            **result,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def get_build_paths() -> Dict[str, Any]:
    """
    Get build output paths for each sanitizer.

    Returns:
        Dict mapping sanitizer names to their build directories.
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        paths = client.get_build_paths()
        return {
            "success": True,
            "build_paths": paths,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


# Export public API
__all__ = [
    # Context
    "set_analyzer_context",
    "get_analyzer_context",
    # Server control
    "analyzer_status",
    # Function queries
    "get_function",
    "get_functions_by_file",
    "search_functions",
    "get_function_source",
    # Call graph
    "get_callers",
    "get_callees",
    "get_call_graph",
    "find_all_paths",
    # Reachability
    "check_reachability",
    "get_reachable_functions",
    "get_unreached_functions",
    # Build info
    "get_fuzzers",
    "get_fuzzer_source",
    "get_build_paths",
]
