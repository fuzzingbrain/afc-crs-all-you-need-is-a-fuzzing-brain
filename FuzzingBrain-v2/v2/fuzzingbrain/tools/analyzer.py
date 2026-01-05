"""
Analyzer Tools

MCP tools for querying the Analysis Server.
Provides code analysis capabilities to AI agents.

These tools wrap the AnalysisClient SDK for use via MCP protocol.
"""

import threading
from contextvars import ContextVar
from typing import Any, Dict, Optional, Tuple

from loguru import logger

from . import tools_mcp
from ..analyzer import AnalysisClient


# =============================================================================
# Context for analyzer tools
# Using ContextVar for async task isolation (each asyncio.Task has its own context)
# =============================================================================

_analysis_socket_path: ContextVar[Optional[str]] = ContextVar('analyzer_socket_path', default=None)
_client_id: ContextVar[str] = ContextVar('analyzer_client_id', default="mcp_agent")

# Thread-safe client cache: key = (socket_path, client_id)
# This ensures each agent gets its own client, but reuses it across thread calls
_client_cache: Dict[Tuple[str, str], AnalysisClient] = {}
_client_cache_lock = threading.Lock()


def _invalidate_client(cache_key: Tuple[str, str]) -> None:
    """
    Remove a client from cache when it becomes invalid.

    Called when a client encounters a connection error (e.g., Bad file descriptor).
    """
    with _client_cache_lock:
        if cache_key in _client_cache:
            try:
                _client_cache[cache_key].close()
            except Exception:
                pass
            del _client_cache[cache_key]
            logger.debug(f"[CACHE] Invalidated client for {cache_key[1]}")


def set_analyzer_context(socket_path: str, client_id: str = "mcp_agent") -> None:
    """
    Set the context for analyzer tools.

    Uses ContextVar for proper isolation in async/parallel execution.
    The actual client is cached in a thread-safe dict keyed by (socket_path, client_id).

    Args:
        socket_path: Path to Analysis Server Unix socket
        client_id: Identifier for this client (for query logging)
    """
    _analysis_socket_path.set(socket_path)
    _client_id.set(client_id)


def get_analyzer_context() -> Optional[str]:
    """Get the current analyzer socket path."""
    return _analysis_socket_path.get()


def _get_client() -> Optional[AnalysisClient]:
    """
    Get or create the Analysis Client.

    Uses thread-safe caching with (socket_path, client_id) as key.
    This ensures:
    - Each agent has its own client (identified by client_id)
    - Clients are reused across multiple tool calls from the same agent
    - Thread-safe access from asyncio.to_thread() worker threads
    """
    import time
    t0 = time.time()

    socket_path = _analysis_socket_path.get()
    if socket_path is None:
        return None

    client_id = _client_id.get()
    cache_key = (socket_path, client_id)

    # Fast path: check if client exists (without lock for read)
    client = _client_cache.get(cache_key)
    if client is not None:
        logger.debug(f"[TIMING] Reusing cached AnalysisClient for {client_id}")
        return client

    # Slow path: create client with lock
    with _client_cache_lock:
        # Double-check after acquiring lock
        client = _client_cache.get(cache_key)
        if client is not None:
            logger.debug(f"[TIMING] Reusing cached AnalysisClient for {client_id} (after lock)")
            return client

        logger.debug(f"[TIMING] Creating new AnalysisClient for {client_id}")
        t1 = time.time()
        try:
            client = AnalysisClient(
                socket_path,
                client_id=client_id,
            )
            t2 = time.time()
            logger.debug(f"[TIMING] AnalysisClient created in {t2-t1:.3f}s")

            if not client.ping():
                logger.warning(f"Analysis Server not responding for {client_id}")
                return None

            t3 = time.time()
            logger.debug(f"[TIMING] ping() completed in {t3-t2:.3f}s")

            # Cache the client
            _client_cache[cache_key] = client
            logger.debug(f"[TIMING] Cached AnalysisClient for {client_id}")

        except Exception as e:
            logger.warning(f"Failed to connect to Analysis Server: {e}")
            return None

    t_end = time.time()
    if t_end - t0 > 0.1:  # Only log if > 100ms
        logger.debug(f"[TIMING] _get_client total: {t_end-t0:.3f}s")

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
        total = len(functions)
        return {
            "success": True,
            "count": total,
            "functions": functions[:50],
            "truncated": total > 50,
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
        pattern: Regex pattern to match function names
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
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        source = client.get_function_source(function_name)
        if source is None:
            return {
                "success": False,
                "error": f"Source not available for function '{function_name}'",
            }
        return {
            "success": True,
            "function_name": function_name,
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
def get_callers(function_name: str) -> Dict[str, Any]:
    """
    Get all functions that call the specified function (who calls this function?).

    Use this to trace backwards in the call graph to understand how a function is reached.

    Args:
        function_name: The function to find callers for

    Returns:
        callers: List of function names that call this function
    """
    err = _ensure_client()
    if err:
        return err

    try:
        client = _get_client()
        result = client.get_callers(function_name)
        callers = result.get("callers", []) if isinstance(result, dict) else result
        total = len(callers)
        return {
            "success": True,
            "count": total,
            "callers": callers[:30],
            "truncated": total > 30,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
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
        return {
            "success": True,
            "count": total,
            "callees": callees[:30],
            "truncated": total > 30,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
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
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
def find_all_paths(
    from_function: str,
    to_function: str,
    max_depth: int = 10,
    max_paths: int = 20,
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
        result = client.find_all_paths(from_function, to_function, max_depth, max_paths)
        paths = result.get("paths", [])
        return {
            "success": True,
            "path_count": len(paths),
            "paths": paths[:20],
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
        response = {
            "success": True,
            "fuzzer_name": result.get("fuzzer", fuzzer_name),
            "function_name": function_name,
            "reachable": result.get("reachable", False),
            "distance": result.get("distance"),
        }
        if result.get("fuzzer") and result["fuzzer"] != fuzzer_name:
            response["queried_as"] = fuzzer_name
        return response
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
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
        return {
            "success": False,
            "error": str(e),
        }


@tools_mcp.tool
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
    "_client_cache",  # For debugging cache state
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
