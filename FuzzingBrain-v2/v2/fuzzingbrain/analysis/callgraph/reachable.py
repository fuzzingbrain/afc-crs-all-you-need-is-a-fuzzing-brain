"""
Reachable Functions Analysis

BFS-based reachability analysis for call graphs.
"""

from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from collections import deque
from dataclasses import dataclass

from .dot_parser import CallGraph, parse_dot_file


@dataclass
class ReachableFunction:
    """A function reachable from the entry point"""
    name: str
    depth: int  # Call depth from entry point
    callers: List[str]  # Functions that call this
    callees: List[str]  # Functions this calls


def bfs_reachable(
    graph: CallGraph,
    entry_point: str,
    max_depth: int = 100
) -> Dict[str, ReachableFunction]:
    """
    Find all functions reachable from entry_point using BFS.

    Args:
        graph: CallGraph object
        entry_point: Starting function (e.g., "LLVMFuzzerTestOneInput")
        max_depth: Maximum call depth to explore

    Returns:
        Dict mapping function name to ReachableFunction with depth info
    """
    if entry_point not in graph.nodes:
        return {}

    result: Dict[str, ReachableFunction] = {}
    visited: Set[str] = set()
    queue: deque = deque([(entry_point, 0)])

    while queue:
        func_name, depth = queue.popleft()

        if func_name in visited:
            continue
        if depth > max_depth:
            continue

        visited.add(func_name)

        # Get callers and callees
        callees = list(graph.get_callees(func_name))
        callers = list(graph.get_callers(func_name))

        result[func_name] = ReachableFunction(
            name=func_name,
            depth=depth,
            callers=callers,
            callees=callees
        )

        # Add callees to queue
        for callee in callees:
            if callee not in visited:
                queue.append((callee, depth + 1))

    return result


def get_reachable_functions(
    dot_path: Path,
    entry_point: str = "LLVMFuzzerTestOneInput",
    max_depth: int = 100
) -> Dict[str, ReachableFunction]:
    """
    Get all functions reachable from entry point.

    This is the main API for reachable function analysis.

    Args:
        dot_path: Path to SVF-generated DOT file
        entry_point: Entry function name (default: LLVMFuzzerTestOneInput)
        max_depth: Maximum call depth

    Returns:
        Dict mapping function name to ReachableFunction
    """
    graph = parse_dot_file(dot_path)
    return bfs_reachable(graph, entry_point, max_depth)


def get_reachable_function_names(
    dot_path: Path,
    entry_point: str = "LLVMFuzzerTestOneInput",
    max_depth: int = 100
) -> List[str]:
    """
    Get just the names of reachable functions.

    Convenience function for simple use cases.

    Args:
        dot_path: Path to SVF-generated DOT file
        entry_point: Entry function name
        max_depth: Maximum call depth

    Returns:
        List of reachable function names
    """
    reachable = get_reachable_functions(dot_path, entry_point, max_depth)
    return list(reachable.keys())


def find_call_paths(
    graph: CallGraph,
    start: str,
    end: str,
    max_depth: int = 50,
    max_paths: int = 50
) -> List[List[str]]:
    """
    Find all paths from start function to end function.

    Uses BFS to find shortest paths first.

    Args:
        graph: CallGraph object
        start: Start function name
        end: End function name
        max_depth: Maximum path length
        max_paths: Maximum number of paths to return

    Returns:
        List of paths, each path is a list of function names
    """
    if start not in graph.nodes or end not in graph.nodes:
        return []

    paths: List[List[str]] = []
    visited: Set[Tuple[str, int]] = set()
    queue: deque = deque([(start, [start], 0)])

    while queue:
        node, path, depth = queue.popleft()

        if node == end:
            paths.append(path)
            if len(paths) >= max_paths:
                break
            continue

        if depth >= max_depth:
            continue

        if (node, depth) in visited:
            continue
        visited.add((node, depth))

        for neighbor in graph.get_callees(node):
            if neighbor not in path:  # Avoid cycles
                queue.append((neighbor, path + [neighbor], depth + 1))

    return paths
