"""
Introspector Parser

Parses fuzz-introspector output to extract:
1. Reachable functions from fuzzer entry points
2. Call graph with proper distances from entry
3. Function metadata (source file, line numbers, etc.)
"""

import json
from pathlib import Path
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional


@dataclass
class FunctionInfo:
    """Information about a reachable function."""

    name: str
    file_path: str
    start_line: int
    end_line: int
    distance_from_entry: int = -1  # -1 = not computed
    callees: List[str] = field(default_factory=list)
    reached_by_fuzzers: List[str] = field(default_factory=list)
    cyclomatic_complexity: int = 0


@dataclass
class CallGraph:
    """Call graph built from introspector data."""

    edges: Dict[str, Set[str]]  # caller -> callees
    functions: Dict[str, FunctionInfo]
    entry_points: List[str]
    distances: Dict[str, int]  # function -> distance from entry


def parse_introspector_json(json_path: Path) -> CallGraph:
    """
    Parse introspector JSON and build call graph.

    Args:
        json_path: Path to all-fuzz-introspector-functions.json

    Returns:
        CallGraph with edges, functions, and distances
    """
    with open(json_path) as f:
        data = json.load(f)

    # Build call graph edges and function info
    edges = defaultdict(set)
    functions = {}

    for func in data:
        name = func.get("Func name", "")

        # Extract function info
        info = FunctionInfo(
            name=name,
            file_path=func.get("Functions filename", ""),
            start_line=func.get("source_line_begin", 0),
            end_line=func.get("source_line_end", 0),
            callees=list(func.get("callsites", {}).keys()),
            reached_by_fuzzers=func.get("Reached by Fuzzers", []),
            cyclomatic_complexity=func.get("Cyclomatic complexity", 0),
        )
        functions[name] = info

        # Add edges
        for callee in info.callees:
            edges[name].add(callee)

    # Find entry points (Reached by Fuzzers but Reached by functions = 0)
    entry_points = []
    for func in data:
        if func.get("Reached by Fuzzers") and func.get("Reached by functions", -1) == 0:
            entry_points.append(func.get("Func name"))

    # BFS to compute distances from entry points
    distances = {}
    queue = deque()

    for ep in entry_points:
        distances[ep] = 0
        queue.append((ep, 0))

    while queue:
        func, dist = queue.popleft()
        for callee in edges.get(func, []):
            if callee not in distances:
                distances[callee] = dist + 1
                queue.append((callee, dist + 1))

    # Update function info with distances
    for name, dist in distances.items():
        if name in functions:
            functions[name].distance_from_entry = dist

    return CallGraph(
        edges=dict(edges),
        functions=functions,
        entry_points=entry_points,
        distances=distances,
    )


def get_reachable_functions(
    callgraph: CallGraph,
    max_distance: Optional[int] = None,
) -> List[FunctionInfo]:
    """
    Get all reachable functions, optionally filtered by distance.

    Args:
        callgraph: CallGraph object
        max_distance: Maximum distance from entry (None = all)

    Returns:
        List of FunctionInfo for reachable functions
    """
    result = []
    for name, dist in callgraph.distances.items():
        if max_distance is None or dist <= max_distance:
            if name in callgraph.functions:
                result.append(callgraph.functions[name])

    # Sort by distance
    result.sort(key=lambda f: f.distance_from_entry)
    return result


def find_call_path(
    callgraph: CallGraph,
    target_function: str,
) -> Optional[List[str]]:
    """
    Find shortest call path from entry to target function.

    Args:
        callgraph: CallGraph object
        target_function: Name of target function (partial match allowed)

    Returns:
        List of function names in the path, or None if not found
    """
    # Find matching function
    target = None
    for name in callgraph.distances:
        if target_function in name:
            target = name
            break

    if target is None:
        return None

    # BFS to find path (reverse from target)
    # Build reverse graph
    reverse_edges = defaultdict(set)
    for caller, callees in callgraph.edges.items():
        for callee in callees:
            reverse_edges[callee].add(caller)

    # BFS from target back to entry
    visited = {target: None}
    queue = deque([target])

    while queue:
        func = queue.popleft()
        if func in callgraph.entry_points:
            # Found path, reconstruct it
            path = []
            current = func
            while current is not None:
                path.append(current)
                # Find next in path (the one we came from)
                for caller in reverse_edges.get(current, []):
                    if caller in visited and visited[current] is None:
                        visited[current] = caller
                current = visited.get(current)
            return path

        for caller in reverse_edges.get(func, []):
            if caller not in visited:
                visited[caller] = func
                queue.append(caller)

    return None


def get_functions_at_distance(
    callgraph: CallGraph,
    distance: int,
) -> List[FunctionInfo]:
    """Get all functions at exactly the specified distance."""
    return [
        callgraph.functions[name]
        for name, dist in callgraph.distances.items()
        if dist == distance and name in callgraph.functions
    ]


def print_callgraph_summary(callgraph: CallGraph) -> str:
    """Print a summary of the call graph."""
    from collections import Counter

    lines = []
    lines.append(f"Entry points: {len(callgraph.entry_points)}")
    for ep in callgraph.entry_points:
        lines.append(f"  - {ep}")

    lines.append(f"\nTotal reachable functions: {len(callgraph.distances)}")

    dist_count = Counter(callgraph.distances.values())
    lines.append("\nDistance distribution:")
    for d in sorted(dist_count.keys()):
        lines.append(f"  Distance {d:2d}: {dist_count[d]:3d} functions")

    return "\n".join(lines)


# Convenience function
def analyze_introspector(introspector_dir: Path) -> CallGraph:
    """
    Analyze introspector output directory.

    Args:
        introspector_dir: Path to static_analysis/introspector/

    Returns:
        CallGraph object
    """
    json_path = introspector_dir / "all-fuzz-introspector-functions.json"
    if not json_path.exists():
        raise FileNotFoundError(f"Introspector JSON not found: {json_path}")

    return parse_introspector_json(json_path)
