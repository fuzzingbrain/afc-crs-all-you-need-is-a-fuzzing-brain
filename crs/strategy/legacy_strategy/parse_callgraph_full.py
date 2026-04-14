#!/usr/bin/env python3
"""
Find call‑paths or reachable functions in a CG‑dot file produced by
clang‑static‑analyzer/llvm‑opt, etc.

Usage
-----
  # Mode 1 – like the original script: find paths start → end
  ./callpaths.py cg.dot end_func [start_func] [max_depth] [output_json]

  # Mode 2 – NEW: list every function reachable from start_func
  ./callpaths.py cg.dot                    # uses default start_func
  ./callpaths.py cg.dot "" my_fuzz_entry   # explicit start_func
"""

import json
import os
import re
import sys
from collections import defaultdict, deque
from typing import Dict, List, Set


# ---------- helpers ---------------------------------------------------------


def canonical_name(func_name: str) -> str:
    """Convert both "png_read_info" and "OSS_FUZZ_png_read_info" → "png_read_info"."""
    return func_name[9:] if func_name.startswith("OSS_FUZZ_") else func_name


def bfs_reachable(graph: Dict[str, List[str]],
                  start: str,
                  max_depth: int = 50) -> List[str]:
    """Return every node reachable from *start* within *max_depth* edges."""
    visited: Set[str] = set()
    queue = deque([(start, 0)])

    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for nbr in graph.get(node, []):
            if nbr not in visited:
                visited.add(nbr)
                queue.append((nbr, depth + 1))

    # remove the start node itself if it slipped in
    visited.discard(start)
    return sorted(visited)


def bfs_find_paths(graph: Dict[str, List[str]],
                   start_name: str,
                   end_name: str,
                   max_depth: int = 50) -> List[List[str]]:
    """All simple paths start → end up to *max_depth* edges."""
    paths: List[List[str]] = []
    visited: Set[tuple[str, int]] = set()
    queue = deque([(start_name, [start_name], 0)])

    while queue:
        node, path, depth = queue.popleft()

        if node == end_name:
            paths.append(path)
            continue

        if depth >= max_depth or (node, depth) in visited:
            continue
        visited.add((node, depth))

        for nbr in graph.get(node, []):
            if nbr not in path:  # avoid cycles
                queue.append((nbr, path + [nbr], depth + 1))

    return paths


# ---------- DOT parsing (unchanged, just shortened here) --------------------


def parse_dot_file(dot_file: str) -> Dict[str, List[str]]:
    """
    Build adjacency list keyed by canonical function name.
    Only the essentials shown; full regex logic unchanged.
    """
    graph: Dict[str, Set[str]] = defaultdict(set)
    node_names: Dict[str, str] = {}

    with open(dot_file, "r", encoding="utf-8") as f:
        content = f.read()

    # ---- nodes ----
    node_old = re.compile(r'Node0x([a-f0-9]+).*?\\{fun: ([^}]+)\\}')
    node_new = re.compile(r'Node(\d+)\s+\[.*?label="([^"\\]+)')
    for m in node_old.finditer(content):
        node_names[m.group(1)] = canonical_name(m.group(2).split("\\n", 1)[0])
    if not node_names:
        for m in node_new.finditer(content):
            node_names[m.group(1)] = canonical_name(m.group(2).split("\\n", 1)[0])

    # ---- edges ----
    edge_old = re.compile(r'Node0x([a-f0-9]+):s\d+\s+->\s+Node0x([a-f0-9]+)')
    edge_new = re.compile(r'Node(\d+)\s*->\s*Node(\d+)')
    edge_iter = edge_old.finditer(content) if edge_old.search(content) else edge_new.finditer(content)

    for m in edge_iter:
        src_id, dst_id = m.group(1), m.group(2)
        if src_id in node_names and dst_id in node_names:
            graph[node_names[src_id]].add(node_names[dst_id])

    return {k: sorted(v) for k, v in graph.items()}


# ---------- main ------------------------------------------------------------


def usage_and_exit() -> None:
    print(__doc__.strip(), file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) < 2:
        usage_and_exit()

    # ---------------- CLI ----------------
    dot_file = sys.argv[1]
    arg_i = 2

    end_func = None
    if arg_i < len(sys.argv) and sys.argv[arg_i] != "":
        end_func = sys.argv[arg_i]
        arg_i += 1

    start_func = "LLVMFuzzerTestOneInput"
    if arg_i < len(sys.argv):
        start_func = sys.argv[arg_i]
        arg_i += 1

    max_depth = 50
    if arg_i < len(sys.argv):
        max_depth = int(sys.argv[arg_i])
        arg_i += 1

    dot_dir = os.path.dirname(os.path.abspath(dot_file))
    dot_basename = os.path.basename(dot_file)
    default_json = f"{dot_basename}_reachable.json"
    output_json = os.path.join(dot_dir, default_json)
    if arg_i < len(sys.argv):
        output_json = sys.argv[arg_i]

    # ---------------- parse + stats ----------------
    graph = parse_dot_file(dot_file)
    all_nodes = sorted(graph.keys())
    print(f"Graph contains {len(all_nodes)} unique canonical function nodes")

    start_canon = canonical_name(start_func)
    if start_canon not in graph:
        sys.exit(f"Start function “{start_canon}” not found in graph.")

    # ---------------- mode 1: paths start → end ----------------
    if end_func is not None:
        end_canon = canonical_name(end_func)
        if end_canon not in graph:
            sys.exit(f"End function “{end_canon}” not found in graph.")

        print(f"Searching for paths {start_canon} → {end_canon} (max_depth={max_depth}) …")
        paths = bfs_find_paths(graph, start_canon, end_canon, max_depth)

        results = {
            "mode": "paths",
            "start_function": start_canon,
            "end_function": end_canon,
            "max_depth": max_depth,
            "num_paths": len(paths),
            "paths": paths,
        }

        print(f"Found {len(paths)} path(s).")

    # ---------------- mode 2: all reachable --------------------
    else:
        print(f"Finding every function reachable from {start_canon} (max_depth={max_depth}) …")
        reachable = bfs_reachable(graph, start_canon, max_depth)

        results = {
            "mode": "reachable",
            "start_function": start_canon,
            "max_depth": max_depth,
            "num_reachable": len(reachable),
            "reachable_functions": reachable,
        }

        print(f"{len(reachable)} functions reachable from {start_canon}.")

    # ---------------- save JSON ----------------
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Results written to {output_json}")


if __name__ == "__main__":
    main()
