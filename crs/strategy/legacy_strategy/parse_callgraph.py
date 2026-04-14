#!/usr/bin/env python3

import re
import os
import sys
import json
from collections import defaultdict, deque

def canonical_name(func_name: str) -> str:
    """
    Convert both "png_read_info" and "OSS_FUZZ_png_read_info" to "png_read_info".
    """
    if func_name.startswith("OSS_FUZZ_"):
        return func_name[9:]  # strip off "OSS_FUZZ_"
    return func_name

def parse_dot_file(dot_file):
    """
    Builds:
      1. graph: adjacency dict keyed by canonical function name
      2. node_names: maps node_id -> canonical function name
    """
    graph = defaultdict(set)  # use a set to avoid duplicates
    node_names = {}

    with open(dot_file, "r") as f:
        content = f.read()

    # 1) Find node definitions
    #    Original format: Node0x[hex] [shape=...,label="{PTACallGraphNode ID: digits {fun: SomeFunc}"]
    #    or new format like: Node[number] [shape=Mrecord,label="FunctionName"]
    node_pattern_old = re.compile(
        r'Node0x([a-f0-9]+)\s+\[shape=.*?label="{PTACallGraphNode ID: \d+ \\{fun: ([^}]+)\\}'
    )
    node_pattern_new = re.compile(r'Node(\d+)\s+\[.*?label="([^"]+)"')

    # Attempt the "old" pattern first
    matches_old = list(node_pattern_old.finditer(content))
    if matches_old:
        print(f"Using old dot format, found {len(matches_old)} nodes")
        for m in matches_old:
            node_id = m.group(1)
            raw_name = m.group(2)

            # Possibly remove extra braces or newlines
            if "\\n" in raw_name:
                raw_name = raw_name.split("\\n", 1)[0]

            # If there's still a "{fun: ...}" pattern inside, extract that
            # But usually m already captures that portion
            if "{fun:" in raw_name:
                # Try to re-extract
                subm = re.search(r'\\{fun:\s*([^}]+)\\}', raw_name)
                if subm:
                    raw_name = subm.group(1)

            norm_name = canonical_name(raw_name)
            node_names[node_id] = norm_name
    else:
        # Try the new pattern
        matches_new = list(node_pattern_new.finditer(content))
        print(f"Using new dot format, found {len(matches_new)} nodes")
        for m in matches_new:
            node_id = m.group(1)
            raw_name = m.group(2)
            # Possibly split on \n if the label has multiple lines
            if "\\n" in raw_name:
                raw_name = raw_name.split("\\n", 1)[0]
            norm_name = canonical_name(raw_name)
            node_names[node_id] = norm_name

    # 2) Find edges
    #    a) Old: Node0x[hex]:sX -> Node0x[hex]
    #    b) New: Node[num] -> Node[num]
    edge_pattern_old = re.compile(r'Node0x([a-f0-9]+):s\d+\s+->\s+Node0x([a-f0-9]+)')
    edge_pattern_new = re.compile(r'Node(\d+)\s*->\s*Node(\d+)')

    matches_edge_old = list(edge_pattern_old.finditer(content))
    if matches_edge_old:
        print(f"Found {len(matches_edge_old)} edges in old format")
        for m in matches_edge_old:
            src_id = m.group(1)
            dst_id = m.group(2)
            if src_id in node_names and dst_id in node_names:
                src_name = node_names[src_id]
                dst_name = node_names[dst_id]
                graph[src_name].add(dst_name)
    else:
        matches_edge_new = list(edge_pattern_new.finditer(content))
        print(f"Found {len(matches_edge_new)} edges in new format")
        for m in matches_edge_new:
            src_id = m.group(1)
            dst_id = m.group(2)
            if src_id in node_names and dst_id in node_names:
                src_name = node_names[src_id]
                dst_name = node_names[dst_id]
                graph[src_name].add(dst_name)

    # Convert sets to lists for JSON serialization
    graph_list = {k: list(v) for k, v in graph.items()}
    return graph_list

def bfs_find_paths(graph, start_name, end_name, max_depth=50, max_paths=50):
    """
    BFS from start_name to end_name in the merged graph (canonical function names).
    """
    paths = []
    visited = set()
    queue = deque([(start_name, [start_name], 0)])
    
    while queue:
        node, path, depth = queue.popleft()
        
        if node == end_name:
            paths.append(path)
            # Stop early if we reached the limit
            if len(paths) >= max_paths:
                break
            continue
            
        if depth >= max_depth:
            continue
            
        # Mark visited
        if (node, depth) in visited:
            continue
            
        visited.add((node, depth))
        
        # Skip if node has no outgoing edges
        if node not in graph:
            continue
            
        for neighbor in graph[node]:
            if neighbor not in path:  # avoid cycles
                queue.append((neighbor, path + [neighbor], depth + 1))

    return paths

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <dot_file> <end_func> [start_func] [max_depth] [output_json]")
        sys.exit(1)

    dot_file = sys.argv[1]
    end_func = sys.argv[2]
    start_func = "LLVMFuzzerTestOneInput"
    max_depth = 50
    dot_dir = os.path.dirname(dot_file)
    output_json = os.path.join(dot_dir, f"{end_func}_callpaths.json")

    if len(sys.argv) > 3:
        start_func = sys.argv[3]
    if len(sys.argv) > 4:
        max_depth = int(sys.argv[4])
    if len(sys.argv) > 5:
        output_json = sys.argv[5]

    # Parse the dot file into a merged adjacency list
    graph = parse_dot_file(dot_file)
    all_funcs = sorted(graph.keys())
    print(f"Graph has {len(all_funcs)} unique canonical function nodes")

    # Do BFS to find all paths
    start_canon = canonical_name(start_func)
    end_canon = canonical_name(end_func)

    if start_canon not in graph:
        print(f"Start function '{start_canon}' not found in graph keys.")
        # Print a sample
        print("Sample of function keys in the graph:")
        for name in all_funcs[:20]:
            print(f"  {name}")
        return

    if end_canon not in all_funcs and end_canon not in [canonical_name(f) for f in all_funcs]:
        print(f"End function '{end_canon}' not found among graph keys.")
        # Print a sample
        print("Sample of function keys in the graph:")
        for name in all_funcs[:20]:
            print(f"  {name}")
        return

    print(f"Searching for paths from '{start_canon}' to '{end_canon}'...")
    paths = bfs_find_paths(graph, start_canon, end_canon, max_depth)
    
    # Prepare results for JSON output
    results = {
        "start_function": start_canon,
        "end_function": end_canon,
        "max_depth": max_depth,
        "num_paths": len(paths),
        "paths": paths
    }
    
    if not paths:
        print(f"No paths found from {start_canon} to {end_canon} (max_depth={max_depth})")
    else:
        print(f"Found {len(paths)} path(s) from {start_canon} to {end_canon}:")
        # Print them
        for i, path in enumerate(paths, 1):
            print(f"Path {i} (length {len(path)}):")
            for idx, fn in enumerate(path):
                print(f"  {idx}. {fn}")
            print()
    
    # Save to JSON if output file specified
    if output_json:
        with open(output_json, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {output_json}")

if __name__ == "__main__":
    main()