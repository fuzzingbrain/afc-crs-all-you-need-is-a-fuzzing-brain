"""
Code Analysis Utilities

Functions for running static analysis on-demand and processing analysis results.
"""
import os
import time
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from opentelemetry import trace

# Note: tracer is imported from global scope when needed


def find_task_directory(task_id: str) -> Optional[str]:
    """
    Find the actual task directory by searching for task_detail.json with matching task_id

    Args:
        task_id: Task identifier to search for

    Returns:
        Path to the task directory, or None if not found
    """
    # Try common workspace locations
    repo_root = Path(__file__).parent.parent.parent.parent.parent
    workspace_dir = repo_root / "workspace"

    if not workspace_dir.exists():
        return None

    # Search for task_detail.json files
    for project_dir in workspace_dir.iterdir():
        if not project_dir.is_dir():
            continue

        task_detail_file = project_dir / "task_detail.json"
        if task_detail_file.exists():
            try:
                with open(task_detail_file, 'r') as f:
                    task_detail = json.load(f)
                    if task_detail.get('task_id') == task_id:
                        return str(project_dir)
            except Exception:
                continue

    return None


def run_static_analysis_local(
    task_id: str,
    task_dir: str,
    focus: str
) -> bool:
    """
    Run static analysis locally using the Go CLI tool

    Note: This function now checks for existing analysis results first.
    If results exist in task_dir/static_analysis/, it skips re-running analysis.
    FuzzingBrain.sh typically runs analysis upfront, so this is usually a no-op.

    Args:
        task_id: Task identifier
        task_dir: Path to the task directory (may be overridden if incorrect)
        focus: Focus area identifier (e.g., project component name)

    Returns:
        True if analysis completed successfully or results already exist, False otherwise
    """
    try:
        # Try to find the actual task directory if the provided one doesn't exist
        if not os.path.exists(task_dir) or not os.path.exists(os.path.join(task_dir, "task_detail.json")):
            print(f"Task directory {task_dir} not found or invalid, searching for correct directory...")
            found_dir = find_task_directory(task_id)
            if found_dir:
                task_dir = found_dir
                print(f"Found task directory at {task_dir}")
            else:
                print(f"Could not find task directory for task_id {task_id}")
                return False

        # Check if analysis results already exist
        static_analysis_dir = os.path.join(task_dir, "static_analysis")
        index_file = os.path.join(static_analysis_dir, "index.json")

        if os.path.exists(index_file):
            print(f"Static analysis results already exist at {static_analysis_dir}")
            print("Skipping re-analysis (run by FuzzingBrain.sh)")
            return True

        # Find the static analysis CLI binary
        repo_root = Path(__file__).parent.parent.parent.parent.parent
        analysis_binary = repo_root / "static-analysis" / "cmd" / "local" / "local"

        # Check if binary exists, if not try to build it
        if not analysis_binary.exists():
            print(f"Static analysis binary not found at {analysis_binary}, attempting to build...")
            build_dir = repo_root / "static-analysis" / "cmd" / "local"
            build_result = subprocess.run(
                ["go", "build", "-o", "local", "."],
                cwd=str(build_dir),
                capture_output=True,
                text=True,
                timeout=300
            )
            if build_result.returncode != 0:
                print(f"Failed to build static analysis tool: {build_result.stderr}")
                return False
            print(f"Successfully built static analysis binary at {analysis_binary}")

        # Run the analysis
        print(f"Running static analysis for task {task_id} on directory {task_dir}")
        result = subprocess.run(
            [str(analysis_binary), task_dir],
            capture_output=True,
            text=True,
            timeout=3600  # 1 hour timeout
        )

        if result.returncode != 0:
            print(f"Static analysis failed: {result.stderr}")
            return False

        print(f"Static analysis completed successfully for task {task_id}")
        print(result.stdout)
        return True

    except subprocess.TimeoutExpired:
        print(f"Static analysis timed out for task {task_id}")
        return False
    except Exception as e:
        print(f"Error running static analysis: {str(e)}")
        return False


def load_qx_analysis_results(
    task_id: str,
    focus: str,
    task_dir: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Load CodeQL (QX) analysis results from cached JSON file, with fallback to regular analysis

    Args:
        task_id: Task identifier
        focus: Focus area identifier
        task_dir: Optional task directory path, if not provided will search for it

    Returns:
        Dictionary containing analysis results, or None if neither file exists
    """
    if task_dir is None or not os.path.exists(task_dir):
        # Try to find the actual task directory
        task_dir = find_task_directory(task_id)
        if task_dir is None:
            print(f"Could not find task directory for task_id {task_id}")
            return None

    # Try to load QX results first (CodeQL-based analysis)
    output_json_qx = os.path.join(task_dir, f"{focus}_qx.json")

    if os.path.exists(output_json_qx):
        try:
            with open(output_json_qx, 'r') as f:
                results = json.load(f)
            print(f"Loaded QX analysis results from {output_json_qx}")
            return results
        except Exception as e:
            print(f"Error loading QX analysis results: {str(e)}")
            # Fall through to try regular results

    # Fallback: Try regular analysis results
    output_json = os.path.join(task_dir, f"{focus}.json")

    if os.path.exists(output_json):
        try:
            with open(output_json, 'r') as f:
                results = json.load(f)
            print(f"QX analysis not available, using regular analysis results from {output_json}")
            return results
        except Exception as e:
            print(f"Error loading regular analysis results: {str(e)}")
            return None

    print(f"No analysis results found (tried {output_json_qx} and {output_json})")
    return None


def get_reachable_functions_qx(
    fuzzer_source_path: str,
    results: Dict[str, Any],
    max_depth: int = 6
) -> List[Dict[str, Any]]:
    """
    Extract reachable functions from analysis results (QX or regular)

    Args:
        fuzzer_source_path: Path to the fuzzer source file
        results: Analysis results dictionary (either QX or regular format)
        max_depth: Maximum depth for reachability analysis

    Returns:
        List of reachable function definitions
    """
    # Normalize the fuzzer source path
    fuzzer_source_path = fuzzer_source_path.replace(os.sep, '/')

    # Determine entry point suffix based on file extension
    if fuzzer_source_path.endswith('.java'):
        suffix = ".fuzzerTestOneInput"
    else:
        suffix = ".LLVMFuzzerTestOneInput"

    # Build candidate entry point keys to try
    fuzzer_basename = os.path.basename(fuzzer_source_path)
    fuzzer_name = os.path.splitext(fuzzer_basename)[0]

    # Try multiple candidate formats
    entry_point_candidates = [
        f"{fuzzer_source_path}{suffix}",  # Full path
        f"{fuzzer_basename}{suffix}",     # Just filename
    ]

    # Try all candidate entry points
    reachable_names = []
    entry_point = None

    for candidate in entry_point_candidates:
        # Try different field names
        for field_name in ['reachable', 'ReachableFunctions', 'Reachable']:
            reachable_names = results.get(field_name, {}).get(candidate, [])
            if reachable_names:
                entry_point = candidate
                break
        if reachable_names:
            break

    # If still not found, try fuzzy matching by searching for keys containing the fuzzer name
    if not reachable_names:
        for field_name in ['reachable', 'ReachableFunctions', 'Reachable']:
            for key in results.get(field_name, {}).keys():
                if fuzzer_name in key and key.endswith(suffix):
                    reachable_names = results.get(field_name, {}).get(key, [])
                    entry_point = key
                    print(f"Fuzzy matched fuzzer '{fuzzer_name}' to entry point: {key}")
                    break
            if reachable_names:
                break

    if not entry_point:
        entry_point = entry_point_candidates[0]  # Use first candidate for error messages

    functions_map = results.get('functions', {})

    # Try uppercase Functions if lowercase didn't work
    if not functions_map:
        functions_map = results.get('Functions', {})

    # Build list of function definitions
    reachable_funcs = []
    for func_name in reachable_names:
        func_def = functions_map.get(func_name)
        if func_def:
            # Handle both lowercase and uppercase field names
            # Use 'body' as the field name for consistency with other parts of the code
            reachable_funcs.append({
                'name': func_def.get('Name', func_def.get('name', func_name)),
                'file_path': func_def.get('FilePath', func_def.get('file_path', '')),
                'start_line': func_def.get('StartLine', func_def.get('start_line', 0)),
                'end_line': func_def.get('EndLine', func_def.get('end_line', 0)),
                'body': func_def.get('SourceCode', func_def.get('source_code', func_def.get('content', '')))
            })

    print(f"Found {len(reachable_funcs)} reachable functions from entry point {entry_point}")
    return reachable_funcs


def extract_call_paths_from_analysis_service(
    fuzzer_path: str,
    fuzzer_src_path: str,
    focus: str,
    project_src_dir: str,
    modified_functions: Dict[str, Any],
    use_qx: bool
) -> List[List[Dict[str, Any]]]:
    """
    Extract call paths leading to vulnerable functions using local static analysis

    Runs static analysis locally (no HTTP service required) to find execution paths
    from the fuzzer entry point to potentially vulnerable functions identified in
    the commit diff.

    Args:
        fuzzer_path: Path to the compiled fuzzer binary
        fuzzer_src_path: Path to the fuzzer source file
        focus: Focus area identifier (e.g., project component name)
        project_src_dir: Path to the project source directory
        modified_functions: Dictionary of modified functions from parse_commit_diff()
        use_qx: Whether to use the qx (CodeQL) analysis

    Returns:
        List of call paths, where each call path is a list of function info dictionaries:
        [
            [
                {
                    "file": "path/to/file.c",
                    "function": "function_name",
                    "body": "function code...",
                    "line": "123",
                    "is_modified": True,
                    "is_vulnerable": False
                },
                ...
            ],
            ...
        ]

    Environment Variables:
        TASK_ID: Task identifier for tracking analysis requests
        WORK_DIR: Working directory for task data (default: /workspace)
    """
    task_id = os.environ.get("TASK_ID")
    if not task_id:
        print("Warning: TASK_ID environment variable not set")
        return []

    # Find the actual task directory
    task_dir = find_task_directory(task_id)
    if not task_dir:
        print(f"Could not find task directory for task_id {task_id}")
        return []

    print(f"Using task directory: {task_dir}")

    # Import tracer if available
    try:
        from opentelemetry import trace
        tracer = trace.get_tracer(__name__)
        use_tracing = True
    except ImportError:
        use_tracing = False

    # Initialize result list
    call_paths = []

    # Simplify modified_functions to just file_path and function names
    simplified_modified_functions = {}
    for file_path, file_info in modified_functions.items():
        function_info = []
        # Check if file_info is already a list (simplified format from covert_target_functions_format)
        if isinstance(file_info, list):
            function_info = file_info
        else:
            # It's a dict with "modified_functions" key (original format)
            for func in file_info.get("modified_functions", []):
                function_info.append({
                    "name": func["name"],
                    "start_line": func["start_line"]
                })
        if function_info:  # Only include if there are functions
            simplified_modified_functions[file_path] = function_info

    print(f"[try 1/1] Running local static analysis")
    print(f"  task_id: {task_id}")
    print(f"  focus: {focus}")
    print(f"  project_src_dir: {project_src_dir}")
    print(f"  fuzzer_path: {fuzzer_path}")
    print(f"  fuzzer_source_path: {fuzzer_src_path}")

    try:
        if use_tracing:
            with tracer.start_as_current_span("static_analysis.local") as span:
                span.set_attribute("crs.action.category", "static_analysis")
                span.set_attribute("crs.action.name", "extract_call_paths_local")
                span.set_attribute("task_id", task_id)
                span.set_attribute("use_qx", use_qx)

                call_paths = _run_local_analysis(
                    task_id, task_dir, focus, fuzzer_src_path,
                    simplified_modified_functions, use_qx
                )
        else:
            call_paths = _run_local_analysis(
                task_id, task_dir, focus, fuzzer_src_path,
                simplified_modified_functions, use_qx
            )

    except Exception as e:
        print(f"Error running local static analysis: {str(e)}")
        import traceback
        traceback.print_exc()

    print(f"Received {len(call_paths)} call_paths\n")
    return call_paths


def _find_paths_bfs(
    start: str,
    target: str,
    adj: Dict[str, List[str]],
    max_depth: int = 8,
    max_paths: int = 2
) -> List[List[str]]:
    """
    Find paths from start to target using BFS on call graph

    Args:
        start: Starting function name
        target: Target function name
        adj: Adjacency list (caller -> list of callees)
        max_depth: Maximum path depth
        max_paths: Maximum number of paths to return

    Returns:
        List of paths, where each path is a list of function names
    """
    from collections import deque

    if start == target:
        return [[start]]

    paths = []
    queue = deque([(start, [start])])
    visited_states = set()

    while queue and len(paths) < max_paths:
        current, path = queue.popleft()

        if len(path) > max_depth:
            continue

        # Create state fingerprint to avoid revisiting same function at same depth
        state = (current, len(path))
        if state in visited_states:
            continue
        visited_states.add(state)

        # Explore callees
        for callee in adj.get(current, []):
            if callee == target:
                # Found a path!
                paths.append(path + [callee])
                if len(paths) >= max_paths:
                    break
            elif callee not in path:  # Avoid cycles
                queue.append((callee, path + [callee]))

    return paths


def _run_local_analysis(
    task_id: str,
    task_dir: str,
    focus: str,
    fuzzer_src_path: str,
    target_functions: Dict[str, Any],
    use_qx: bool
) -> List[List[Dict[str, Any]]]:
    """
    Internal function to run local analysis and process results

    Args:
        task_id: Task identifier
        task_dir: Path to task directory
        focus: Focus area identifier
        fuzzer_src_path: Path to fuzzer source file
        target_functions: Simplified target functions dictionary
        use_qx: Whether to use CodeQL analysis

    Returns:
        List of call paths
    """
    # Check if analysis results already exist
    if use_qx:
        results_file = os.path.join(task_dir, f"{focus}_qx.json")
    else:
        results_file = os.path.join(task_dir, f"{focus}.json")

    # If results don't exist, run the analysis
    if not os.path.exists(results_file):
        print(f"Analysis results not found at {results_file}, running analysis...")
        success = run_static_analysis_local(task_id, task_dir, focus)
        if not success:
            print("Failed to run static analysis")
            return []

        # Wait a bit for results to be written
        time.sleep(2)

        # Check again
        if not os.path.exists(results_file):
            print(f"Analysis completed but results file {results_file} not found")
            return []

    # Load the analysis results
    try:
        with open(results_file, 'r') as f:
            analysis_results = json.load(f)
        print(f"Loaded analysis results from {results_file}")
    except Exception as e:
        print(f"Error loading analysis results: {str(e)}")
        return []

    # Extract call paths from the results
    call_paths = []

    if use_qx:
        # CodeQL results have paths organized by fuzzer and target
        paths_data = analysis_results.get('paths', {})

        # Normalize fuzzer path for lookup
        fuzzer_key = fuzzer_src_path.replace(os.sep, '/')
        fuzzer_paths = paths_data.get(fuzzer_key, {})

        # For each target function, get the paths
        for file_path, functions in target_functions.items():
            for func_info in functions:
                func_name = func_info['name']

                # Try to find paths to this function
                target_paths = fuzzer_paths.get(func_name, [])

                # Process each path
                for path in target_paths:
                    processed_path = []
                    for node_name in path:
                        # Get function definition
                        func_def = analysis_results.get('functions', {}).get(node_name, {})

                        processed_func = {
                            "file": func_def.get('FilePath', ''),
                            "function": func_def.get('Name', node_name),
                            "body": func_def.get('SourceCode', ''),
                            "line": str(func_def.get('StartLine', '')),
                            "is_modified": node_name in [f['name'] for f in sum([funcs for funcs in target_functions.values()], [])],
                            "is_vulnerable": False,
                        }
                        processed_path.append(processed_func)

                    if processed_path:
                        call_paths.append(processed_path)
    else:
        # Regular analysis results
        paths_data = analysis_results.get('paths', {})
        reachable_data = analysis_results.get('reachable', {})

        # Find the entry point by matching fuzzer name
        # fuzzer_src_path might be empty or a binary path like /path/to/fuzzer_binary
        # We need to find the matching entry point from reachable data
        entry_point = None

        if fuzzer_src_path:
            # Extract fuzzer name from the path
            fuzzer_name = os.path.basename(fuzzer_src_path)
            # Remove extension if present
            fuzzer_name_base = os.path.splitext(fuzzer_name)[0]

            # Search for matching entry point in reachable data
            for ep_key in reachable_data.keys():
                # Entry points are like: tests/fuzzer/flatbuffers_64bit_fuzzer.cc.LLVMFuzzerTestOneInput
                # We want to match 64bit_fuzzer or flatbuffers_64bit_fuzzer
                if fuzzer_name_base in ep_key or ep_key.endswith(f"{fuzzer_name_base}.cc.LLVMFuzzerTestOneInput") or ep_key.endswith(f"{fuzzer_name_base}.java.fuzzerTestOneInput"):
                    entry_point = ep_key
                    print(f"Matched fuzzer '{fuzzer_name_base}' to entry point: {entry_point}")
                    break

        # If we still don't have an entry point, use the first one available
        if not entry_point and reachable_data:
            entry_point = list(reachable_data.keys())[0]
            print(f"Using first available entry point: {entry_point}")

        if not entry_point:
            print("No entry points found in analysis results")
            return []

        # If target_functions is empty, extract all paths for this entry point
        if not target_functions or len(target_functions) == 0:
            print(f"No specific target functions provided, extracting all paths for entry point: {entry_point}")

            # Get all paths that start with this entry point
            for composite_key, path_list in paths_data.items():
                if composite_key.startswith(entry_point + "-"):
                    for path in path_list:
                        processed_path = []
                        for node_name in path:
                            # Get function definition
                            func_def = analysis_results.get('functions', {}).get(node_name, {})

                            processed_func = {
                                "file": func_def.get('FilePath', ''),
                                "function": func_def.get('Name', node_name),
                                "body": func_def.get('SourceCode', ''),
                                "line": str(func_def.get('StartLine', '')),
                                "is_modified": False,  # No specific modified functions
                                "is_vulnerable": False,
                            }
                            processed_path.append(processed_func)

                        if processed_path:
                            call_paths.append(processed_path)

            # If no paths found (empty paths_data), compute sample paths on-demand
            if len(call_paths) == 0:
                print(f"No paths available in analysis results. Computing sample paths on-demand...")
                reachable_funcs = reachable_data.get(entry_point, [])
                print(f"Found {len(reachable_funcs)} reachable functions from entry point")

                # Strategy: Sample a subset of interesting functions and compute paths to them
                # Priority: functions with source code (not library functions), larger functions
                functions_map = analysis_results.get('functions', {})
                call_graph = analysis_results.get('callGraph', {})

                # Filter and score reachable functions
                scored_funcs = []
                for func_name in reachable_funcs:
                    func_def = functions_map.get(func_name, {})
                    if not func_def:
                        continue

                    # Skip library/empty functions
                    source_code = func_def.get('SourceCode', '')
                    file_path = func_def.get('FilePath', '')
                    if not source_code or not file_path or file_path == '<empty>':
                        continue

                    # Score by source code length (prefer non-trivial functions)
                    score = len(source_code)
                    scored_funcs.append((score, func_name, func_def))

                # Sort by score descending, take top targets
                scored_funcs.sort(reverse=True, key=lambda x: x[0])
                top_targets = scored_funcs[:10]  # Top 10 interesting functions (reduced to save context)

                print(f"Selected {len(top_targets)} interesting target functions for path computation")

                # Compute paths to these targets using BFS on call graph
                call_graph_edges = call_graph.get('Calls', []) if call_graph else []

                # Build adjacency list
                adj = {}
                for edge in call_graph_edges:
                    caller = edge.get('Caller', '')
                    callee = edge.get('Callee', '')
                    if caller and callee:
                        if caller not in adj:
                            adj[caller] = []
                        adj[caller].append(callee)

                print(f"Built call graph with {len(adj)} nodes, {len(call_graph_edges)} edges")

                # Check if call graph uses abbreviated names (bug in simple parser)
                sample_callers = list(adj.keys())[:5]
                uses_abbreviated_names = any(len(caller) <= 3 for caller in sample_callers)

                if uses_abbreviated_names:
                    print(f"Warning: Call graph uses abbreviated names, cannot compute paths reliably")
                    print(f"Falling back to sampling interesting reachable functions")

                    # Fallback: Return sample of interesting functions as 2-hop paths
                    # Create synthetic paths: entry_point -> interesting_function
                    for score, target_name, target_def in top_targets[:30]:
                        # Create 2-node path
                        entry_func = functions_map.get(entry_point, {})
                        processed_path = [
                            {
                                "file": entry_func.get('FilePath', ''),
                                "function": entry_func.get('Name', entry_point),
                                "body": entry_func.get('SourceCode', ''),
                                "line": str(entry_func.get('StartLine', '')),
                                "is_modified": False,
                                "is_vulnerable": False,
                            },
                            {
                                "file": target_def.get('FilePath', ''),
                                "function": target_def.get('Name', target_name),
                                "body": target_def.get('SourceCode', ''),
                                "line": str(target_def.get('StartLine', '')),
                                "is_modified": False,
                                "is_vulnerable": False,
                            }
                        ]
                        call_paths.append(processed_path)
                else:
                    # Try to compute real paths using BFS
                    print(f"Entry point in call graph: {entry_point in adj}")
                    if entry_point in adj:
                        print(f"Entry point has {len(adj[entry_point])} direct callees")

                    for i, (score, target_name, target_def) in enumerate(top_targets):
                        # Increased max_depth to 15 to handle long paths, but only return 1 path per target
                        paths = _find_paths_bfs(entry_point, target_name, adj, max_depth=15, max_paths=1)

                        for path in paths:
                            processed_path = []
                            for node_name in path:
                                func_def = functions_map.get(node_name, {})
                                processed_func = {
                                    "file": func_def.get('FilePath', ''),
                                    "function": func_def.get('Name', node_name),
                                    "body": func_def.get('SourceCode', ''),
                                    "line": str(func_def.get('StartLine', '')),
                                    "is_modified": False,
                                    "is_vulnerable": False,
                                }
                                processed_path.append(processed_func)

                            if len(processed_path) > 1:
                                call_paths.append(processed_path)

                        # Stop if we have enough paths
                        if len(call_paths) >= 30:
                            break

            print(f"Extracted {len(call_paths)} paths for entry point {entry_point}")
            return call_paths

        # For each target function, get the paths
        # First check if paths are pre-computed in paths_data
        has_precomputed_paths = any(
            paths_data.get(f"{entry_point}-{file_path.replace(os.sep, '/')}.{func['name']}", [])
            for file_path, functions in target_functions.items()
            for func in functions
        )

        # If no pre-computed paths, compute them on-demand
        if not has_precomputed_paths:
            print(f"No pre-computed paths found. Computing paths on-demand for {len(target_functions)} target files...")

            functions_map = analysis_results.get('functions', {})
            call_graph = analysis_results.get('callGraph', {})

            # Build adjacency list for BFS
            call_graph_edges = call_graph.get('Calls', []) if call_graph else []
            adj = {}
            for edge in call_graph_edges:
                caller = edge.get('Caller', '')
                callee = edge.get('Callee', '')
                if caller and callee:
                    if caller not in adj:
                        adj[caller] = []
                    adj[caller].append(callee)

            print(f"Built call graph with {len(adj)} nodes, {len(call_graph_edges)} edges")

            # Compute paths for each target function
            for file_path, functions in target_functions.items():
                normalized_file_path = file_path.replace(os.sep, '/')

                for func_info in functions:
                    func_name = func_info['name']
                    target_signature = f"{normalized_file_path}.{func_name}"

                    # Find paths using BFS
                    paths = _find_paths_bfs(entry_point, target_signature, adj, max_depth=15, max_paths=1)

                    if paths:
                        print(f"Found {len(paths)} path(s) to {target_signature}")
                        for path in paths:
                            processed_path = []
                            for node_name in path:
                                func_def = functions_map.get(node_name, {})
                                processed_func = {
                                    "file": func_def.get('FilePath', ''),
                                    "function": func_def.get('Name', node_name),
                                    "body": func_def.get('SourceCode', ''),
                                    "line": str(func_def.get('StartLine', '')),
                                    "is_modified": node_name in [f['name'] for f in sum([funcs for funcs in target_functions.values()], [])],
                                    "is_vulnerable": False,
                                }
                                processed_path.append(processed_func)

                            if processed_path:
                                call_paths.append(processed_path)
                    else:
                        print(f"No paths found to {target_signature}")
        else:
            # Use pre-computed paths from paths_data
            for file_path, functions in target_functions.items():
                normalized_file_path = file_path.replace(os.sep, '/')

                for func_info in functions:
                    func_name = func_info['name']
                    target_signature = f"{normalized_file_path}.{func_name}"
                    composite_key = f"{entry_point}-{target_signature}"

                    target_paths = paths_data.get(composite_key, [])

                    if target_paths:
                        print(f"Found {len(target_paths)} paths for {composite_key}")
                    else:
                        print(f"No paths found for {composite_key}")

                    # Process each path
                    for path in target_paths:
                        processed_path = []
                        for node_name in path:
                            func_def = analysis_results.get('functions', {}).get(node_name, {})
                            processed_func = {
                                "file": func_def.get('FilePath', ''),
                                "function": func_def.get('Name', node_name),
                                "body": func_def.get('SourceCode', ''),
                                "line": str(func_def.get('StartLine', '')),
                                "is_modified": node_name in [f['name'] for f in sum([funcs for funcs in target_functions.values()], [])],
                                "is_vulnerable": False,
                            }
                            processed_path.append(processed_func)

                        if processed_path:
                            call_paths.append(processed_path)

    return call_paths

# ============================================================================
# Joern CPG Query Functions
# ============================================================================

def query_joern_cpg(cpg_path: str, query: str, timeout: int = 60) -> str:
    """
    Execute a Joern query on a CPG and return results.

    Args:
        cpg_path: Path to the CPG.bin file
        query: Joern/Scala query string
        timeout: Query timeout in seconds

    Returns:
        Query output as string
    """
    import tempfile
    import subprocess

    # Create a temporary script file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sc', delete=False) as f:
        script_path = f.name
        f.write(f'''
importCpg("{cpg_path}")

{query}

exit
''')

    try:
        # Run joern with the script
        result = subprocess.run(
            ['joern', '--script', script_path],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0:
            raise RuntimeError(f"Joern query failed: {result.stderr}")

        return result.stdout
    finally:
        os.unlink(script_path)


def get_all_functions_joern(cpg_path: str) -> List[Dict[str, Any]]:
    """
    Get all functions from the Joern CPG with their metadata.

    Args:
        cpg_path: Path to the CPG.bin file

    Returns:
        List of function dictionaries with keys: name, file, startLine, endLine, signature
    """
    query = '''
// Output as simple CSV format that we can parse
cpg.method.foreach { m =>
  val name = m.fullName
  val file = m.filename
  val startLine = m.lineNumber.getOrElse(0)
  val endLine = m.lineNumberEnd.getOrElse(0)
  val sig = m.signature
  println(s"FUNC|||${name}|||${file}|||${startLine}|||${endLine}|||${sig}")
}
'''

    output = query_joern_cpg(cpg_path, query)
    functions = []
    for line in output.split('\n'):
        if line.startswith('FUNC|||'):
            parts = line.split('|||')
            if len(parts) >= 6:
                functions.append({
                    'name': parts[1],
                    'file': parts[2],
                    'startLine': int(parts[3]) if parts[3].isdigit() else 0,
                    'endLine': int(parts[4]) if parts[4].isdigit() else 0,
                    'signature': parts[5]
                })
    return functions


def get_reachable_functions_joern(
    cpg_path: str,
    entry_point: str,
    max_depth: int = 100
) -> List[str]:
    """
    Find all functions reachable from an entry point using BFS in Joern.

    Args:
        cpg_path: Path to CPG
        entry_point: Entry point function name (e.g., "LLVMFuzzerTestOneInput")
        max_depth: Maximum call depth to traverse

    Returns:
        List of reachable function names
    """
    query = f'''
// Find reachable functions using BFS
def findReachable(startMethod: io.shiftleft.codepropertygraph.generated.nodes.Method, maxDepth: Int = {max_depth}): List[String] = {{
  import scala.collection.mutable
  val visited = mutable.Set[String]()
  val queue = mutable.Queue[(String, Int)]((startMethod.fullName, 0))
  val result = mutable.ListBuffer[String]()

  while (queue.nonEmpty) {{
    val (currentName, depth) = queue.dequeue()
    if (!visited.contains(currentName) && depth < maxDepth) {{
      visited.add(currentName)

      val currentMethods = cpg.method.fullName(currentName).l
      currentMethods.foreach {{ m =>
        m.callOut.foreach {{ call =>
          call.calledMethod.foreach {{ callee =>
            val calleeName = callee.fullName
            if (!visited.contains(calleeName)) {{
              queue.enqueue((calleeName, depth + 1))
              result += calleeName
            }}
          }}
        }}
      }}
    }}
  }}
  result.toList
}}

// Find entry point
val entryMethod = cpg.method.fullName(".*{entry_point}.*").l.headOption

entryMethod match {{
  case Some(m) =>
    val reachable = findReachable(m, {max_depth})
    reachable.foreach(f => println(s"REACHABLE|||$f"))
    println("DONE")
  case None =>
    println("DONE")
}}
'''

    output = query_joern_cpg(cpg_path, query)
    functions = []
    for line in output.split('\n'):
        if line.startswith('REACHABLE|||'):
            parts = line.split('|||')
            if len(parts) >= 2:
                functions.append(parts[1])
    return functions


def get_function_source_joern(cpg_path: str, function_name: str) -> Optional[str]:
    """
    Get the source code for a specific function from Joern CPG.

    Args:
        cpg_path: Path to CPG
        function_name: Full name of the function

    Returns:
        Source code string or None if not found
    """
    # Escape special characters in function name for regex
    escaped_name = function_name.replace("\\", "\\\\").replace("\"", "\\\"")

    query = f'''
val method = cpg.method.fullName(".*{escaped_name}.*").headOption

method match {{
  case Some(m) =>
    val code = m.code.headOption.getOrElse("")
    println(code)
  case None =>
    println("NOT_FOUND")
}}
'''

    output = query_joern_cpg(cpg_path, query)
    lines = [l.strip() for l in output.split('\n') if l.strip()]
    if lines and lines[-1] != "NOT_FOUND":
        return lines[-1]
    return None


def get_call_paths_joern(
    cpg_path: str,
    entry_point: str,
    target_functions: List[str],
    max_depth: int = 10
) -> List[List[str]]:
    """
    Find call paths from entry point to target functions using Joern.

    Args:
        cpg_path: Path to CPG
        entry_point: Entry point function name
        target_functions: List of target function names to find paths to
        max_depth: Maximum path depth

    Returns:
        List of call paths, where each path is a list of function names
    """
    # Escape function names
    escaped_targets = [t.replace("\\", "\\\\").replace("\"", "\\\"") for t in target_functions]
    targets_str = '", "'.join(escaped_targets)

    query = f'''
// Find paths from entry to targets
val entryMethod = cpg.method.fullName(".*{entry_point}.*").l.headOption
val targetNames = Set("{targets_str}")

def findPaths(
    start: io.shiftleft.codepropertygraph.generated.nodes.Method,
    targets: Set[String],
    maxDepth: Int
): List[List[String]] = {{
  import scala.collection.mutable

  val allPaths = mutable.ListBuffer[List[String]]()

  def dfs(
      current: String,
      path: List[String],
      visited: Set[String],
      depth: Int
  ): Unit = {{
    if (depth > maxDepth) return

    // Check if we reached a target
    if (targets.exists(t => current.contains(t))) {{
      allPaths += (path :+ current)
      return
    }}

    // Continue DFS
    val currentMethods = cpg.method.fullName(current).l
    currentMethods.foreach {{ m =>
      m.callOut.foreach {{ call =>
        call.calledMethod.foreach {{ callee =>
          val calleeName = callee.fullName
          if (!visited.contains(calleeName)) {{
            dfs(calleeName, path :+ current, visited + calleeName, depth + 1)
          }}
        }}
      }}
    }}
  }}

  dfs(start.fullName, List(), Set(start.fullName), 0)
  allPaths.toList
}}

entryMethod match {{
  case Some(m) =>
    val paths = findPaths(m, targetNames, {max_depth})
    println(upickle.default.write(paths))
  case None =>
    println("[]")
}}
'''

    output = query_joern_cpg(cpg_path, query)
    for line in output.split('\n'):
        if line.strip().startswith('['):
            return json.loads(line)
    return []
