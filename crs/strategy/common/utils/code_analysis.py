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

    Args:
        task_id: Task identifier
        task_dir: Path to the task directory (may be overridden if incorrect)
        focus: Focus area identifier (e.g., project component name)

    Returns:
        True if analysis completed successfully, False otherwise
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

    # Determine entry point based on file extension
    if fuzzer_source_path.endswith('.java'):
        entry_point = f"{fuzzer_source_path}.fuzzerTestOneInput"
    else:
        entry_point = f"{fuzzer_source_path}.LLVMFuzzerTestOneInput"

    # Try QX format first (has 'reachable' field)
    reachable_names = results.get('reachable', {}).get(entry_point, [])

    # If QX format didn't work, try regular format (has 'ReachableFunctions' field)
    if not reachable_names:
        reachable_names = results.get('ReachableFunctions', {}).get(entry_point, [])

    # Also try with uppercase field names (some formats use these)
    if not reachable_names:
        reachable_names = results.get('Reachable', {}).get(entry_point, [])

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

        # Determine the entry point based on fuzzer file extension
        fuzzer_key = fuzzer_src_path.replace(os.sep, '/')
        if fuzzer_src_path.endswith('.java'):
            entry_point = f"{fuzzer_key}.fuzzerTestOneInput"
        else:
            entry_point = f"{fuzzer_key}.LLVMFuzzerTestOneInput"

        # For each target function, get the paths
        for file_path, functions in target_functions.items():
            # Normalize file path
            normalized_file_path = file_path.replace(os.sep, '/')

            for func_info in functions:
                func_name = func_info['name']

                # Construct the full target function signature
                target_signature = f"{normalized_file_path}.{func_name}"

                # Construct the composite key: fuzzer.entryPoint-target.function
                composite_key = f"{entry_point}-{target_signature}"

                # Try to find paths using the composite key
                target_paths = paths_data.get(composite_key, [])

                if target_paths:
                    print(f"Found {len(target_paths)} paths for {composite_key}")
                else:
                    print(f"No paths found for {composite_key}")

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

    return call_paths
