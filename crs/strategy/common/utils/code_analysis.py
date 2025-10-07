"""
Code Analysis Utilities

Functions for querying static analysis services and processing analysis results.
"""
import os
import time
import requests
from typing import Dict, List, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from opentelemetry import trace

# Note: tracer is imported from global scope when needed


def extract_call_paths_from_analysis_service(
    fuzzer_path: str,
    fuzzer_src_path: str,
    focus: str,
    project_src_dir: str,
    modified_functions: Dict[str, Any],
    use_qx: bool
) -> List[List[Dict[str, Any]]]:
    """
    Extract call paths leading to vulnerable functions by querying a static analysis service

    Makes HTTP requests to an analysis service endpoint that performs static
    analysis to find execution paths from the fuzzer entry point to potentially
    vulnerable functions identified in the commit diff.

    Args:
        fuzzer_path: Path to the compiled fuzzer binary
        fuzzer_src_path: Path to the fuzzer source file
        focus: Focus area identifier (e.g., project component name)
        project_src_dir: Path to the project source directory
        modified_functions: Dictionary of modified functions from parse_commit_diff()
        use_qx: Whether to use the qx (query extended) analysis endpoint

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
        ANALYSIS_SERVICE_URL: Base URL of the analysis service (default: http://localhost:7082)
        TASK_ID: Task identifier for tracking analysis requests
    """
    # Get analysis service endpoint
    ANALYSIS_SERVICE_URL = os.environ.get("ANALYSIS_SERVICE_URL", "http://localhost:7082")

    # Select endpoint based on use_qx flag
    if use_qx:
        if "/v1/analysis_qx" not in ANALYSIS_SERVICE_URL:
            ANALYSIS_SERVICE_URL = f"{ANALYSIS_SERVICE_URL}/v1/analysis_qx"
    else:
        if "/v1/analysis" not in ANALYSIS_SERVICE_URL:
            ANALYSIS_SERVICE_URL = f"{ANALYSIS_SERVICE_URL}/v1/analysis"

    # Simplify modified_functions to just file_path and function names
    simplified_modified_functions = {}
    for file_path, file_info in modified_functions.items():
        function_info = []
        for func in file_info.get("modified_functions", []):
            function_info.append({
                "name": func["name"],
                "start_line": func["start_line"]
            })
        if function_info:  # Only include if there are functions
            simplified_modified_functions[file_path] = function_info

    # Build request payload
    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "focus": focus,
        "project_src_dir": project_src_dir,
        "fuzzer_path": fuzzer_path,
        "fuzzer_source_path": fuzzer_src_path,
        "target_functions": simplified_modified_functions,
    }

    # Initialize result list
    call_paths = []

    # Retry configuration
    max_tries = 60  # Total attempts
    backoff_sec = 30  # Initial back-off in seconds

    # Import tracer if available
    try:
        from opentelemetry import trace
        tracer = trace.get_tracer(__name__)
        use_tracing = True
    except ImportError:
        use_tracing = False

    # Attempt requests with retries
    for attempt in range(1, max_tries + 1):
        # Early exit check (check if POV already found by another process)
        # Note: This requires access to has_successful_pov0() which may not be
        # available in this module. Consider removing or adding as parameter.
        # For now, commented out to avoid dependency.
        # if has_successful_pov0(fuzzer_path):
        #     print(f"Early return {len(call_paths)} call_paths\n")
        #     return call_paths

        try:
            print(f"ANALYSIS_SERVICE_URL: {ANALYSIS_SERVICE_URL} payload: {payload}")

            if use_tracing:
                with tracer.start_as_current_span("analysis_service.request") as span:
                    span.set_attribute("crs.action.category", "static_analysis")
                    span.set_attribute("crs.action.name", "extract_call_paths")
                    span.set_attribute("payload", f"{payload}")

                    # Make request to analysis service (5 mins timeout)
                    response = requests.post(ANALYSIS_SERVICE_URL, json=payload, timeout=300)
            else:
                # Make request without tracing
                response = requests.post(ANALYSIS_SERVICE_URL, json=payload, timeout=300)

            if response.status_code == 200:
                result = response.json()

                if "call_paths" in result and isinstance(result["call_paths"], list):
                    raw_call_paths = result["call_paths"]

                    # Process each call path
                    for call_path_obj in raw_call_paths:
                        processed_path = []

                        # Extract the nodes array from the call path object
                        if "nodes" not in call_path_obj or not isinstance(call_path_obj["nodes"], list):
                            continue  # Skip if no nodes array

                        for func_info in call_path_obj["nodes"]:
                            file_path = func_info.get("file", "")
                            function_name = func_info.get("function", "")
                            func_body = func_info.get("body", "")
                            line = func_info.get("line", "")

                            # Construct processed function info
                            processed_func = {
                                "file": file_path,
                                "function": function_name,
                                "body": func_body,
                                "line": line,
                                "is_modified": func_info.get("is_modified", False),
                                "is_vulnerable": func_info.get("is_vulnerable", False),
                            }

                            processed_path.append(processed_func)

                        # Only add non-empty paths
                        if processed_path:
                            call_paths.append(processed_path)

                # Success - break out of retry loop
                break

            else:
                print(f"Analysis service returned non-200 status: {response.status_code}")
                try:
                    error_details = response.json()
                    print("Error details (JSON):", error_details)
                except Exception:
                    print("Response body (not JSON):", response.text)

        except Exception as e:
            print(f"Error querying analysis service: {str(e)}")

        # Only sleep if we will retry again
        if attempt < max_tries:
            time.sleep(backoff_sec)

    print(f"Received {len(call_paths)} call_paths\n")
    return call_paths
