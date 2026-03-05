"""
Code Analysis Utilities

Functions for querying static analysis services and processing analysis results.
"""
import os
import re
import json
import time
import textwrap
import requests
from typing import Dict, List, Any, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from opentelemetry import trace

# Note: tracer is imported from global scope when needed


def extract_reachable_functions_from_analysis_service_for_c(
    fuzzer_path: str,
    fuzzer_src_path: str,
    focus: str,
    project_src_dir: str,
) -> List[Dict[str, Any]]:
    """
    Extract reachable functions from the static analysis service (C/C++ variant).

    Args:
        fuzzer_path: Path to fuzzer binary
        fuzzer_src_path: Path to fuzzer source file
        focus: Focus area identifier
        project_src_dir: Path to project source directory

    Returns:
        List of reachable function dicts with Name, Body, FilePath, etc.
    """
    ANALYSIS_SERVICE_URL = os.environ.get("ANALYSIS_SERVICE_URL", "http://localhost:7082")
    if "/v1/reachable" not in ANALYSIS_SERVICE_URL:
        ANALYSIS_SERVICE_URL = f"{ANALYSIS_SERVICE_URL}/v1/reachable"

    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "focus": focus,
        "project_src_dir": project_src_dir,
        "fuzzer_path": fuzzer_path,
        "fuzzer_source_path": fuzzer_src_path,
    }
    max_tries = 60
    backoff_sec = 30

    reachable_functions = []
    for attempt in range(1, max_tries + 1):
        try:
            print(f"[try {attempt}/{max_tries}] ANALYSIS_SERVICE_URL: {ANALYSIS_SERVICE_URL} payload: {payload}")
            resp = requests.post(ANALYSIS_SERVICE_URL, json=payload, timeout=60)

            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data.get("reachable"), list):
                    reachable_functions = data["reachable"]
                break
            else:
                print(f"Analysis service returned {resp.status_code} for {ANALYSIS_SERVICE_URL}")
                try:
                    print("Error details (JSON):", resp.json())
                except Exception:
                    print("Response body (not JSON):", resp.text)

        except Exception as e:
            print(f"Error querying analysis service on attempt {attempt}: {e}")

        if attempt < max_tries:
            time.sleep(backoff_sec)

    return reachable_functions


def extract_reachable_functions_from_analysis_service(
    fuzzer_path: str,
    fuzzer_src_path: str,
    focus: str,
    project_src_dir: str,
    use_both: bool = True,
) -> List[Dict[str, Any]]:
    """
    Extract reachable functions from the static analysis service (Java/general variant).
    Tries _qx endpoint first, then falls back to regular endpoint.

    Args:
        fuzzer_path: Path to fuzzer binary
        fuzzer_src_path: Path to fuzzer source file
        focus: Focus area identifier
        project_src_dir: Path to project source directory
        use_both: If True, try both _qx and regular endpoints per attempt

    Returns:
        List of reachable function dicts
    """
    ANALYSIS_SERVICE_URL = os.environ.get("ANALYSIS_SERVICE_URL", "http://localhost:7082")
    if "/v1/reachable" not in ANALYSIS_SERVICE_URL:
        ANALYSIS_SERVICE_URL = f"{ANALYSIS_SERVICE_URL}/v1/reachable"
    ANALYSIS_SERVICE_URL_QX = f"{ANALYSIS_SERVICE_URL}_qx"

    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "focus": focus,
        "project_src_dir": project_src_dir,
        "fuzzer_path": fuzzer_path,
        "fuzzer_source_path": fuzzer_src_path,
    }
    max_tries = 60
    backoff_sec = 30

    reachable_functions = []
    for attempt in range(1, max_tries + 1):
        try:
            print(f"[try {attempt}/{max_tries}] ANALYSIS_SERVICE_URL_QX: {ANALYSIS_SERVICE_URL_QX} payload: {payload}")
            resp = requests.post(ANALYSIS_SERVICE_URL_QX, json=payload, timeout=60)

            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data.get("reachable"), list):
                    reachable_functions = data["reachable"]
                    if len(reachable_functions) > 0:
                        return reachable_functions
            else:
                print(f"Analysis service returned {resp.status_code} for {ANALYSIS_SERVICE_URL_QX}")

            if use_both:
                print(f"[try {attempt}/{max_tries}] ANALYSIS_SERVICE_URL: {ANALYSIS_SERVICE_URL} payload: {payload}")
                resp = requests.post(ANALYSIS_SERVICE_URL, json=payload, timeout=60)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data.get("reachable"), list):
                        reachable_functions = data["reachable"]
                        if len(reachable_functions) > 0:
                            return reachable_functions

        except Exception as e:
            print(f"Error querying analysis service on attempt {attempt}: {e}")

        if attempt < max_tries:
            time.sleep(backoff_sec)

    return reachable_functions


def find_most_likely_vulnerable_functions(
    reachable_funcs: List[Dict[str, Any]],
    language: str,
    llm_client: Any,
    logger: Any,
    top_k: int = 10,
) -> List[Dict[str, Any]]:
    """
    Use LLM to score reachable functions by vulnerability likelihood.

    Args:
        reachable_funcs: List of reachable function dicts
        language: "c" or "java"
        llm_client: LLMClient instance
        logger: StrategyLogger instance
        top_k: Max number of results to return

    Returns:
        List of dicts with name, score, reason (sorted by score desc)
    """
    if not reachable_funcs:
        return []

    # Build function catalog
    func_catalog = []
    for f in reachable_funcs:
        name = f.get("name") or f.get("Name") or "<unknown>"
        body = (f.get("body") or f.get("Body") or
                f.get("sourceCode") or f.get("SourceCode") or "")
        snippet = f"Function: {name}\n{body}"
        func_catalog.append(snippet)

    catalog_text = "\n".join(func_catalog)

    # Truncate if too large
    word_count = len(re.findall(r'\w+', catalog_text))
    if word_count > 50_000:
        func_catalog = []
        for f in reachable_funcs:
            name = f.get("name") or f.get("Name") or "<unknown>"
            body = (f.get("body") or f.get("Body") or
                    f.get("sourceCode") or f.get("SourceCode") or "")
            if body.count('\n') <= 500:
                func_catalog.append(f"Function: {name}\n{body}")
        catalog_text = "\n".join(func_catalog)

    # Language-specific guidance
    if language.lower().startswith("c"):
        vuln_bullets = """an address, memory or UB sanitizer would catch.  Consider:
      - complex loops / parsing
      - string or buffer manipulation
      - pointer arithmetic, malloc/free
      - recursion, deep nesting
      - heavy use of user-controlled data

Typical sanitizer-detectable bugs in C/C++:
  - Buffer overflows (stack / heap / global)
  - Use-after-free, double-free, memory leaks
  - Integer over/under-flow, shift overflow
  - Uninitialised memory reads
  - NULL / mis-aligned pointer dereference
"""
    else:
        vuln_bullets = """
Jazzer can detect (non-exhaustive):
  - Deserialization issues
  - Path traversal
  - Regex denial-of-service
  - LDAP / SQL / XPath injection
  - Script engine injection, unsafe reflection
  - SSRF or RCE-style vulnerabilities
  - Unhandled runtime exceptions (NullPointerException, etc.)
"""

    prompt = textwrap.dedent(f"""
    Context: you are a world-class vulnerability researcher.

    Below is the list of functions reachable from the fuzzer entry-point.
    For each function, decide whether it is a *likely* place for a bug that
    {vuln_bullets}

    Return **JSON only**, no markdown, in this exact schema:

    [
      {{"name":"<funcName>", "score":<1-10>, "reason":"<short>"}},
      ...
    ]

    Provide at most {top_k} entries, sorted by descending score.

    Reachable functions:
    {catalog_text}
    """)

    messages = [
        {"role": "system", "content": "You are an expert in code security."},
        {"role": "user", "content": prompt}
    ]
    start = time.time()
    raw, ok = llm_client.call(messages, llm_client.config.models[0] if llm_client.config.models else "claude-sonnet-4-5-20250929")
    duration = time.time() - start

    if not ok:
        logger.warning(f"LLM call for vulnerability scoring failed in {duration:.1f}s")
        return []

    # Strip markdown fences if present
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
    if m:
        raw = m.group(1).strip()

    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list) and parsed:
            return parsed[:top_k]
    except json.JSONDecodeError:
        logger.warning("JSON parse failed for vulnerability scoring response")

    return []


def extract_vulnerable_functions(
    reachable_funcs: List[Dict[str, Any]],
    vulnerable_functions: List[Dict[str, Any]],
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """
    Filter reachable functions to only those identified as vulnerable.

    Args:
        reachable_funcs: Full list of reachable functions
        vulnerable_functions: LLM-scored vulnerable functions
        limit: Max functions to return

    Returns:
        Filtered list of reachable functions
    """
    if not vulnerable_functions:
        return reachable_funcs[:limit]

    top_names = [
        (vf.get("name") or vf.get("Name") or "").strip()
        for vf in vulnerable_functions[:limit]
    ]
    wanted = {name for name in top_names if name}

    filtered = []
    for f in reachable_funcs:
        name = (f.get("name") or f.get("Name") or "").strip()
        if name in wanted:
            filtered.append(f)

    return filtered


def convert_target_functions_format(
    reachable_funcs: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Convert reachable_funcs list into simplified format for call path extraction.

    Args:
        reachable_funcs: List of function dicts with FilePath, Name, StartLine

    Returns:
        Dict mapping file_path to list of {name, start_line} dicts
    """
    simplified = {}
    for func in reachable_funcs:
        file_path = func.get("FilePath") or func.get("file_path")
        name = func.get("Name") or func.get("name")
        start_line = func.get("StartLine") or func.get("start_line")

        if not file_path or not name or start_line is None:
            continue

        if file_path not in simplified:
            simplified[file_path] = []

        simplified[file_path].append({
            "name": name,
            "start_line": start_line
        })

    return simplified


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
