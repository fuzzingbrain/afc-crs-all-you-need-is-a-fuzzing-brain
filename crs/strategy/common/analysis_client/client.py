"""Static analysis integration.

Entry points for the external analysis service, the local CodeQL /
custom analyser fallback, Joern CPG queries, LLM-based vulnerability
scoring, and a small on-disk cache layer.

TODO(tech-debt): this file was lifted from ``common/utils/code_analysis.py``
as part of the subpackage migration and is still a monolith (~1900
lines covering HTTP client, local analyser, Joern helpers, scoring,
and cache). A follow-up will split it into focused submodules under
``common/analysis_client/`` (client.py / local.py / qx.py / joern.py
/ scoring.py / cache.py). For now everything lives here and the
legacy ``common.utils.code_analysis`` import path remains as a
backward-compatibility shim.
"""
import os
import time
import json
import subprocess
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from opentelemetry import trace

# Note: tracer is imported from global scope when needed


# ============================================================================
# LLM-based Vulnerability Scoring
# ============================================================================

def _compute_cache_key(
    repo_path: str,
    entry_point: str,
    paths: List[List[Dict[str, Any]]],
    model: str,
    config: Dict[str, Any]
) -> str:
    """
    Compute a cache key for LLM path analysis results.

    Cache key includes:
    - Repository path
    - Entry point name
    - Hash of all paths (structure + function names)
    - Model name
    - Configuration (SIZE_PREFILTER, MAX_PATHS_TO_EXTRACT, etc.)

    This ensures cache is invalidated when code or configuration changes.
    """
    # Create a deterministic representation of paths
    # Include function names and file paths, but not full source (too big)
    path_fingerprint = []
    for path in paths:
        path_sig = tuple((step.get('function', ''), step.get('file', '')) for step in path)
        path_fingerprint.append(path_sig)

    # Combine all inputs into cache key
    cache_data = {
        'repo_path': repo_path,
        'entry_point': entry_point,
        'paths': path_fingerprint,
        'model': model,
        'config': config
    }

    # Create hash of cache key
    cache_str = json.dumps(cache_data, sort_keys=True)
    cache_hash = hashlib.sha256(cache_str.encode()).hexdigest()[:16]

    return cache_hash


def _get_cache_path(repo_path: str) -> str:
    """Get the path to the LLM analysis cache file."""
    return os.path.join(repo_path, '.llm_path_analysis_cache.json')


def _load_cached_analysis(
    repo_path: str,
    entry_point: str,
    paths: List[List[Dict[str, Any]]],
    model: str,
    config: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    """
    Load cached LLM analysis results if available and valid.

    Returns cached results or None if cache miss/invalid.
    """
    cache_file = _get_cache_path(repo_path)

    if not os.path.exists(cache_file):
        return None

    try:
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)

        # Compute cache key for current analysis
        cache_key = _compute_cache_key(repo_path, entry_point, paths, model, config)

        # Check if cache entry exists
        if cache_key not in cache_data:
            return None

        entry = cache_data[cache_key]

        # Check cache age (invalidate after 24 hours)
        cache_age = time.time() - entry['timestamp']
        if cache_age > 86400:  # 24 hours
            print(f"  Cache expired (age: {cache_age / 3600:.1f} hours)")
            return None

        print(f"  ✓ Found cached LLM analysis (age: {cache_age / 60:.1f} minutes, {len(entry['results'])} paths)")
        return entry['results']

    except Exception as e:
        print(f"  Warning: Failed to load cache: {e}")
        return None


def _save_cached_analysis(
    repo_path: str,
    entry_point: str,
    paths: List[List[Dict[str, Any]]],
    model: str,
    config: Dict[str, Any],
    results: List[Dict[str, Any]]
):
    """
    Save LLM analysis results to cache.

    Cache is stored as JSON with timestamp and metadata.
    """
    cache_file = _get_cache_path(repo_path)

    try:
        # Load existing cache
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
        else:
            cache_data = {}

        # Compute cache key
        cache_key = _compute_cache_key(repo_path, entry_point, paths, model, config)

        # Store results with metadata
        cache_data[cache_key] = {
            'timestamp': time.time(),
            'entry_point': entry_point,
            'model': model,
            'num_paths': len(paths),
            'config': config,
            'results': results
        }

        # Clean up old entries (keep last 10)
        if len(cache_data) > 10:
            # Sort by timestamp, keep newest 10
            sorted_keys = sorted(cache_data.keys(),
                               key=lambda k: cache_data[k]['timestamp'],
                               reverse=True)
            cache_data = {k: cache_data[k] for k in sorted_keys[:10]}

        # Save cache
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)

        print(f"  ✓ Saved LLM analysis to cache ({len(results)} paths)")

    except Exception as e:
        print(f"  Warning: Failed to save cache: {e}")


def score_functions_with_llm(
    functions: List[Tuple[str, str, str]],  # (name, source, filepath)
    model: str = "claude-sonnet-4-5-20250929"
) -> List[Dict[str, Any]]:
    """
    Score functions by vulnerability potential using Claude API

    Args:
        functions: List of (function_name, source_code, file_path) tuples
        model: Claude model to use for analysis

    Returns:
        List of dicts with score, risk_level, reasons, and patterns
    """
    try:
        from anthropic import Anthropic
    except ImportError as e:
        # Try adding venv site-packages to path if running from venv
        import sys
        import site

        venv_path = os.environ.get('VIRTUAL_ENV')
        if venv_path:
            # Add venv site-packages to sys.path
            python_version = f"python{sys.version_info.major}.{sys.version_info.minor}"
            site_packages = os.path.join(venv_path, "lib", python_version, "site-packages")
            if os.path.exists(site_packages) and site_packages not in sys.path:
                sys.path.insert(0, site_packages)
                print(f"  Added venv site-packages to path: {site_packages}")
                try:
                    from anthropic import Anthropic
                    print("  ✓ Successfully imported anthropic after adding venv to path")
                except ImportError as e2:
                    print(f"  Warning: anthropic still not found after adding venv: {e2}")
                    print(f"  Python executable: {sys.executable}")
                    print("  Falling back to size-based scoring")
                    return [{"score": min(100, len(src) // 100), "risk_level": "unknown",
                             "reasons": ["LLM unavailable - anthropic not found in venv"], "vulnerability_patterns": []}
                            for _, src, _ in functions]
            else:
                print("Warning: anthropic package not installed, falling back to size-based scoring")
                print(f"  Import error: {e}")
                print(f"  Python executable: {sys.executable}")
                print(f"  VIRTUAL_ENV: {venv_path}")
                print(f"  Site packages path: {site_packages} (exists: {os.path.exists(site_packages)})")
                print("  Install with: pip install anthropic")
                return [{"score": min(100, len(src) // 100), "risk_level": "unknown",
                         "reasons": ["LLM unavailable - anthropic package not installed"], "vulnerability_patterns": []}
                        for _, src, _ in functions]
        else:
            print("Warning: anthropic package not installed, falling back to size-based scoring")
            print(f"  Import error: {e}")
            print(f"  Python executable: {sys.executable}")
            print("  VIRTUAL_ENV not set")
            print("  Install with: pip install anthropic")
            return [{"score": min(100, len(src) // 100), "risk_level": "unknown",
                     "reasons": ["LLM unavailable - anthropic package not installed"], "vulnerability_patterns": []}
                    for _, src, _ in functions]

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Warning: ANTHROPIC_API_KEY not set, falling back to size-based scoring")
        print("  Set your API key with: export ANTHROPIC_API_KEY='your-key'")
        return [{"score": min(100, len(src) // 100), "risk_level": "unknown",
                 "reasons": ["LLM unavailable - API key not set"], "vulnerability_patterns": []}
                for _, src, _ in functions]

    client = Anthropic(api_key=api_key)
    results = []

    for i, (func_name, source_code, file_path) in enumerate(functions):
        print(f"  [{i+1}/{len(functions)}] Analyzing {func_name} with LLM...")

        prompt = f"""Analyze this C/C++ function for vulnerability potential and fuzzing priority.

Function: {func_name}
File: {file_path}

Source Code:
```c
{source_code[:3000]}
```

Score 0-100 based on vulnerability risk. Look for:
- Buffer operations (strcpy, memcpy, sprintf, strcat, gets, scanf)
- Pointer arithmetic and unchecked derefs
- Format strings with user input
- Integer overflow potential
- Memory allocation without checks
- Input parsing (especially strings, URLs, headers)
- Complex branching and error paths
- Type conversions and casts

High scores (80-100): Buffer ops, parsing, format strings
Medium scores (50-79): Memory ops, complex logic
Low scores (0-49): Simple operations

Respond ONLY with JSON:
{{"score": <0-100>, "risk_level": "<critical|high|medium|low>", "reasons": ["reason1", "reason2"], "vulnerability_patterns": ["pattern1", "pattern2"]}}"""

        try:
            response = client.messages.create(
                model=model,
                max_tokens=512,
                temperature=0.0,
                messages=[{"role": "user", "content": prompt}]
            )

            result_text = response.content[0].text.strip()

            # Extract JSON from markdown if needed
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0].strip()

            result = json.loads(result_text)
            results.append(result)

        except Exception as e:
            print(f"    Warning: LLM scoring failed for {func_name}: {str(e)}")
            # Fallback to size heuristic
            results.append({
                "score": min(100, len(source_code) // 100),
                "risk_level": "unknown",
                "reasons": ["LLM analysis failed"],
                "vulnerability_patterns": []
            })

        # Rate limiting
        if i < len(functions) - 1:
            time.sleep(0.1)

    return results


def _score_single_path_with_llm(
    path_index: int,
    path: List[Dict[str, Any]],
    entry_point: str,
    model: str,
    api_key: str,
    progress_lock: Any
) -> Dict[str, Any]:
    """
    Score a single execution path (used for parallel processing).

    Args:
        path_index: Index of this path (for progress reporting)
        path: Single execution path to analyze
        entry_point: Entry point function name
        model: Claude model to use
        api_key: Anthropic API key
        progress_lock: Threading lock for progress reporting

    Returns:
        Dict with score, risk_level, reasons, attack_vector, vulnerable_step, blocking_checks
    """
    try:
        from anthropic import Anthropic
        import json

        client = Anthropic(api_key=api_key)

        # Build path visualization
        path_steps = []
        for step in path:
            func_name = step.get('function', 'unknown')
            file_path = step.get('file', 'unknown')
            path_steps.append(f"{func_name} in {file_path}")

        # Build detailed function info for each step
        function_details = []
        for j, step in enumerate(path, 1):
            func_name = step.get('function', 'unknown')
            source = step.get('body', '')
            # Truncate very long source code
            truncated_source = source[:1000] if len(source) > 1000 else source
            function_details.append(f"""
Step {j}: {func_name}
```c
{truncated_source}
{'... (truncated)' if len(source) > 1000 else ''}
```
""")

        prompt = f"""Analyze this EXECUTION PATH for exploitability in a fuzzing context.

ENTRY POINT: {entry_point}

EXECUTION PATH ({len(path)} functions):
{' → '.join(path_steps)}

FUNCTION DETAILS:
{''.join(function_details)}

ANALYSIS QUESTIONS:

1. DATA FLOW:
   - Can attacker-controlled input reach the final function?
   - What transformations/validations happen along the way?
   - Are there sanitization steps that would block exploitation?

2. VULNERABILITY ASSESSMENT:
   - What dangerous operations exist in this path?
   - Are they reachable with attacker-controlled data?
   - Are there exploitable conditions?

3. EXPLOIT FEASIBILITY:
   - How complex would it be to trigger a vulnerability?
   - Are there checks that must be bypassed?
   - What's the most likely vulnerability in this path?

4. FUZZING PRIORITY:
   - How valuable is this path for fuzzing?
   - Is it likely to find bugs?

Score 0-100 based on REALISTIC exploitability of this COMPLETE PATH:
- 90-100: Direct path to exploitable vulnerability (e.g., unchecked buffer op with attacker data)
- 70-89: Likely exploitable with some effort (some checks but bypassable)
- 50-69: Potentially exploitable (requires specific conditions)
- 30-49: Low exploitability (significant mitigations in place)
- 0-29: Unlikely exploitable (well-protected or no dangerous operations)

Respond ONLY with JSON:
{{
  "score": <0-100>,
  "risk_level": "<critical|high|medium|low>",
  "reasons": ["reason1", "reason2"],
  "attack_vector": "description of how to exploit this path",
  "blocking_checks": ["check1", "check2"],
  "vulnerable_step": "which function/step is most vulnerable"
}}"""

        response = client.messages.create(
            model=model,
            max_tokens=1024,
            temperature=0.0,
            messages=[{"role": "user", "content": prompt}]
        )

        result_text = response.content[0].text.strip()

        # Extract JSON from response
        if "```json" in result_text:
            result_text = result_text.split("```json")[1].split("```")[0].strip()
        elif "```" in result_text:
            result_text = result_text.split("```")[1].split("```")[0].strip()

        result = json.loads(result_text)

        # Thread-safe progress reporting
        with progress_lock:
            risk = result.get('risk_level', 'unknown')
            score = result.get('score', 0)
            print(f"    [{path_index}] Score: {score}/100, Risk: {risk}")

        return result

    except Exception as e:
        with progress_lock:
            print(f"    [{path_index}] Warning: Path analysis failed: {e}")
        return {
            "score": 0,
            "risk_level": "unknown",
            "reasons": [f"Analysis failed: {e}"],
            "attack_vector": "unknown",
            "blocking_checks": [],
            "vulnerable_step": "unknown"
        }


def score_paths_with_llm(
    entry_point: str,
    paths: List[List[Dict[str, Any]]],  # List of paths, each path is list of function dicts
    model: str = "claude-sonnet-4-5-20250929",
    repo_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Score execution paths for vulnerability potential using Claude API (PARALLEL VERSION with CACHING).

    This analyzes complete execution paths from entry point to target,
    considering data flow, validations, and realistic exploitability.

    Uses parallel processing to analyze multiple paths concurrently for speed.
    Results are cached to avoid redundant LLM calls on reruns.

    Args:
        entry_point: Name of entry point function
        paths: List of execution paths, each path is a list of function dicts with 'function', 'body', 'file'
        model: Claude model to use
        repo_path: Optional path to repository for caching (if None, caching is disabled)

    Returns:
        List of dicts with: score (0-100), risk_level, reasons, attack_vector, vulnerable_step, blocking_checks
    """
    # Try to load from cache if repo_path provided
    if repo_path:
        # Build config for cache key
        config = {
            'SIZE_PREFILTER': os.environ.get('SIZE_PREFILTER', '200'),
            'MAX_PATHS_TO_EXTRACT': os.environ.get('MAX_PATHS_TO_EXTRACT', '100'),
            'LLM_ANALYSIS_WORKERS': os.environ.get('LLM_ANALYSIS_WORKERS', '8'),
        }

        cached_results = _load_cached_analysis(repo_path, entry_point, paths, model, config)
        if cached_results is not None:
            return cached_results

        print(f"  No valid cache found, running fresh LLM analysis")
    # Check if anthropic is available
    try:
        from anthropic import Anthropic
    except ImportError as e:
        # Try adding venv site-packages to path if running from venv
        import sys
        venv_path = os.environ.get('VIRTUAL_ENV')
        if venv_path:
            # Add venv site-packages to sys.path
            python_version = f"python{sys.version_info.major}.{sys.version_info.minor}"
            site_packages = os.path.join(venv_path, "lib", python_version, "site-packages")
            if os.path.exists(site_packages) and site_packages not in sys.path:
                sys.path.insert(0, site_packages)
                print(f"  Added venv site-packages to path: {site_packages}")
                try:
                    from anthropic import Anthropic
                    print(f"  ✓ Successfully imported anthropic after adding venv to path")
                except ImportError:
                    print(f"Warning: anthropic package not installed, cannot score paths with LLM")
                    print(f"  Import error: {e}")
                    print(f"  Python executable: {sys.executable}")
                    print(f"  VIRTUAL_ENV: {venv_path}")
                    print(f"  Site packages path: {site_packages} (exists: {os.path.exists(site_packages)})")
                    print(f"  Install with: pip install anthropic")
                    return []
            else:
                print(f"Warning: anthropic package not installed, cannot score paths with LLM")
                print(f"  Install with: pip install anthropic")
                return []
        else:
            print(f"Warning: anthropic package not installed, cannot score paths with LLM")
            print(f"  Install with: pip install anthropic")
            return []

    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        print(f"Warning: ANTHROPIC_API_KEY not set, cannot score paths with LLM")
        return []

    # Parallel processing configuration
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading

    # Get max workers from environment (default: 8, can go up to 16)
    max_workers = int(os.environ.get('LLM_ANALYSIS_WORKERS', '8'))
    print(f"  Using {max_workers} parallel workers for LLM analysis")

    progress_lock = threading.Lock()
    results = [None] * len(paths)  # Pre-allocate results list to preserve order

    # Submit all paths for parallel processing
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_index = {
            executor.submit(
                _score_single_path_with_llm,
                i + 1,  # 1-indexed for progress display
                path,
                entry_point,
                model,
                api_key,
                progress_lock
            ): i
            for i, path in enumerate(paths)
        }

        # Collect results as they complete
        completed = 0
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            results[index] = future.result()
            completed += 1

            # Progress update (thread-safe)
            with progress_lock:
                if completed % 10 == 0 or completed == len(paths):
                    print(f"  Progress: {completed}/{len(paths)} paths analyzed")

    # Save results to cache if repo_path provided
    if repo_path:
        config = {
            'SIZE_PREFILTER': os.environ.get('SIZE_PREFILTER', '200'),
            'MAX_PATHS_TO_EXTRACT': os.environ.get('MAX_PATHS_TO_EXTRACT', '100'),
            'LLM_ANALYSIS_WORKERS': os.environ.get('LLM_ANALYSIS_WORKERS', '8'),
        }
        _save_cached_analysis(repo_path, entry_point, paths, model, config, results)

    return results


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
    for func_name in (reachable_names or []):
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
    if "/fuzz-tooling/build/out" in fuzzer_path:
        project_dir = fuzzer_path.split("/fuzz-tooling/build/out")[0] + "/"
    else:
        project_dir = os.path.dirname(os.path.dirname(fuzzer_path))

    task_dir = project_dir

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
    print(f"  task_dir: {task_dir}")
    print(f"  focus: {focus}")
    print(f"  project_src_dir: {project_src_dir}")
    print(f"  fuzzer_path: {fuzzer_path}")
    print(f"  fuzzer_source_path: {fuzzer_src_path}")

    try:
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
        success = run_static_analysis_local(task_dir, focus)
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
                target_paths = fuzzer_paths.get(func_name, []) or []

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

        # If we still don't have an entry point, find the best one from available candidates
        # Prefer entry points with the most reachable functions
        if not entry_point and reachable_data:
            # Sort entry points by number of reachable functions (descending)
            entry_point_candidates = [
                (ep, len(reachable_data[ep]) if reachable_data[ep] else 0)
                for ep in reachable_data.keys()
            ]
            entry_point_candidates.sort(key=lambda x: x[1], reverse=True)

            # Use the entry point with the most reachable functions
            if entry_point_candidates:
                entry_point = entry_point_candidates[0][0]
                num_reachable = entry_point_candidates[0][1]
                print(f"Selected entry point with most reachable functions: {entry_point} ({num_reachable} reachable)")

                # If the top one has 0, show alternatives
                if num_reachable == 0:
                    alternatives = [ep for ep, count in entry_point_candidates if count > 0]
                    if alternatives:
                        print(f"Note: Found {len(alternatives)} alternative entry points with reachable functions:")
                        for ep, count in entry_point_candidates[:5]:  # Show top 5
                            if count > 0:
                                print(f"  - {ep}: {count} reachable functions")
                        # Use the best alternative
                        entry_point = entry_point_candidates[0][0]
                        for ep, count in entry_point_candidates:
                            if count > 0:
                                entry_point = ep
                                print(f"Switching to entry point: {entry_point} ({count} reachable functions)")
                                break

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
                reachable_funcs = reachable_data.get(entry_point, []) or []
                print(f"Found {len(reachable_funcs)} reachable functions from entry point")

                # Strategy: Sample a subset of interesting functions and compute paths to them
                # Priority: functions with source code (not library functions), larger functions
                functions_map = analysis_results.get('functions', {})
                call_graph = analysis_results.get('callGraph', {})

                # Filter and score reachable functions
                scored_funcs = []
                for func_name in reachable_funcs:
                    # Skip operators and unresolved namespaces
                    if func_name.startswith('<operator>') or func_name.startswith('<unresolvedNamespace>'):
                        continue

                    # Try direct match first
                    func_def = functions_map.get(func_name, {})

                    # If not found, try fuzzy matching by base function name
                    if not func_def:
                        # Extract base name (e.g., "Buffer.Buffer" from "Buffer.Buffer:void(ANY,ANY)")
                        base_name = func_name.split(':')[0] if ':' in func_name else func_name
                        for key, val in functions_map.items():
                            if base_name in key or key.endswith(base_name):
                                func_def = val
                                break

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

                # Use LLM-based vulnerability scoring by default
                # Set USE_LLM_VULNERABILITY_SCORING=false to disable
                use_llm_scoring = os.environ.get('USE_LLM_VULNERABILITY_SCORING', 'true').lower() == 'true'
                # Aggressive settings optimized for $100 budget
                size_prefilter = int(os.environ.get('SIZE_PREFILTER', '200'))  # Top 200 candidates (configurable)

                if use_llm_scoring and len(scored_funcs) > 0:
                    print(f"PATH-BASED LLM vulnerability scoring enabled")
                    print(f"Step 1: Size-based prefiltering (top {size_prefilter} candidates)")

                    # Get top candidates by size
                    size_candidates = scored_funcs[:size_prefilter]
                    print(f"  Selected {len(size_candidates)} candidates for path extraction")

                    # Step 2: Build call graph and extract paths
                    print(f"Step 2: Extracting execution paths to candidate functions")
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

                    # Check if call graph is usable
                    sample_callers = list(adj.keys())[:20]
                    useless_callers = sum(1 for c in sample_callers if c.startswith('<operator>') or c.startswith('<unresolved') or len(c) <= 3)
                    uses_abbreviated_names = len(sample_callers) > 0 and (useless_callers / len(sample_callers)) > 0.5

                    if uses_abbreviated_names:
                        print(f"  Warning: Call graph is mostly operators ({useless_callers}/{len(sample_callers)})")
                        print(f"  Falling back to function-based LLM scoring")

                        # Fallback: Use function-based scoring
                        functions_to_score = [
                            (func_name, func_def.get('SourceCode', ''), func_def.get('FilePath', ''))
                            for _, func_name, func_def in size_candidates[:20]  # Reduced to 20 for fallback
                        ]

                        llm_results = score_functions_with_llm(functions_to_score)

                        # Re-score with LLM scores
                        llm_scored = []
                        for (size_score, func_name, func_def), llm_result in zip(size_candidates[:20], llm_results):
                            llm_score = llm_result.get('score', size_score // 100)
                            risk_level = llm_result.get('risk_level', 'unknown')
                            reasons = llm_result.get('reasons', [])

                            func_def['_llm_score'] = llm_score
                            func_def['_llm_risk'] = risk_level
                            func_def['_llm_reasons'] = reasons
                            func_def['_size_score'] = size_score

                            llm_scored.append((llm_score, func_name, func_def))

                        llm_scored.sort(reverse=True, key=lambda x: x[0])
                        top_targets = llm_scored[:10]

                    else:
                        # Extract paths to top candidates
                        candidate_paths = []
                        # Aggressive setting: analyze up to 100 paths (optimized for $100 budget)
                        max_paths_to_extract = int(os.environ.get('MAX_PATHS_TO_EXTRACT', '100'))

                        print(f"  Extracting paths from {entry_point} to top candidates...")
                        for i, (score, target_name, target_def) in enumerate(size_candidates):
                            if len(candidate_paths) >= max_paths_to_extract:
                                break

                            # Find 1-2 paths to each target
                            paths = _find_paths_bfs(entry_point, target_name, adj, max_depth=15, max_paths=2)

                            for path in paths:
                                if len(candidate_paths) >= max_paths_to_extract:
                                    break

                                # Build processed path with function details
                                processed_path = []
                                for node_name in path:
                                    func_def = functions_map.get(node_name, {})
                                    processed_func = {
                                        "file": func_def.get('FilePath', ''),
                                        "function": func_def.get('Name', node_name),
                                        "body": func_def.get('SourceCode', ''),
                                        "line": str(func_def.get('StartLine', '')),
                                    }
                                    processed_path.append(processed_func)

                                if len(processed_path) > 1:  # Only include paths with at least 2 functions
                                    candidate_paths.append(processed_path)

                        print(f"  Extracted {len(candidate_paths)} execution paths")

                        if len(candidate_paths) == 0:
                            print(f"  Warning: No paths found, falling back to function-based scoring")
                            # Fallback to function-based
                            functions_to_score = [
                                (func_name, func_def.get('SourceCode', ''), func_def.get('FilePath', ''))
                                for _, func_name, func_def in size_candidates[:20]
                            ]
                            llm_results = score_functions_with_llm(functions_to_score)
                            llm_scored = []
                            for (size_score, func_name, func_def), llm_result in zip(size_candidates[:20], llm_results):
                                llm_score = llm_result.get('score', size_score // 100)
                                func_def['_llm_score'] = llm_score
                                func_def['_llm_risk'] = llm_result.get('risk_level', 'unknown')
                                func_def['_llm_reasons'] = llm_result.get('reasons', [])
                                func_def['_size_score'] = size_score
                                llm_scored.append((llm_score, func_name, func_def))
                            llm_scored.sort(reverse=True, key=lambda x: x[0])
                            top_targets = llm_scored[:10]
                        else:
                            # Step 3: Score paths with LLM (with caching)
                            print(f"Step 3: LLM vulnerability analysis ({len(candidate_paths)} paths)")
                            path_llm_results = score_paths_with_llm(entry_point, candidate_paths, repo_path=task_dir)

                            # Combine paths with scores
                            scored_paths = []
                            for path, llm_result in zip(candidate_paths, path_llm_results):
                                path_score = llm_result.get('score', 0)
                                risk_level = llm_result.get('risk_level', 'unknown')
                                reasons = llm_result.get('reasons', [])
                                attack_vector = llm_result.get('attack_vector', '')
                                vulnerable_step = llm_result.get('vulnerable_step', '')

                                scored_paths.append({
                                    'score': path_score,
                                    'risk': risk_level,
                                    'reasons': reasons,
                                    'attack_vector': attack_vector,
                                    'vulnerable_step': vulnerable_step,
                                    'path': path
                                })

                            # Sort by score
                            scored_paths.sort(reverse=True, key=lambda x: x['score'])

                            # Select top N paths (configurable, default 25 for better coverage)
                            top_n_paths = int(os.environ.get('TOP_PATHS_FOR_POV', '25'))

                            # Handle case where requested paths exceed available paths
                            available_paths = len(scored_paths)
                            actual_paths = min(top_n_paths, available_paths)

                            if top_n_paths > available_paths:
                                print(f"  Note: Requested {top_n_paths} paths, but only {available_paths} paths available")

                            top_10_paths = scored_paths[:actual_paths]

                            print(f"Step 4: Selected top {len(top_10_paths)} vulnerable execution paths (requested={top_n_paths}, available={available_paths})")
                            for i, path_data in enumerate(top_10_paths, 1):
                                path = path_data['path']
                                path_str = ' → '.join([f['function'] for f in path[:3]])
                                if len(path) > 3:
                                    path_str += f" → ... ({len(path)} total)"
                                print(f"  {i}. {path_str}")
                                print(f"     Score: {path_data['score']}/100, Risk: {path_data['risk']}")
                                print(f"     Vulnerable step: {path_data['vulnerable_step']}")
                                if path_data['attack_vector']:
                                    print(f"     Attack: {path_data['attack_vector'][:80]}...")

                            # Extract target functions from top paths for compatibility with rest of code
                            top_targets = []
                            seen_targets = set()
                            for path_data in top_10_paths:
                                path = path_data['path']
                                if len(path) > 0:
                                    # Use the last function in the path as the target
                                    target_func = path[-1]
                                    target_name = target_func['function']

                                    # Avoid duplicates
                                    if target_name in seen_targets:
                                        continue
                                    seen_targets.add(target_name)

                                    # Find the function definition
                                    func_def = functions_map.get(target_name, {})
                                    if not func_def:
                                        # Try fuzzy match
                                        for key, val in functions_map.items():
                                            if target_name in key or key.endswith(target_name):
                                                func_def = val
                                                target_name = key
                                                break

                                    # Store path analysis results
                                    func_def['_llm_score'] = path_data['score']
                                    func_def['_llm_risk'] = path_data['risk']
                                    func_def['_llm_reasons'] = path_data['reasons']
                                    func_def['_path_attack_vector'] = path_data['attack_vector']
                                    func_def['_path_vulnerable_step'] = path_data['vulnerable_step']

                                    top_targets.append((path_data['score'], target_name, func_def))

                            # Populate call_paths with the scored paths
                            # This avoids recomputing paths later
                            for path_data in top_10_paths:
                                call_paths.append(path_data['path'])

                            print(f"Populated {len(call_paths)} paths from path-based LLM analysis")

                else:
                    # Size-only scoring (fallback or disabled)
                    top_targets = scored_funcs[:10]  # Top 10 interesting functions (reduced to save context)
                    print(f"Size-based scoring (LLM analysis disabled via USE_LLM_VULNERABILITY_SCORING=false)")

                # If no targets found from reachability, sample top functions by source code size
                # This handles cases where Joern produces incomplete reachability (stubs without source)
                if len(top_targets) == 0:
                    print(f"No reachable functions with source code found, sampling top functions by size...")
                    # Score all functions with source code
                    all_scored = []
                    for func_name, func_def in functions_map.items():
                        # Skip operators, globals, and unresolved
                        if (func_name.startswith('<operator>') or
                            func_name.startswith('<unresolved') or
                            func_name.endswith(':<global>') or
                            func_name.startswith('<includes>')):
                            continue

                        source_code = func_def.get('SourceCode', '')
                        file_path = func_def.get('FilePath', '')
                        if not source_code or not file_path or file_path == '<empty>':
                            continue

                        score = len(source_code)
                        all_scored.append((score, func_name, func_def))

                    all_scored.sort(reverse=True, key=lambda x: x[0])
                    top_targets = all_scored[:10]
                    print(f"Sampled {len(top_targets)} top functions by source code size")

                print(f"Selected {len(top_targets)} interesting target functions for path computation")

                # Check if paths were already computed during path-based LLM analysis
                if len(call_paths) > 0:
                    print(f"Skipping path computation - already have {len(call_paths)} paths from path-based LLM analysis")
                else:
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

                    # Check if call graph is mostly operators/unresolved (not useful for path finding)
                    sample_callers = list(adj.keys())[:20]
                    useless_callers = sum(1 for c in sample_callers if c.startswith('<operator>') or c.startswith('<unresolved') or len(c) <= 3)
                    uses_abbreviated_names = len(sample_callers) > 0 and (useless_callers / len(sample_callers)) > 0.5

                    if uses_abbreviated_names:
                        print(f"Warning: Call graph is mostly operators ({useless_callers}/{len(sample_callers)}), cannot compute paths reliably")
                        print(f"Falling back to sampling {len(top_targets)} interesting reachable functions")

                        # Fallback: Return sample of interesting functions as 2-hop paths
                        # Create synthetic paths: entry_point -> interesting_function

                        # Look up entry point function with fuzzy matching
                        entry_func = functions_map.get(entry_point, {})
                        if not entry_func:
                            for key, val in functions_map.items():
                                if entry_point in key or key.endswith(entry_point):
                                    entry_func = val
                                    break

                        for score, target_name, target_def in top_targets[:30]:
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

                    target_paths = paths_data.get(composite_key, []) or []

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
