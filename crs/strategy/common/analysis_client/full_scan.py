# SPDX-License-Identifier: Apache-2.0
"""Full-scan analysis helpers.

Full-scan POV strategies enumerate every function reachable from the
fuzzer entry point, score them with an LLM, and drive POV generation
against the highest-scoring candidates. The helpers here cover that
workflow:

* :func:`extract_reachable_functions` — walk the local static-analysis
  JSON output for ``{focus}.json`` and return a list of function
  records.
* :func:`extract_call_paths_for_full_scan` — thin wrapper around the
  local-analysis call-paths helper, kept under a distinct name so the
  signature difference from the delta-scan entry point is explicit.
* :func:`find_most_likely_vulnerable_functions` — ask an LLM to score
  the reachable functions and return the top-k candidates.
* :func:`extract_vulnerable_functions` — filter the reachable list
  down to the names the LLM highlighted.
* :func:`convert_target_functions_format` — reshape a reachable-funcs
  list into the per-file dict used by the prompt builders.
"""
from __future__ import annotations

import json
import logging
import os
import re
import textwrap
import time
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from common.analysis_client.client import (
    run_static_analysis_local,
)

if TYPE_CHECKING:
    from common.llm.client import LLMClient

logger = logging.getLogger(__name__)

_MAX_CATALOG_WORDS = 50_000
_MAX_BODY_LINES_WHEN_PRUNED = 500
_DEFAULT_TOP_K = 10
_JSON_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*([\s\S]*?)```")


def extract_call_paths_for_full_scan(
    project_name: str,  # noqa: ARG001  retained for signature parity
    fuzzer_path: str,
    fuzzer_src_path: str,
    focus: str,
    project_src_dir: str,
    target_functions: Dict[str, Any],
) -> List[Any]:
    """Return call paths from the fuzzer to ``target_functions``.

    Delegates to ``common.analysis_client.client.extract_call_paths_local``
    via the :mod:`common.analysis_client.client` namespace; takes an
    extra ``project_name`` arg only for signature parity with the
    legacy as0_full caller, which hands it in but never uses it.
    """
    # Local import: the underlying helper lives inside the monolith file
    # and its name is not re-exported from the package __init__ yet.
    from common.analysis_client.client import extract_call_paths_local

    return extract_call_paths_local(
        fuzzer_path,
        fuzzer_src_path,
        focus,
        project_src_dir,
        target_functions,
        False,
    )


def extract_reachable_functions(
    fuzzer_src_path: str,
    focus: str,
    project_dir: str,
) -> List[Dict[str, Any]]:
    """Return the reachable-function records produced by local static analysis.

    Runs ``run_static_analysis_local`` when the results file does not
    yet exist, then parses ``{project_dir}/{focus}.json`` and
    normalises each function entry into a dict with ``name``,
    ``file_path``, ``start_line``, ``end_line``, and ``body``.
    """
    task_id = os.environ.get("TASK_ID")
    results_file = os.path.join(project_dir, f"{focus}.json")

    if not os.path.exists(results_file):
        logger.info("Running local static analysis for %s", focus)
        if not run_static_analysis_local(task_id, project_dir, focus):
            logger.error("Failed to run static analysis")
            return []
        time.sleep(2)

    if not os.path.exists(results_file):
        return []

    try:
        with open(results_file, "r") as fh:
            results = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Error reading static analysis results %s: %s", results_file, exc)
        return []

    fuzzer_key = fuzzer_src_path.replace(os.sep, "/")
    entry_point = (
        f"{fuzzer_key}.fuzzerTestOneInput"
        if fuzzer_src_path.endswith(".java")
        else f"{fuzzer_key}.LLVMFuzzerTestOneInput"
    )

    reachable_names = results.get("reachable", {}).get(entry_point, [])
    functions_map = results.get("functions", {})

    reachable_funcs: List[Dict[str, Any]] = []
    for func_name in reachable_names:
        func_def = functions_map.get(func_name, {})
        reachable_funcs.append(
            {
                "name": func_def.get("Name", func_name),
                "file_path": func_def.get("FilePath", ""),
                "start_line": func_def.get("StartLine", 0),
                "end_line": func_def.get("EndLine", 0),
                "body": func_def.get("SourceCode", ""),
            }
        )
    return reachable_funcs


def _function_name(func: Dict[str, Any]) -> str:
    return func.get("name") or func.get("Name") or "<unknown>"


def _function_body(func: Dict[str, Any]) -> str:
    return (
        func.get("body")
        or func.get("Body")
        or func.get("sourceCode")
        or func.get("SourceCode")
        or ""
    )


def _build_catalog(reachable_funcs: List[Dict[str, Any]]) -> str:
    """Join reachable functions into the LLM catalogue text."""
    snippets = [f"Function: {_function_name(f)}\n{_function_body(f)}" for f in reachable_funcs]
    return "\n".join(snippets)


def _prune_catalog_for_budget(reachable_funcs: List[Dict[str, Any]]) -> str:
    """Drop functions whose body exceeds the per-function line cap."""
    snippets: List[str] = []
    for func in reachable_funcs:
        body = _function_body(func)
        if body.count("\n") > _MAX_BODY_LINES_WHEN_PRUNED:
            continue
        snippets.append(f"Function: {_function_name(func)}\n{body}")
    return "\n".join(snippets)


_C_VULN_GUIDANCE = """an address, memory or UB sanitizer would catch.  Consider:

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

_JAVA_VULN_GUIDANCE = """
Jazzer can detect (non-exhaustive):
  - Deserialization issues
  - Path traversal
  - Regex denial-of-service
  - LDAP / SQL / XPath injection
  - Script engine injection, unsafe reflection
  - SSRF or RCE-style vulnerabilities
  - Unhandled runtime exceptions (NullPointerException, etc.)
"""


def _build_scoring_prompt(catalog_text: str, language: str, top_k: int) -> str:
    vuln_bullets = _C_VULN_GUIDANCE if language.lower().startswith("c") else _JAVA_VULN_GUIDANCE
    return textwrap.dedent(
        f"""
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
        """
    )


def find_most_likely_vulnerable_functions(
    llm_client: "LLMClient",
    reachable_funcs: List[Dict[str, Any]],
    language: str,
    model_name: Optional[str] = None,
    top_k: int = _DEFAULT_TOP_K,
) -> List[Dict[str, Any]]:
    """Ask the LLM to score ``reachable_funcs`` and return the top-k vulnerable ones.

    When the naive catalogue exceeds :data:`_MAX_CATALOG_WORDS` it is
    rebuilt with extremely long functions dropped, to stay under the
    LLM context window.

    Returns an empty list on LLM failure or JSON parse failure.
    """
    if not reachable_funcs:
        return []

    catalog_text = _build_catalog(reachable_funcs)
    if len(re.findall(r"\w+", catalog_text)) > _MAX_CATALOG_WORDS:
        catalog_text = _prune_catalog_for_budget(reachable_funcs)

    prompt = _build_scoring_prompt(catalog_text, language, top_k)
    messages = [
        {"role": "system", "content": "You are an expert in code security."},
        {"role": "user", "content": prompt},
    ]

    kwargs = {} if model_name is None else {"model_name": model_name}
    start = time.time()
    raw, ok = llm_client.call(messages, **kwargs)
    duration = time.time() - start
    if not ok:
        logger.warning("%s scoring call failed after %.1fs", model_name, duration)
        return []

    match = _JSON_BLOCK_PATTERN.search(raw)
    if match:
        raw = match.group(1).strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("JSON parse failed for %s scoring response", model_name)
        return []

    if isinstance(parsed, list) and parsed:
        return parsed[:top_k]
    return []


def extract_vulnerable_functions(
    reachable_funcs: List[Dict[str, Any]],
    vulnerable_functions: List[Dict[str, Any]],
    limit: int = _DEFAULT_TOP_K,
) -> List[Dict[str, Any]]:
    """Filter ``reachable_funcs`` to the names flagged by
    :func:`find_most_likely_vulnerable_functions`.

    When ``vulnerable_functions`` is empty, returns up to ``limit``
    reachable funcs unchanged (nothing to filter by).
    """
    if not vulnerable_functions:
        return reachable_funcs[:limit]

    wanted = {
        (vf.get("name") or vf.get("Name") or "").strip()
        for vf in vulnerable_functions[:limit]
    }
    wanted.discard("")

    return [
        f for f in reachable_funcs
        if (f.get("name") or f.get("Name") or "").strip() in wanted
    ]


def convert_target_functions_format(
    reachable_funcs: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Reshape a reachable-funcs list into ``{file_path: [{name, start_line}, ...]}``.

    Used as a pre-processing step before handing the data to prompt
    builders that expect the per-file dict shape.
    """
    result: Dict[str, List[Dict[str, Any]]] = {}
    for func in reachable_funcs:
        file_path = func.get("FilePath") or func.get("file_path")
        name = func.get("Name") or func.get("name")
        start_line = func.get("StartLine") or func.get("start_line")

        if not file_path or not name or start_line is None:
            continue

        result.setdefault(file_path, []).append(
            {"name": name, "start_line": start_line}
        )

    return result
