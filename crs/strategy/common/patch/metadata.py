# SPDX-License-Identifier: Apache-2.0
"""Target-function metadata resolution for patch strategies.

Three entry points, in priority order:

* :func:`load_from_analysis_service` — cheap remote lookup against
  the static-analysis service's ``/v1/funmeta`` endpoint.
* :func:`find_function_metadata` — falls back to ``fundef`` binary
  scans when the service response is empty. Looks for each
  ``file:function`` target in the project source tree, trying
  several path-resolution strategies.
* :func:`format_function_metadata` — format a metadata dict as a
  bounded-length prompt fragment for the LLM, preferring whole-file
  inclusion when each file fits inside the budget and falling back
  to per-function snippets otherwise.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Iterable, List, Optional

import requests

from common.code.cleanup import strip_license_text
from common.code.fundef import extract_function_using_fundef

logger = logging.getLogger(__name__)

_DEFAULT_ANALYSIS_SERVICE_URL = "http://localhost:7082"
_ANALYSIS_SERVICE_PATH = "/v1/funmeta"
_ANALYSIS_SERVICE_TIMEOUT = 300

_MAX_TOTAL_PROMPT_LENGTH = 300_000
_MAX_PER_FILE_LENGTH = 30_000
_TEST_PATH_MARKERS = ("/test/", "/tests/", "/docs/")


def _analysis_service_url() -> str:
    """Return the configured analysis-service URL (with path)."""
    base = os.environ.get("ANALYSIS_SERVICE_URL", _DEFAULT_ANALYSIS_SERVICE_URL)
    if _ANALYSIS_SERVICE_PATH in base:
        return base
    return f"{base}{_ANALYSIS_SERVICE_PATH}"


def load_from_analysis_service(
    target_functions: List[str],
    project_src_dir: str,
    focus: str,
) -> Dict[str, Any]:
    """Ask the static-analysis service for metadata on ``target_functions``.

    Returns the ``funmeta`` dict from the response on success, or an
    empty dict on any failure (network error, non-200 status, missing
    key). The caller is expected to fall back to a local scan.
    """
    url = _analysis_service_url()
    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "focus": focus,
        "project_src_dir": project_src_dir,
        "target_functions": target_functions,
    }
    logger.debug("Posting funmeta query to %s: %s", url, payload)

    try:
        response = requests.post(url, json=payload, timeout=_ANALYSIS_SERVICE_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("Error querying analysis service: %s", exc)
        return {}

    if response.status_code != 200:
        logger.warning(
            "Analysis service returned status %s; body: %s",
            response.status_code,
            response.text[:500],
        )
        return {}

    try:
        result = response.json()
    except ValueError as exc:
        logger.warning("Analysis service returned invalid JSON: %s", exc)
        return {}

    funmeta = result.get("funmeta", {})
    return funmeta if isinstance(funmeta, dict) else {}


def _extension_for_language(language: str) -> str:
    return ".c" if language.startswith("c") else ".java"


def _resolve_target_file(file_path: str, project_src_dir: str) -> Optional[str]:
    """Try several resolutions to turn ``file_path`` into a real file on disk."""
    primary = os.path.join(project_src_dir, file_path)
    if os.path.exists(primary):
        return primary

    if file_path.startswith("/src/"):
        parts = file_path.split("/")
        if len(parts) >= 3:
            relative = "/".join(parts[3:])
            candidate = os.path.join(project_src_dir, relative)
            if os.path.exists(candidate):
                return candidate

    basename = os.path.basename(file_path)
    for root, _, files in os.walk(project_src_dir):
        if basename in files:
            return os.path.join(root, basename)

    return None


def _ingest_metadata(
    metadata_list: Any,
    function_name: str,
    rel_path: str,
    function_metadata: Dict[str, Any],
) -> None:
    """Merge the ``extract_function_using_fundef`` output into ``function_metadata``."""
    if isinstance(metadata_list, list):
        for i, metadata in enumerate(metadata_list):
            unique_key = f"{function_name}_{i + 1}"
            metadata["file_path"] = rel_path
            function_metadata[unique_key] = metadata
            logger.debug("Recorded function %s in %s", unique_key, rel_path)
    else:
        metadata_list["file_path"] = rel_path
        function_metadata[function_name] = metadata_list
        logger.debug("Recorded function %s in %s", function_name, rel_path)


def _scan_candidate_files(
    candidate_files: Iterable[str],
    function_name: str,
    project_src_dir: str,
    function_metadata: Dict[str, Any],
) -> bool:
    """Try ``extract_function_using_fundef`` on each candidate until one hits."""
    for file_path in candidate_files:
        logger.debug("Scanning candidate %s for %s", file_path, function_name)
        metadata_list = extract_function_using_fundef(file_path, function_name)
        if not metadata_list:
            continue
        rel_path = os.path.relpath(file_path, project_src_dir)
        _ingest_metadata(metadata_list, function_name, rel_path, function_metadata)
        return True
    return False


def _walk_project_for_function(
    project_src_dir: str,
    extension: str,
    function_name: str,
    function_metadata: Dict[str, Any],
) -> bool:
    """Walk the whole project tree for a source file containing ``function_name``."""
    for root, _, files in os.walk(project_src_dir):
        for name in files:
            if not name.endswith(extension) or name.startswith("Crash_"):
                continue
            file_path = os.path.join(root, name)
            if any(marker in file_path.lower() for marker in _TEST_PATH_MARKERS):
                continue
            if name.lower().startswith("test"):
                continue
            metadata_list = extract_function_using_fundef(file_path, function_name)
            if not metadata_list:
                continue
            rel_path = os.path.relpath(file_path, project_src_dir)
            _ingest_metadata(metadata_list, function_name, rel_path, function_metadata)
            return True
    return False


def find_function_metadata(
    target_functions: List[str],
    project_src_dir0: str,
    project_src_dir: str,
    project_name: str,
    focus: str = "",
    language: str = "c",
    relevant_source_files: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Resolve metadata for each ``file_path:function_name`` in ``target_functions``.

    Tries the analysis service first, then ``fundef`` on the specific
    file path the LLM named, then ``fundef`` on any path in
    ``relevant_source_files``, then a full project-tree walk.

    Args:
        target_functions: Entries like ``"path/to/file.c:func"``.
        project_src_dir0: Pristine project source directory (used for
            the analysis-service query).
        project_src_dir: Potentially patched project source directory
            (used for the local scans).
        project_name: OSS-Fuzz project name (for logging only).
        focus: Focus directory; passed through to the analysis service.
        language: ``"c"`` or ``"java"``.
        relevant_source_files: Optional iterable of source files known
            to be relevant (e.g. files mentioned earlier in the
            strategy conversation). Checked before the full tree walk.

    Returns:
        Dict keyed by function name (or ``{func}_{index}`` for multi-
        match cases), values are the metadata dicts augmented with a
        ``file_path`` relative to ``project_src_dir``.
    """
    del project_name  # retained for parity; not currently used for lookup
    remote = load_from_analysis_service(target_functions, project_src_dir0, focus)
    if remote:
        return remote

    function_metadata: Dict[str, Any] = {}
    extension = _extension_for_language(language)

    for target in target_functions:
        try:
            file_path, function_name = target.split(":", 1)
        except ValueError:
            logger.debug("Skipping malformed target: %s", target)
            continue

        logger.debug("Resolving %s in %s", function_name, file_path)

        resolved = _resolve_target_file(file_path, project_src_dir)
        if resolved is not None:
            metadata_list = extract_function_using_fundef(resolved, function_name)
            if metadata_list:
                rel_path = os.path.relpath(resolved, project_src_dir)
                _ingest_metadata(metadata_list, function_name, rel_path, function_metadata)
                continue
            logger.debug("Function %s not in resolved file %s", function_name, resolved)

        if relevant_source_files:
            candidate_files = [
                rel if os.path.isabs(rel) else os.path.join(project_src_dir, rel)
                for rel in relevant_source_files
                if rel.endswith(extension)
            ]
            candidate_files = [p for p in candidate_files if os.path.exists(p)]
            if _scan_candidate_files(candidate_files, function_name, project_src_dir, function_metadata):
                continue

        _walk_project_for_function(project_src_dir, extension, function_name, function_metadata)

    return function_metadata


def _group_by_file(function_metadata: Dict[str, Any]) -> Dict[str, List]:
    """Group metadata entries by ``file_path``."""
    grouped: Dict[str, List] = {}
    for func_name, metadata in function_metadata.items():
        file_path = metadata["file_path"]
        grouped.setdefault(file_path, []).append((func_name, metadata))
    return grouped


def _relative_file_path(file_path: str, project_src_dir: str) -> str:
    """Turn an absolute file path into a readable prompt-friendly form."""
    patch_idx = file_path.find("patch_workspace")
    if patch_idx != -1:
        parts = file_path[patch_idx:].split("/")
        if len(parts) >= 2:
            project_idx = file_path.find(parts[1], patch_idx)
            if project_idx != -1:
                start = project_idx + len(parts[1]) + 1
                if start < len(file_path):
                    return file_path[start:]

    if project_src_dir and file_path.startswith(project_src_dir):
        return file_path[len(project_src_dir):].lstrip("/")

    return file_path


def _truncate_function(metadata: Dict[str, Any], remaining: int) -> str:
    """Return a truncated signature-only rendering when the function body is too big."""
    if remaining < 500:
        return ""
    content = metadata["content"]
    signature_end = content.find("{") + 1
    signature = content[:signature_end] if signature_end > 0 else content[: min(200, len(content))]
    return signature + "\n    // ... [function body omitted due to length] ...\n}"


def format_function_metadata(
    function_metadata: Dict[str, Any],
    project_src_dir: str,
) -> str:
    """Format ``function_metadata`` as a bounded-length prompt fragment.

    Emits whole files when they fit inside the per-file budget; otherwise
    falls back to per-function snippets (full body when it fits, else
    signature-only with a placeholder body).
    """
    grouped = _group_by_file(function_metadata)

    parts: List[str] = []
    remaining = _MAX_TOTAL_PROMPT_LENGTH
    files_included: set = set()
    file_contents: Dict[str, str] = {}

    for file_path in grouped:
        if not os.path.exists(file_path):
            continue
        try:
            with open(file_path, "r") as fh:
                content = strip_license_text(fh.read())
        except OSError as exc:
            logger.debug("Error reading %s: %s", file_path, exc)
            continue

        file_contents[file_path] = content
        if len(content) <= _MAX_PER_FILE_LENGTH and len(content) <= remaining:
            rel = _relative_file_path(file_path, project_src_dir)
            parts.append(f"File: {rel}\nContent:\n{content}\n\n")
            files_included.add(file_path)
            remaining -= len(content)
            logger.debug("Included entire file %s (%d chars)", rel, len(content))

    for file_path, functions in grouped.items():
        if file_path in files_included:
            continue

        rel = _relative_file_path(file_path, project_src_dir)
        parts.append(f"File: {rel}\n\n")

        for func_name, metadata in functions:
            content = metadata["content"]
            klass = metadata.get("class")

            if len(content) > remaining:
                truncated = _truncate_function(metadata, remaining)
                if not truncated:
                    parts.append(f"Function: {func_name} (omitted due to space constraints)\n\n")
                    if klass:
                        parts.append(f"Class: {klass}\n")
                    continue
                parts.append(f"Function: {func_name}\n{truncated}\n\n")
                if klass:
                    parts.append(f"Class: {klass}\n")
                remaining -= len(truncated) + len(func_name) + 20
            else:
                parts.append(f"Function: {func_name}\n{content}\n\n")
                if klass:
                    parts.append(f"Class: {klass}\n")
                remaining -= len(content) + len(func_name) + 20

    return "".join(parts)
