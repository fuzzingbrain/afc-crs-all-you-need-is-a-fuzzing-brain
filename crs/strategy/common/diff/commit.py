"""Commit diff loading and per-function extraction.

Two entry points:

* :func:`get_commit_info` — read the task's ``diff/ref.diff`` when
  present, falling back to ``git log`` / ``git diff`` on the repository
  at ``project_dir``. Large diffs are run through
  :func:`common.diff.process.process_large_diff`.
* :func:`parse_commit_diff` — split a unified diff into per-file
  modified-function metadata by combining a lightweight hunk scanner
  with :func:`common.code.extract.extract_function_body`.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Any, Dict, Tuple

from common.code.extract import extract_function_body
from common.diff.process import process_large_diff

logger = logging.getLogger(__name__)

_LARGE_DIFF_THRESHOLD = 50_000  # bytes

_JAVA_FUNCTION_PATTERN = re.compile(
    r"(?:public|private|protected|static|\s) +"
    r"(?:[a-zA-Z0-9_<>]+) +"
    r"([a-zA-Z0-9_]+) *\([^)]*\) *(?:\{|throws|$)"
)

_C_FUNCTION_PATTERN = re.compile(
    r"(?:(?:static|inline|extern)?\s+(?:[a-zA-Z0-9_]+\s+)*([a-zA-Z0-9_]+)"
    r"\s*\([^)]*\)\s*(?:\{|$))|"
    r"(?:^([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:\{|$))",
    re.MULTILINE,
)

_C_KEYWORD_BLOCKLIST = {"if", "while", "for", "switch", "return"}
_SOURCE_EXTENSIONS = (".java", ".c", ".h")


def get_commit_info(project_dir: str, language: str) -> Tuple[str, str]:
    """Return ``(commit_message, diff_content)`` for the vuln-introducing commit.

    First looks for ``{project_dir}/diff/ref.diff`` (used by delta
    tasks). Otherwise falls back to ``git log -1`` plus
    ``git diff HEAD~1 HEAD`` on the directory. Diffs larger than
    :data:`_LARGE_DIFF_THRESHOLD` bytes are passed through
    :func:`process_large_diff`.

    Args:
        project_dir: Repository root on the host.
        language: ``"c"`` / ``"java"``; reserved for future
            language-specific behaviour.

    Returns:
        ``(message, diff)`` tuple. ``("", "")`` on unrecoverable errors.
    """
    del language  # currently unused; retained for API parity

    diff_path = os.path.join(project_dir, "diff", "ref.diff")
    if os.path.exists(diff_path):
        try:
            with open(diff_path, "r") as fh:
                diff_content = fh.read()
        except OSError as exc:
            logger.error("Error reading diff file %s: %s", diff_path, exc)
        else:
            logger.debug("Read diff from %s (%d bytes)", diff_path, len(diff_content))
            if len(diff_content) > _LARGE_DIFF_THRESHOLD:
                logger.debug("Diff is large; running process_large_diff")
                return "Processed commit from diff/ref.diff", process_large_diff(diff_content)
            return "Commit from diff/ref.diff", diff_content

    try:
        git_log = subprocess.check_output(
            ["git", "log", "-1", "--pretty=format:%h %s"], cwd=project_dir, text=True
        )
        git_diff = subprocess.check_output(
            ["git", "diff", "HEAD~1", "HEAD"], cwd=project_dir, text=True
        )
    except (subprocess.CalledProcessError, OSError) as exc:
        logger.error("Error getting commit info: %s", exc)
        return "", ""

    logger.debug("Latest commit: %s", git_log)
    return git_log, git_diff


def _iter_file_hunks(file_diff: str):
    """Yield ``(start_line_new, hunk_text)`` for each hunk in a per-file diff."""
    for match in re.finditer(
        r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@(.*?)(?=\n@@|\Z)",
        file_diff,
        re.DOTALL,
    ):
        yield int(match.group(3)), match.group(0)


def _collect_java_functions_from_hunk(
    hunk_text: str,
    start_line: int,
    full_file_path: str,
    file_path: str,
    seen_names: set,
) -> list:
    """Return Java function metadata entries for a single hunk."""
    entries = []
    class_name = None
    if "." in file_path:
        class_name = file_path.split("/")[-1].split(".")[0]

    for match in _JAVA_FUNCTION_PATTERN.finditer(hunk_text):
        function_name = match.group(1)
        if class_name and function_name == class_name:
            continue  # constructor

        function_pos = match.start()
        lines_before = hunk_text[:function_pos].count("\n")
        function_start_line = start_line + lines_before

        if function_name in seen_names:
            continue
        seen_names.add(function_name)

        entries.append(
            {
                "name": function_name,
                "start_line": function_start_line,
                "body": extract_function_body(full_file_path, function_name),
            }
        )
    return entries


def _collect_c_functions_from_hunk(
    hunk_text: str,
    start_line: int,
    full_file_path: str,
    seen_names: set,
) -> list:
    """Return C/C++ function metadata entries for a single hunk."""
    entries = []
    for match in _C_FUNCTION_PATTERN.finditer(hunk_text):
        function_name = match.group(1) or match.group(2)
        if not function_name or function_name in _C_KEYWORD_BLOCKLIST:
            continue

        function_pos = match.start()
        lines_before = hunk_text[:function_pos].count("\n")
        function_start_line = start_line + lines_before

        if function_name in seen_names:
            continue
        seen_names.add(function_name)

        entries.append(
            {
                "name": function_name,
                "start_line": function_start_line,
                "body": extract_function_body(full_file_path, function_name),
            }
        )
    return entries


def parse_commit_diff(project_src_dir: str, commit_diff: str) -> Dict[str, Any]:
    """Parse a unified diff into per-file modified-function metadata.

    For every file touched by the diff, extracts the names and bodies of
    functions that appear inside changed hunks. Skips test files and
    non-source files.

    Args:
        project_src_dir: Directory to resolve relative file paths against.
        commit_diff: Unified diff string.

    Returns:
        Dictionary keyed by file path; values carry
        ``{"file_path", "modified_functions": [{"name", "start_line", "body"}, ...]}``.
    """
    modified: Dict[str, Any] = {}

    file_diffs = re.split(r"diff --git ", commit_diff)
    if file_diffs and file_diffs[0] == "":
        file_diffs = file_diffs[1:]
    else:
        file_diffs[0] = file_diffs[0].lstrip()

    for file_diff in file_diffs:
        if not file_diff:
            continue

        path_match = re.search(r"a/(.*) b/", file_diff)
        if not path_match:
            continue
        file_path = path_match.group(1)

        if "/test/" in file_path:
            continue
        if not any(file_path.endswith(ext) for ext in _SOURCE_EXTENSIONS):
            continue

        full_file_path = os.path.join(project_src_dir, file_path)
        if not os.path.exists(full_file_path):
            continue

        entry = modified.setdefault(
            file_path, {"file_path": file_path, "modified_functions": []}
        )
        seen_names = {f["name"] for f in entry["modified_functions"]}

        for start_line, hunk_text in _iter_file_hunks(file_diff):
            if file_path.endswith(".java"):
                entry["modified_functions"].extend(
                    _collect_java_functions_from_hunk(
                        hunk_text, start_line, full_file_path, file_path, seen_names
                    )
                )
            elif file_path.endswith((".c", ".h")):
                entry["modified_functions"].extend(
                    _collect_c_functions_from_hunk(
                        hunk_text, start_line, full_file_path, seen_names
                    )
                )

    return modified
