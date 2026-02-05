"""
Diff Parser and Reachability Analysis

Parses unified diff format and checks if changes are reachable from a fuzzer.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path

from loguru import logger


@dataclass
class DiffHunk:
    """A single hunk in a diff (one @@ section)"""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    content: str

    @property
    def new_lines(self) -> range:
        """Line range in the new file"""
        return range(self.new_start, self.new_start + self.new_count)


@dataclass
class FileDiff:
    """Diff for a single file"""

    old_path: str
    new_path: str
    hunks: List[DiffHunk] = field(default_factory=list)
    is_new_file: bool = False
    is_deleted: bool = False
    is_binary: bool = False

    @property
    def path(self) -> str:
        """Get the relevant file path (new path for modifications, old for deletions)"""
        if self.is_deleted:
            return self.old_path
        return self.new_path

    @property
    def changed_lines(self) -> List[int]:
        """Get all changed line numbers in the new file"""
        lines = []
        for hunk in self.hunks:
            lines.extend(list(hunk.new_lines))
        return lines


@dataclass
class ReachableChange:
    """A change that is reachable from a fuzzer"""

    file_path: str
    function_name: str
    function_file: (
        str  # File where function is defined (may differ from diff file for headers)
    )
    line_start: int
    line_end: int
    changed_lines: List[int]  # Which lines in this function were changed
    diff_content: str  # The actual diff content for this function
    reachability_distance: Optional[int] = None  # Call depth from fuzzer


@dataclass
class FunctionChange:
    """A changed function (regardless of reachability)"""

    file_path: str
    function_name: str
    function_file: str
    line_start: int
    line_end: int
    changed_lines: List[int]
    diff_content: str
    # Reachability info (from static analysis - may be wrong for function pointers!)
    static_reachable: bool = False
    reachability_distance: Optional[int] = None


@dataclass
class DiffReachabilityResult:
    """Result of diff reachability analysis"""

    reachable: bool  # Are any changes reachable?
    reachable_changes: List[ReachableChange] = field(default_factory=list)
    unreachable_functions: List[str] = field(default_factory=list)
    changed_files: List[str] = field(default_factory=list)
    total_changed_functions: int = 0

    @property
    def summary(self) -> str:
        """Human-readable summary"""
        reachable_count = len(self.reachable_changes)
        if self.total_changed_functions == 0:
            return "No functions changed in diff"
        return f"{reachable_count}/{self.total_changed_functions} changed functions are reachable"


def parse_diff(diff_content: str) -> List[FileDiff]:
    """
    Parse unified diff format into structured data.

    Args:
        diff_content: Raw diff content (unified diff format)

    Returns:
        List of FileDiff objects, one per changed file
    """
    file_diffs = []

    # Split by file boundaries
    # Pattern matches "diff --git a/path b/path" or just file headers
    file_sections = re.split(r"^diff --git ", diff_content, flags=re.MULTILINE)

    for section in file_sections:
        if not section.strip():
            continue

        # Check for binary file
        if "Binary files" in section or "GIT binary patch" in section:
            # Try to extract path
            path_match = re.search(r"a/(\S+)\s+b/(\S+)", section)
            if path_match:
                file_diffs.append(
                    FileDiff(
                        old_path=path_match.group(1),
                        new_path=path_match.group(2),
                        is_binary=True,
                    )
                )
            continue

        # Extract file paths
        path_match = re.search(r"a/(\S+)\s+b/(\S+)", section)
        if not path_match:
            continue

        old_path = path_match.group(1)
        new_path = path_match.group(2)

        # Check for new/deleted file
        is_new = "new file mode" in section
        is_deleted = "deleted file mode" in section

        # Parse hunks
        hunks = []
        hunk_pattern = r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*?)(?=^@@|\Z)"

        for match in re.finditer(hunk_pattern, section, re.MULTILINE | re.DOTALL):
            old_start = int(match.group(1))
            old_count = int(match.group(2)) if match.group(2) else 1
            new_start = int(match.group(3))
            new_count = int(match.group(4)) if match.group(4) else 1
            content = match.group(5)

            hunks.append(
                DiffHunk(
                    old_start=old_start,
                    old_count=old_count,
                    new_start=new_start,
                    new_count=new_count,
                    content=content.strip(),
                )
            )

        if hunks or is_new or is_deleted:
            file_diffs.append(
                FileDiff(
                    old_path=old_path,
                    new_path=new_path,
                    hunks=hunks,
                    is_new_file=is_new,
                    is_deleted=is_deleted,
                )
            )

    return file_diffs


def _is_source_file(path: str) -> bool:
    """Check if file is a source file we care about"""
    extensions = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".java"}
    return Path(path).suffix.lower() in extensions


def _extract_hunk_content_for_function(
    hunks: List[DiffHunk],
    func_start: int,
    func_end: int,
) -> Tuple[str, List[int]]:
    """
    Extract diff content that overlaps with a function.

    Returns:
        Tuple of (diff_content, changed_lines)
    """
    relevant_content = []
    changed_lines = []

    for hunk in hunks:
        # Check if hunk overlaps with function
        hunk_start = hunk.new_start
        hunk_end = hunk.new_start + hunk.new_count

        if hunk_end < func_start or hunk_start > func_end:
            continue  # No overlap

        # There is overlap
        relevant_content.append(
            f"@@ -{hunk.old_start},{hunk.old_count} +{hunk.new_start},{hunk.new_count} @@"
        )
        relevant_content.append(hunk.content)

        # Track which lines in the function were changed
        for line in hunk.new_lines:
            if func_start <= line <= func_end:
                changed_lines.append(line)

    return "\n".join(relevant_content), changed_lines


def get_reachable_changes(
    diff_content: str,
    fuzzer: str,
    analysis_client: Any,  # AnalysisClient
) -> DiffReachabilityResult:
    """
    Analyze diff and return reachable changes.

    This function:
    1. Parses the diff to find changed files and line ranges
    2. Gets functions in those files from Analysis Server
    3. Finds which functions contain changed lines
    4. Checks if those functions are reachable from the fuzzer
    5. Returns structured result with reachable changes

    Args:
        diff_content: Raw diff content (unified diff format)
        fuzzer: Fuzzer name (entry point)
        analysis_client: Connected AnalysisClient instance

    Returns:
        DiffReachabilityResult with reachable changes and summary
    """
    result = DiffReachabilityResult(reachable=False)

    # Parse diff
    file_diffs = parse_diff(diff_content)

    if not file_diffs:
        logger.warning("No file changes found in diff")
        return result

    # Filter to source files only
    source_diffs = [
        d for d in file_diffs if _is_source_file(d.path) and not d.is_binary
    ]

    if not source_diffs:
        logger.info("No source file changes in diff")
        return result

    result.changed_files = [d.path for d in source_diffs]
    logger.info(f"Analyzing {len(source_diffs)} changed source files")

    # For each changed file, find affected functions
    changed_functions = []  # List of (function_info, file_diff)

    for file_diff in source_diffs:
        if file_diff.is_deleted:
            logger.debug(f"Skipping deleted file: {file_diff.path}")
            continue

        if not file_diff.hunks:
            continue

        # Get functions in this file from Analysis Server
        try:
            functions = analysis_client.get_functions_by_file(file_diff.path)
        except Exception as e:
            logger.warning(f"Failed to get functions for {file_diff.path}: {e}")
            continue

        if not functions:
            logger.debug(f"No functions found in {file_diff.path}")
            continue

        # Find which functions overlap with changed lines
        changed_lines = set(file_diff.changed_lines)

        for func in functions:
            func_start = func.get("start_line", 0)
            func_end = func.get("end_line", 0)
            func_name = func.get("name", "")

            if not func_name or not func_start:
                continue

            # Check if any changed line is within this function
            func_lines = set(range(func_start, func_end + 1))
            overlap = changed_lines & func_lines

            if overlap:
                changed_functions.append((func, file_diff))
                logger.debug(f"Function {func_name} has {len(overlap)} changed lines")

    result.total_changed_functions = len(changed_functions)

    if not changed_functions:
        logger.info("No functions contain changed lines")
        return result

    logger.info(
        f"Found {len(changed_functions)} functions with changes, checking reachability..."
    )

    # Check reachability for each changed function
    for func, file_diff in changed_functions:
        func_name = func.get("name", "")
        func_file = func.get("file_path", file_diff.path)
        func_start = func.get("start_line", 0)
        func_end = func.get("end_line", 0)

        try:
            reachability = analysis_client.get_reachability(fuzzer, func_name)
            is_reachable = reachability.get("reachable", False)
            distance = reachability.get("distance")
        except Exception as e:
            logger.warning(f"Failed to check reachability for {func_name}: {e}")
            is_reachable = False
            distance = None

        if is_reachable:
            # Extract the relevant diff content for this function
            diff_excerpt, changed_lines = _extract_hunk_content_for_function(
                file_diff.hunks, func_start, func_end
            )

            result.reachable_changes.append(
                ReachableChange(
                    file_path=file_diff.path,
                    function_name=func_name,
                    function_file=func_file,
                    line_start=func_start,
                    line_end=func_end,
                    changed_lines=changed_lines,
                    diff_content=diff_excerpt,
                    reachability_distance=distance,
                )
            )
            logger.debug(f"  ✓ {func_name} is reachable (distance: {distance})")
        else:
            result.unreachable_functions.append(func_name)
            logger.debug(f"  ✗ {func_name} is NOT reachable")

    result.reachable = len(result.reachable_changes) > 0

    # Sort by reachability distance (closer = higher priority)
    result.reachable_changes.sort(
        key=lambda x: (
            x.reachability_distance if x.reachability_distance is not None else 999
        )
    )

    logger.info(result.summary)
    return result


def get_reachable_changes_simple(
    diff_content: str,
    fuzzer: str,
    analysis_client: Any,
) -> Dict[str, Any]:
    """
    Simplified version that returns a plain dict (for tool use).

    Returns:
        {
            "reachable": bool,
            "summary": str,
            "reachable_changes": [
                {
                    "file": str,
                    "function": str,
                    "lines": "start-end",
                    "changed_lines": [int, ...],
                    "diff_content": str,
                    "distance": int or null,
                },
                ...
            ],
            "unreachable_functions": [str, ...],
            "changed_files": [str, ...],
        }
    """
    result = get_reachable_changes(diff_content, fuzzer, analysis_client)

    return {
        "reachable": result.reachable,
        "summary": result.summary,
        "reachable_changes": [
            {
                "file": c.file_path,
                "function": c.function_name,
                "lines": f"{c.line_start}-{c.line_end}",
                "changed_lines": c.changed_lines,
                "diff_content": c.diff_content,
                "distance": c.reachability_distance,
            }
            for c in result.reachable_changes
        ],
        "unreachable_functions": result.unreachable_functions,
        "changed_files": result.changed_files,
    }


def get_all_changes(
    diff_content: str,
    fuzzer: str,
    analysis_client: Any,
) -> List[FunctionChange]:
    """
    Get ALL changed functions from diff, with reachability info.

    Unlike get_reachable_changes which filters out unreachable functions,
    this returns ALL changed functions. The reachability info is included
    but should be used as a scoring factor, not a hard filter.

    IMPORTANT: Static analysis may incorrectly mark function-pointer-called
    functions as unreachable. The LLM should judge actual reachability.

    Args:
        diff_content: Raw diff content (unified diff format)
        fuzzer: Fuzzer name (entry point)
        analysis_client: Connected AnalysisClient instance

    Returns:
        List of FunctionChange objects (ALL changes, not just reachable)
    """
    all_changes: List[FunctionChange] = []

    # Parse diff
    file_diffs = parse_diff(diff_content)

    if not file_diffs:
        logger.warning("No file changes found in diff")
        return all_changes

    # Filter to source files only
    source_diffs = [
        d for d in file_diffs if _is_source_file(d.path) and not d.is_binary
    ]

    if not source_diffs:
        logger.info("No source file changes in diff")
        return all_changes

    logger.info(
        f"Analyzing {len(source_diffs)} changed source files (ignoring reachability filter)"
    )

    # For each changed file, find affected functions
    for file_diff in source_diffs:
        if file_diff.is_deleted:
            logger.debug(f"Skipping deleted file: {file_diff.path}")
            continue

        if not file_diff.hunks:
            continue

        # Get functions in this file from Analysis Server
        try:
            functions = analysis_client.get_functions_by_file(file_diff.path)
        except Exception as e:
            logger.warning(f"Failed to get functions for {file_diff.path}: {e}")
            continue

        if not functions:
            logger.debug(f"No functions found in {file_diff.path}")
            continue

        # Find which functions overlap with changed lines
        changed_lines = set(file_diff.changed_lines)

        for func in functions:
            func_start = func.get("start_line", 0)
            func_end = func.get("end_line", 0)
            func_name = func.get("name", "")

            if not func_name or not func_start:
                continue

            # Check if any changed line is within this function
            func_lines = set(range(func_start, func_end + 1))
            overlap = changed_lines & func_lines

            if overlap:
                # Extract diff content for this function
                diff_excerpt, func_changed_lines = _extract_hunk_content_for_function(
                    file_diff.hunks, func_start, func_end
                )

                # Check reachability (but don't filter!)
                static_reachable = False
                distance = None
                try:
                    reachability = analysis_client.get_reachability(fuzzer, func_name)
                    static_reachable = reachability.get("reachable", False)
                    distance = reachability.get("distance")
                except Exception as e:
                    logger.warning(f"Failed to check reachability for {func_name}: {e}")

                reachable_mark = "✓" if static_reachable else "✗(static)"
                logger.debug(
                    f"  {func_name} [{reachable_mark}] - {len(overlap)} changed lines"
                )

                all_changes.append(
                    FunctionChange(
                        file_path=file_diff.path,
                        function_name=func_name,
                        function_file=func.get("file_path", file_diff.path),
                        line_start=func_start,
                        line_end=func_end,
                        changed_lines=list(overlap),
                        diff_content=diff_excerpt,
                        static_reachable=static_reachable,
                        reachability_distance=distance,
                    )
                )

    # Sort: reachable first, then by distance
    all_changes.sort(
        key=lambda x: (
            0 if x.static_reachable else 1,
            x.reachability_distance if x.reachability_distance is not None else 999,
        )
    )

    reachable_count = sum(1 for c in all_changes if c.static_reachable)
    logger.info(
        f"Found {len(all_changes)} changed functions ({reachable_count} static-reachable, {len(all_changes) - reachable_count} static-unreachable)"
    )

    return all_changes


__all__ = [
    # Data classes
    "DiffHunk",
    "FileDiff",
    "ReachableChange",
    "FunctionChange",
    "DiffReachabilityResult",
    # Functions
    "parse_diff",
    "get_reachable_changes",
    "get_reachable_changes_simple",
    "get_all_changes",
]
