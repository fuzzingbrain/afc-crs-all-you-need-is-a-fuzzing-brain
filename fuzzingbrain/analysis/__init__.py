# SPDX-License-Identifier: Apache-2.0
"""
Static Analysis Module

Provides code analysis capabilities for FuzzingBrain.

Modules:
- parsers: Source code parsing (tree-sitter)
- function_extraction: Function metadata extraction
- diff_parser: Diff parsing and reachability analysis
"""

from .function_extraction import get_function_metadata, extract_functions_from_file
from .diff_parser import (
    parse_diff,
    get_reachable_changes,
    get_reachable_changes_simple,
    DiffHunk,
    FileDiff,
    ReachableChange,
    DiffReachabilityResult,
)

__all__ = [
    # Function extraction (tree-sitter)
    "get_function_metadata",
    "extract_functions_from_file",
    # Diff parsing and reachability
    "parse_diff",
    "get_reachable_changes",
    "get_reachable_changes_simple",
    "DiffHunk",
    "FileDiff",
    "ReachableChange",
    "DiffReachabilityResult",
]
