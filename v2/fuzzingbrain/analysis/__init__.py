"""
Static Analysis Module

Provides code analysis capabilities for FuzzingBrain.

Modules:
- parsers: Source code parsing (tree-sitter)
- function_extraction: Function metadata extraction
- introspector_parser: Call graph and reachability analysis (via OSS-Fuzz introspector)
- diff_parser: Diff parsing and reachability analysis
"""

from .function_extraction import get_function_metadata, extract_functions_from_file
from .introspector_parser import (
    analyze_introspector,
    parse_introspector_json,
    get_reachable_functions,
    find_call_path,
    FunctionInfo,
    CallGraph,
)
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
    # Introspector analysis (recommended)
    "analyze_introspector",
    "parse_introspector_json",
    "get_reachable_functions",
    "find_call_path",
    "FunctionInfo",
    "CallGraph",
    # Diff parsing and reachability
    "parse_diff",
    "get_reachable_changes",
    "get_reachable_changes_simple",
    "DiffHunk",
    "FileDiff",
    "ReachableChange",
    "DiffReachabilityResult",
]
