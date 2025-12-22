"""
Static Analysis Module

Provides code analysis capabilities for FuzzingBrain.

Modules:
- parsers: Source code parsing (tree-sitter)
- function_extraction: Function metadata extraction
- introspector_parser: Call graph and reachability analysis (via OSS-Fuzz introspector)
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
]
