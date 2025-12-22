"""
Static Analysis Module

Provides code analysis capabilities for FuzzingBrain.

Modules:
- parsers: Source code parsing (tree-sitter)
- callgraph: Call graph analysis (SVF, CodeQL)
- function_extraction: Function metadata extraction
- static_analyzer: Orchestrates static analysis workflow
"""

from .function_extraction import get_function_metadata, extract_functions_from_file
from .callgraph import (
    get_reachable_functions,
    get_reachable_function_names,
    find_call_paths,
    parse_dot_file,
    CallGraph,
)
from .static_analyzer import StaticAnalyzer, analyze_project
from .introspector_parser import (
    analyze_introspector,
    parse_introspector_json,
    get_reachable_functions as get_introspector_reachable,
    find_call_path,
    FunctionInfo,
    CallGraph as IntrospectorCallGraph,
)

__all__ = [
    # Function extraction
    "get_function_metadata",
    "extract_functions_from_file",
    # Call graph analysis (SVF-based, legacy)
    "get_reachable_functions",
    "get_reachable_function_names",
    "find_call_paths",
    "parse_dot_file",
    "CallGraph",
    # Static analyzer
    "StaticAnalyzer",
    "analyze_project",
    # Introspector analysis (recommended)
    "analyze_introspector",
    "parse_introspector_json",
    "get_introspector_reachable",
    "find_call_path",
    "FunctionInfo",
    "IntrospectorCallGraph",
]
