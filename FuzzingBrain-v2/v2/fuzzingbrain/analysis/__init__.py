"""
Static Analysis Module

Provides code analysis capabilities for FuzzingBrain.

Modules:
- parsers: Source code parsing (tree-sitter)
- callgraph: Call graph analysis (SVF, CodeQL)
"""

from .function_extraction import get_function_metadata, extract_functions_from_file

__all__ = [
    "get_function_metadata",
    "extract_functions_from_file",
]
