"""
Source Code Parsers

Uses tree-sitter for fast and accurate parsing.
"""

from .c_parser import parse_c_file, extract_c_functions

__all__ = [
    "parse_c_file",
    "extract_c_functions",
]
