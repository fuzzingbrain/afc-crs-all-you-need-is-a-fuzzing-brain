# SPDX-License-Identifier: Apache-2.0
"""
C/C++ Parser using tree-sitter

Extracts function definitions from C/C++ source files.
"""

import tree_sitter_c as tsc
from tree_sitter import Language, Parser
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict


# Initialize C language and parser
C_LANGUAGE = Language(tsc.language())
_parser: Optional[Parser] = None


def get_parser() -> Parser:
    """Get or create the tree-sitter parser (singleton)"""
    global _parser
    if _parser is None:
        _parser = Parser(C_LANGUAGE)
    return _parser


@dataclass
class FunctionInfo:
    """Extracted function information"""

    name: str
    file_path: str
    start_line: int
    end_line: int
    content: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Declarator node types we descend THROUGH while hunting for the declared name.
_DECLARATOR_TYPES = frozenset(
    {
        "function_declarator",
        "pointer_declarator",
        "parenthesized_declarator",
        "array_declarator",
        "reference_declarator",  # C++ references
    }
)


def _name_from_declarator(decl) -> Optional[str]:
    """Recursively resolve the declared identifier inside a declarator subtree.

    Descent prefers the tree-sitter ``declarator`` field, which points at the
    thing being declared (the name or a nested declarator) and NOT the parameter
    list — so parameter identifiers can never be mistaken for the function name.
    This handles arbitrarily nested shapes, including a function that RETURNS a
    function pointer (``void (*getcb(int x))(int)`` -> ``getcb``), which the old
    fixed-depth walk missed entirely.
    """
    if decl is None:
        return None
    if decl.type == "identifier":
        return decl.text.decode("utf-8", errors="replace")

    if decl.type in _DECLARATOR_TYPES:
        # Field-based descent first (skips the parameter_list sibling).
        inner = decl.child_by_field_name("declarator")
        if inner is not None:
            name = _name_from_declarator(inner)
            if name:
                return name
        # Fallback: scan declarator-ish children (some grammars omit the field).
        for child in decl.children:
            if child.type in _DECLARATOR_TYPES or child.type == "identifier":
                name = _name_from_declarator(child)
                if name:
                    return name
    return None


def find_function_name(node) -> Optional[str]:
    """
    Find the function name from a function_definition node.

    The structure is typically:
    function_definition
      ├── type (e.g., "void", "int")
      ├── function_declarator
      │     ├── identifier (function name) or pointer_declarator
      │     └── parameter_list
      └── compound_statement (body)
    """
    return _name_from_declarator(node.child_by_field_name("declarator"))


def extract_c_functions(source: bytes, file_path: str) -> List[FunctionInfo]:
    """
    Extract all function definitions from C source code.

    Args:
        source: The source code as bytes
        file_path: Path to the source file (for reference)

    Returns:
        List of FunctionInfo objects
    """
    parser = get_parser()
    tree = parser.parse(source)

    functions = []

    def traverse(node):
        if node.type == "function_definition":
            name = find_function_name(node)
            if name:
                func_info = FunctionInfo(
                    name=name,
                    file_path=file_path,
                    start_line=node.start_point[0] + 1,  # 1-indexed
                    end_line=node.end_point[0] + 1,  # 1-indexed
                    content=source[node.start_byte : node.end_byte].decode(
                        "utf-8", errors="replace"
                    ),
                )
                functions.append(func_info)

        # Recurse into children
        for child in node.children:
            traverse(child)

    traverse(tree.root_node)
    return functions


def parse_c_file(file_path: Path) -> List[FunctionInfo]:
    """
    Parse a C file and extract all function definitions.

    Args:
        file_path: Path to the C source file

    Returns:
        List of FunctionInfo objects
    """
    with open(file_path, "rb") as f:
        source = f.read()

    return extract_c_functions(source, str(file_path))


def parse_c_files(directory: Path, extensions: List[str] = None) -> List[FunctionInfo]:
    """
    Parse all C files in a directory and extract functions.

    Args:
        directory: Directory to search
        extensions: File extensions to include (default: [".c", ".h"])

    Returns:
        List of FunctionInfo objects from all files
    """
    if extensions is None:
        extensions = [".c", ".h"]

    all_functions = []

    for ext in extensions:
        for file_path in directory.rglob(f"*{ext}"):
            try:
                functions = parse_c_file(file_path)
                all_functions.extend(functions)
            except Exception as e:
                print(f"Warning: Failed to parse {file_path}: {e}")

    return all_functions
