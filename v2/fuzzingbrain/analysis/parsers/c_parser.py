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
    # Find the declarator
    declarator = node.child_by_field_name("declarator")
    if declarator is None:
        return None

    # The declarator might be a function_declarator or wrapped in pointer_declarator
    while declarator.type in ("pointer_declarator", "parenthesized_declarator"):
        # Go deeper to find the actual function_declarator
        for child in declarator.children:
            if child.type in (
                "function_declarator",
                "pointer_declarator",
                "parenthesized_declarator",
                "identifier",
            ):
                declarator = child
                break
        else:
            break

    # Now find the identifier
    if declarator.type == "function_declarator":
        for child in declarator.children:
            if child.type == "identifier":
                return child.text.decode("utf-8")
            elif child.type == "parenthesized_declarator":
                # Handle function pointers like: void (*func)(int)
                for subchild in child.children:
                    if subchild.type == "pointer_declarator":
                        for subsubchild in subchild.children:
                            if subsubchild.type == "identifier":
                                return subsubchild.text.decode("utf-8")
    elif declarator.type == "identifier":
        return declarator.text.decode("utf-8")

    return None


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
