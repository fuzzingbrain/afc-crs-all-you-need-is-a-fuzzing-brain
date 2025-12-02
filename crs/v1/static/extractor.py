"""
Unified function extraction interface

Supports C/C++ and Java
"""
import os
from typing import List, Dict, Optional

from .models import FunctionInfo
from . import c_extractor
from . import java_extractor


def extract_functions_from_file(
    file_path: str,
    include_paths: Optional[List[str]] = None,
    language: Optional[str] = None
) -> Dict[str, FunctionInfo]:
    """
    Extract all functions from a source file

    Args:
        file_path: Path to source file
        include_paths: Include directories (C/C++ only)
        language: "c", "c++", or "java" (auto-detected if None)

    Returns:
        Dict mapping function names to FunctionInfo
    """
    if not os.path.exists(file_path):
        return {}

    # Auto-detect language
    if language is None:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".java":
            language = "java"
        elif ext in [".cpp", ".cc", ".cxx", ".hpp", ".hxx"]:
            language = "c++"
        else:
            language = "c"

    if language == "java":
        return java_extractor.extract(file_path)
    else:
        return c_extractor.extract(file_path, include_paths, language)


def extract_functions_from_directory(
    directory: str,
    extensions: Optional[List[str]] = None,
    include_paths: Optional[List[str]] = None,
    recursive: bool = True
) -> Dict[str, Dict[str, FunctionInfo]]:
    """
    Extract functions from all source files in a directory

    Args:
        directory: Directory path
        extensions: File extensions to process
        include_paths: Include directories (C/C++ only)
        recursive: Scan subdirectories

    Returns:
        Dict mapping file paths to function dicts
    """
    if extensions is None:
        extensions = [".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".java"]

    result = {}

    def process_file(file_path: str):
        ext = os.path.splitext(file_path)[1].lower()
        if ext in extensions:
            funcs = extract_functions_from_file(file_path, include_paths)
            if funcs:
                result[file_path] = funcs

    if recursive:
        for root, _, files in os.walk(directory):
            for filename in files:
                process_file(os.path.join(root, filename))
    else:
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            if os.path.isfile(file_path):
                process_file(file_path)

    return result


def extract_function_by_name(
    file_path: str,
    function_name: str,
    include_paths: Optional[List[str]] = None
) -> Optional[FunctionInfo]:
    """
    Extract a specific function by name from a file

    Args:
        file_path: Path to source file
        function_name: Function name to find
        include_paths: Include directories (C/C++ only)

    Returns:
        FunctionInfo if found, None otherwise
    """
    functions = extract_functions_from_file(file_path, include_paths)

    # Direct match
    if function_name in functions:
        return functions[function_name]

    # For Java, match by method name (without class prefix)
    for key, info in functions.items():
        if info.name == function_name:
            return info
        if key.endswith(f".{function_name}"):
            return info

    return None


def find_function(
    function_name: str,
    directory: str,
    extensions: Optional[List[str]] = None,
    include_paths: Optional[List[str]] = None
) -> Optional[FunctionInfo]:
    """
    Search for a function by name in a directory

    Args:
        function_name: Function name to find
        directory: Directory to search in
        extensions: File extensions to search
        include_paths: Include directories (C/C++ only)

    Returns:
        FunctionInfo if found, None otherwise
    """
    all_funcs = extract_functions_from_directory(directory, extensions, include_paths)

    for file_path, funcs in all_funcs.items():
        # Direct match
        if function_name in funcs:
            return funcs[function_name]

        # For Java, match by method name
        for key, info in funcs.items():
            if info.name == function_name:
                return info
            if key.endswith(f".{function_name}"):
                return info

    return None
