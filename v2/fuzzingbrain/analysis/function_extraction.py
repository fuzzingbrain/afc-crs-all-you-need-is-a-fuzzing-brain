"""
Function Metadata Extraction

High-level API for extracting function metadata from source code.
"""

from pathlib import Path
from typing import List, Dict
from .parsers.c_parser import parse_c_file, FunctionInfo


# Default directories to exclude (system headers, third-party libs, build artifacts)
DEFAULT_EXCLUDE_DIRS = {
    # System
    "usr",
    "include",
    # Third-party libraries
    "llvm",
    "clang",
    "boost",
    "third_party",
    "third-party",
    "vendor",
    "external",
    "deps",
    "node_modules",
    # Build artifacts
    "build",
    "out",
    "cmake-build",
    ".git",
    "__pycache__",
}


def extract_functions_from_file(
    file_path: Path, language: str = "c"
) -> List[FunctionInfo]:
    """
    Extract all functions from a source file.

    Args:
        file_path: Path to the source file
        language: Programming language ("c" or "java")

    Returns:
        List of FunctionInfo objects
    """
    if language == "c":
        return parse_c_file(file_path)
    elif language == "java":
        # TODO: Implement Java parser
        raise NotImplementedError("Java parser not yet implemented")
    else:
        raise ValueError(f"Unsupported language: {language}")


def _should_exclude(file_path: Path, exclude_dirs: set) -> bool:
    """Check if file should be excluded"""
    parts = file_path.parts
    for part in parts:
        if part in exclude_dirs:
            return True
    return False


def extract_functions_from_directory(
    directory: Path,
    language: str = "c",
    extensions: List[str] = None,
    exclude_dirs: set = None,
) -> List[FunctionInfo]:
    """
    Extract all functions from a directory of source files.

    Args:
        directory: Directory to search
        language: Programming language ("c" or "java")
        extensions: File extensions to include
        exclude_dirs: Directory names to skip (uses DEFAULT_EXCLUDE_DIRS if None)

    Returns:
        List of FunctionInfo objects
    """
    if exclude_dirs is None:
        exclude_dirs = DEFAULT_EXCLUDE_DIRS

    if language == "c":
        if extensions is None:
            extensions = [".c", ".h"]

        all_functions = []
        for ext in extensions:
            for file_path in directory.rglob(f"*{ext}"):
                if _should_exclude(file_path, exclude_dirs):
                    continue
                try:
                    functions = parse_c_file(file_path)
                    all_functions.extend(functions)
                except Exception as e:
                    print(f"Warning: Failed to parse {file_path}: {e}")
        return all_functions
    elif language == "java":
        raise NotImplementedError("Java parser not yet implemented")
    else:
        raise ValueError(f"Unsupported language: {language}")


def get_function_metadata(
    function_names: List[str], project_dir: Path, language: str = "c"
) -> Dict[str, List[FunctionInfo]]:
    """
    Get metadata for specific functions.

    Args:
        function_names: List of function names to find
        project_dir: Project source directory
        language: Programming language

    Returns:
        Dictionary mapping function name to list of FunctionInfo (supports duplicate names)
    """
    # Extract all functions
    all_functions = extract_functions_from_directory(project_dir, language)

    # Build lookup by name (keep all duplicates)
    result: Dict[str, List[FunctionInfo]] = {}
    for func in all_functions:
        if func.name in function_names:
            if func.name not in result:
                result[func.name] = []
            result[func.name].append(func)

    return result


def find_function_by_name(
    name: str, project_dir: Path, language: str = "c"
) -> List[FunctionInfo]:
    """
    Find a specific function by name.

    Args:
        name: Function name to find
        project_dir: Project source directory
        language: Programming language

    Returns:
        List of FunctionInfo (may contain duplicates)
    """
    result = get_function_metadata([name], project_dir, language)
    return result.get(name, [])
