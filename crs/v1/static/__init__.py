"""
Static analysis module for function extraction

Supports C/C++ (libclang) and Java (javalang)
"""
from .models import FunctionInfo
from .extractor import (
    extract_functions_from_file,
    extract_functions_from_directory,
    extract_function_by_name,
    find_function,
)

__all__ = [
    "FunctionInfo",
    "extract_functions_from_file",
    "extract_functions_from_directory",
    "extract_function_by_name",
    "find_function",
]
