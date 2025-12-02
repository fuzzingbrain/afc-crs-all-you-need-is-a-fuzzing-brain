"""
Data models for function extraction
"""
from dataclasses import dataclass


@dataclass
class FunctionInfo:
    """Information about an extracted function"""
    name: str
    file_path: str
    start_line: int
    end_line: int
    body: str
    return_type: str = ""
    parameters: str = ""
    language: str = "c"  # "c", "c++", or "java"
