"""
C/C++ function extraction using libclang
"""
import os
from typing import List, Dict, Optional

from clang import cindex

from .models import FunctionInfo


def _get_clang_args(language: str = "c") -> List[str]:
    """Get clang compiler arguments based on language"""
    if language == "c++":
        return ["-std=c++17", "-x", "c++"]
    return ["-std=c11", "-x", "c"]


def _extract_body(file_path: str, start_line: int, end_line: int) -> str:
    """Extract function body from file given line range"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            return "".join(lines[start_line - 1 : end_line])
    except Exception:
        return ""


def extract(
    file_path: str,
    include_paths: Optional[List[str]] = None,
    language: Optional[str] = None
) -> Dict[str, FunctionInfo]:
    """
    Extract all function definitions from a C/C++ file

    Args:
        file_path: Path to the source file
        include_paths: Optional list of include directories
        language: "c" or "c++" (auto-detected if None)

    Returns:
        Dict mapping function names to FunctionInfo
    """
    if not os.path.exists(file_path):
        return {}

    # Auto-detect language
    if language is None:
        ext = os.path.splitext(file_path)[1].lower()
        language = "c++" if ext in [".cpp", ".cc", ".cxx", ".hpp", ".hxx"] else "c"

    args = _get_clang_args(language)
    if include_paths:
        args.extend([f"-I{p}" for p in include_paths])

    index = cindex.Index.create()

    try:
        tu = index.parse(file_path, args=args)
    except Exception:
        return {}

    functions = {}

    def visit(cursor):
        if cursor.kind == cindex.CursorKind.FUNCTION_DECL and cursor.is_definition():
            loc = cursor.location
            if loc.file and loc.file.name == file_path:
                extent = cursor.extent
                start = extent.start.line
                end = extent.end.line

                name = cursor.spelling
                ret_type = cursor.result_type.spelling if cursor.result_type else ""

                params = []
                for child in cursor.get_children():
                    if child.kind == cindex.CursorKind.PARM_DECL:
                        ptype = child.type.spelling
                        pname = child.spelling
                        params.append(f"{ptype} {pname}" if pname else ptype)

                functions[name] = FunctionInfo(
                    name=name,
                    file_path=file_path,
                    start_line=start,
                    end_line=end,
                    body=_extract_body(file_path, start, end),
                    return_type=ret_type,
                    parameters=", ".join(params),
                    language=language
                )

        for child in cursor.get_children():
            visit(child)

    visit(tu.cursor)
    return functions
