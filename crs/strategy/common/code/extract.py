"""Source-code inspection utilities.

Helpers that read source files or source snippets to extract function
names and complete function bodies. Covers C / C++ / Java, plus a
relaxed multi-language function-name scanner used to label LLM-produced
code blocks.
"""
from __future__ import annotations

import logging
import re
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


_FUNCTION_NAME_PATTERNS: Tuple[str, ...] = (
    # C/C++ style: ``static void foo(...)``, ``png_something foo(...)``, etc.
    r"(?:static\s+)?(?:void|int|char|double|float|size_t|png_\w+)\s+(\w+)\s*\(",
    # More general C/C++: any type (possibly pointer) followed by name(
    r"(?:static\s+)?(?:\w+)\s+(?:\*\s*)?(\w+)\s*\(",
    r"function\s+(\w+)\s*\(",
    r"def\s+(\w+)\s*\(",
    # Java method signatures (modifiers + type + name().
    r"(?:public|private|protected|static|final|native|synchronized|abstract|transient)?\s*"
    r"(?:<.*>)?\s*(?:(?:\w+)(?:<.*>)?(?:\[\])?\s+)?(\w+)\s*\(",
    r"(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*(?:\w+)(?:<.*>)?\s+(\w+)\s*\(",
)


def extract_function_name_from_code(code_block: str) -> Optional[str]:
    """Best-effort extraction of a function name from a free-form code block.

    Runs a small list of language-agnostic regex patterns in priority
    order and returns the first match. Used to tag LLM-produced patches
    with their target function name.

    Args:
        code_block: Source snippet of unknown language.

    Returns:
        The function name, or ``None`` when no pattern matches.
    """
    for pattern in _FUNCTION_NAME_PATTERNS:
        match = re.search(pattern, code_block)
        if match:
            return match.group(1)
    return None


def _extract_java_function(content: str, function_name: str) -> str:
    """Return a Java method body by regex-matching on ``function_name``."""
    pattern = (
        r"(?:public|private|protected|static|\s)+ +(?:[a-zA-Z0-9_<>]+) +"
        + re.escape(function_name)
        + r" *\([^)]*\) *(?:\{[^}]*\}|\{(?:\{[^}]*\}|[^{}])*\})"
    )
    match = re.search(pattern, content, re.DOTALL)
    return match.group(0) if match else ""


def _extract_c_function(content: str, function_name: str) -> str:
    """Return a C/C++ function body using declaration search + brace matching."""
    decl_pattern = (
        r"(?:(?:static|inline|extern)?\s+(?:[a-zA-Z0-9_]+\s+)*"
        + re.escape(function_name)
        + r"\s*\([^)]*\)\s*(?:\{|$))|(?:^"
        + re.escape(function_name)
        + r"\s*\([^)]*\)\s*(?:\{|$))"
    )
    decl_match = re.search(decl_pattern, content, re.MULTILINE)
    if not decl_match:
        return ""

    start_pos = decl_match.start()
    opening_brace_pos = content.find("{", start_pos)
    if opening_brace_pos == -1:
        return ""

    brace_count = 1
    pos = opening_brace_pos + 1
    while brace_count > 0 and pos < len(content):
        ch = content[pos]
        if ch == "{":
            brace_count += 1
        elif ch == "}":
            brace_count -= 1
        pos += 1

    if brace_count != 0:
        return ""
    return content[start_pos:pos]


def extract_function_body(file_path: str, function_name: str) -> str:
    """Extract the full body of ``function_name`` from ``file_path``.

    Supports ``.java``, ``.c``, ``.cpp``, and ``.h`` files. For Java
    uses a single regex with limited nested-brace handling; for C/C++
    uses a declaration regex plus brace-count matching.

    Args:
        file_path: Path to a source file on disk.
        function_name: Name of the function to locate.

    Returns:
        The complete function declaration + body as a string, or ``""``
        when the function could not be located. Returns ``""`` for
        unsupported file extensions.

    Raises:
        FileNotFoundError: If ``file_path`` does not exist.
    """
    try:
        with open(file_path, "r") as fh:
            content = fh.read()
    except FileNotFoundError:
        raise
    except OSError as exc:
        logger.debug("Error reading %s: %s", file_path, exc)
        return ""

    if file_path.endswith(".java"):
        return _extract_java_function(content, function_name)
    if file_path.endswith((".c", ".cpp", ".h")):
        return _extract_c_function(content, function_name)
    return ""
