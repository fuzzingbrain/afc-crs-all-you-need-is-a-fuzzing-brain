"""Source-code inspection utilities.

Helpers that read source files or source snippets to extract function
names and complete function bodies. Covers C / C++ / Java, plus a
relaxed multi-language function-name scanner used to label LLM-produced
code blocks.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional, Tuple

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


def extract_java_method(file_path: str, method_name: str) -> Optional[Dict[str, Any]]:
    """Extract a Java method by name, with line-accurate metadata.

    Unlike :func:`extract_function_body` (which returns just the
    method text), this helper returns a dict with ``start_line``,
    ``end_line``, and ``content``. It uses a string-aware brace
    matcher that tracks strings, char literals, and both kinds of
    comments so ``{`` / ``}`` inside those lexical contexts don't
    throw off the count.

    Args:
        file_path: Path to a ``.java`` source file.
        method_name: The method name to locate.

    Returns:
        ``{"start_line": int, "end_line": int, "content": str}`` when
        found, or ``None`` when the method is missing, the file cannot
        be read, or the braces do not balance.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as exc:
        logger.debug("Error reading %s: %s", file_path, exc)
        return None

    method_pattern = (
        r"(?:public|protected|private|static|final|native|synchronized|abstract|transient)?\s*"
        r"(?:<.*?>)?\s*(?:[\w\<\>\[\]]+)\s+"
        + re.escape(method_name)
        + r"\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*\{"
    )

    for match in re.finditer(method_pattern, content):
        start_pos = match.start()
        end_pos = _find_matching_brace_end(content, start_pos)
        if end_pos is None:
            continue

        method_code = content[start_pos : end_pos + 1]
        start_line = content[:start_pos].count("\n") + 1
        end_line = start_line + method_code.count("\n")
        return {
            "start_line": start_line,
            "end_line": end_line,
            "content": method_code,
        }

    return None


def _find_matching_brace_end(content: str, start_pos: int) -> Optional[int]:
    """Return the index of the ``}`` that balances the first ``{`` at/after ``start_pos``.

    Tracks lexical context so brace characters inside strings,
    character literals, ``//`` line comments, and ``/* */`` block
    comments are ignored.
    """
    brace_count = 0
    in_string = False
    in_char = False
    in_line_comment = False
    in_block_comment = False

    i = start_pos
    length = len(content)
    while i < length:
        char = content[i]
        next_char = content[i + 1] if i + 1 < length else ""

        if in_line_comment:
            if char == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if char == "*" and next_char == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if char == "\\" and next_char in ('"', "\\"):
                i += 2
                continue
            if char == '"':
                in_string = False
            i += 1
            continue
        if in_char:
            if char == "\\" and next_char in ("'", "\\"):
                i += 2
                continue
            if char == "'":
                in_char = False
            i += 1
            continue

        if char == "/" and next_char == "/":
            in_line_comment = True
            i += 2
            continue
        if char == "/" and next_char == "*":
            in_block_comment = True
            i += 2
            continue
        if char == '"':
            in_string = True
            i += 1
            continue
        if char == "'":
            in_char = True
            i += 1
            continue

        if char == "{":
            brace_count += 1
        elif char == "}":
            brace_count -= 1
            if brace_count == 0:
                return i
        i += 1

    return None
