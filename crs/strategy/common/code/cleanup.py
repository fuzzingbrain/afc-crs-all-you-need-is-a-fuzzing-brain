"""Source-code cleanup helpers (license/comment stripping)."""
from __future__ import annotations

import logging
import re
from typing import Tuple

logger = logging.getLogger(__name__)

_LICENSE_START_PATTERNS: Tuple[str, ...] = (
    "/*",
    "/**",
    "// Copyright",
    "/* Copyright",
    "# Copyright",
    "// Licensed",
    "/* Licensed",
    "# Licensed",
    "// SPDX-License-Identifier",
    "/* SPDX-License-Identifier",
)

_LICENSE_END_PATTERNS: Tuple[str, ...] = ("*/", "**/")

_LICENSE_KEYWORDS: Tuple[str, ...] = (
    "copyright",
    "license",
    "permission",
    "redistribution",
)


def strip_license_text(source_code: str) -> str:
    """Remove a leading copyright / license block from ``source_code``.

    This is an in-memory preprocessing step used solely to reduce the token
    count of prompts sent to a Large Language Model (LLM) for vulnerability
    analysis and patch generation. The returned string is consumed by the
    LLM client only; it is **never written back to disk, committed, or
    redistributed**, and no third-party source code is published with its
    license / copyright information removed.

    First tries a structured block scan (``/* ... */`` style) anchored on
    license keywords; if that does not find a clear block, falls back to
    a heuristic that drops any leading run of comment lines whose combined
    text mentions license-related keywords.

    Args:
        source_code: File contents to clean.

    Returns:
        The source with a leading license block removed, or the original
        text when no block could be confidently identified.
    """
    lines = source_code.split("\n")
    in_license_block = False
    license_end_line = -1

    # First: look for a structured license block with clear start + end.
    for i, line in enumerate(lines):
        stripped = line.strip()

        if not in_license_block:
            for pattern in _LICENSE_START_PATTERNS:
                if stripped.startswith(pattern) and any(
                    kw in stripped.lower() for kw in _LICENSE_KEYWORDS
                ):
                    in_license_block = True
                    break
            continue

        # We are inside a candidate block; look for an end marker that is
        # not also a start marker (guarding against one-line comments that
        # contain both ``/*`` and ``*/`` delimiters).
        for pattern in _LICENSE_END_PATTERNS:
            if stripped.endswith(pattern) and not any(
                start in stripped for start in _LICENSE_START_PATTERNS
            ):
                license_end_line = i
                break

        if license_end_line >= 0:
            break

    if in_license_block and license_end_line >= 0:
        return "\n".join(lines[license_end_line + 1:]).strip()

    # Fallback: drop leading comment lines if they collectively smell like
    # a license header.
    first_code_line = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if not (
            stripped.startswith("//")
            or stripped.startswith("/*")
            or stripped.startswith("*")
            or stripped.startswith("#")
        ):
            first_code_line = i
            break

    if first_code_line > 0:
        header = "\n".join(lines[:first_code_line]).lower()
        if any(kw in header for kw in _LICENSE_KEYWORDS):
            return "\n".join(lines[first_code_line:]).strip()

    return source_code


_LICENSE_HEADER_REGEX = re.compile(
    r"^\s*/\*.*?(?:license|copyright|apache|mit|gpl|bsd|gnu).*?\*/\s*",
    re.IGNORECASE | re.DOTALL,
)
_C_MULTILINE_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_C_LINE_COMMENT = re.compile(r"//.*?$", re.MULTILINE)
_PY_DOUBLE_DOCSTRING = re.compile(r'^\s*""".*?"""\s*', re.DOTALL)
_PY_SINGLE_DOCSTRING = re.compile(r"^\s*'''.*?'''\s*", re.DOTALL)
_PY_LINE_COMMENT = re.compile(r"#.*?$", re.MULTILINE)
_BLANK_LINE_COLLAPSE = re.compile(r"\n{3,}")


def strip_comments_and_license(source_code: str, file_path: str) -> str:
    """Remove license headers and code comments from ``source_code``.

    The language is guessed from ``file_path``; supported families are
    C/C++ (``.c``, ``.cpp``, ``.h``, ``.hpp``), Java (``.java``), and
    Python (``.py``). Unknown extensions fall through with only the
    trailing blank-line collapse applied.

    Args:
        source_code: File contents to clean.
        file_path: Path used only for extension detection.

    Returns:
        The cleaned source.
    """
    if file_path.endswith((".java", ".c", ".cpp", ".h", ".hpp")):
        source_code = _LICENSE_HEADER_REGEX.sub("", source_code)
        source_code = _C_MULTILINE_COMMENT.sub("", source_code)
        source_code = _C_LINE_COMMENT.sub("", source_code)
    elif file_path.endswith(".py"):
        source_code = _PY_DOUBLE_DOCSTRING.sub("", source_code)
        source_code = _PY_SINGLE_DOCSTRING.sub("", source_code)
        source_code = _PY_LINE_COMMENT.sub("", source_code)

    return _BLANK_LINE_COLLAPSE.sub("\n\n", source_code)
