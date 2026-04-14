"""Source-code cleanup helpers (license/comment stripping)."""
from __future__ import annotations

import logging
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
