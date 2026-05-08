# SPDX-License-Identifier: Apache-2.0
"""Crash location extraction and vulnerability signature hashing.

Given raw fuzzer/sanitiser output, produce a concise ``file:line`` style
location string identifying where the crash happened, or a hash-based
signature when no location could be determined. These signatures are
used upstream to deduplicate reports across multiple crashes.
"""
from __future__ import annotations

import hashlib
import logging
import re

logger = logging.getLogger(__name__)


def extract_java_fallback_location(output: str) -> str:
    """Return ``'pkg.Class.method:LINE'`` from a Java stack trace.

    Args:
        output: Crash output containing a Java stack trace.

    Returns:
        Formatted ``qualified_method:line`` string, or ``""`` when no
        ``at ...(File.java:LINE)`` frame is present.
    """
    for raw in output.split("\n"):
        line = raw.strip()
        m = re.match(r"at\s+([\w\.$]+)\(([^:]+):(\d+)\)", line)
        if m:
            qualified_method = m.group(1)
            line_no = m.group(3)
            return f"{qualified_method}:{line_no}"
    return ""


def extract_asan_fallback_location(output: str) -> str:
    """Return the location after ``SUMMARY: AddressSanitizer: <type>``."""
    match = re.search(r"SUMMARY: AddressSanitizer: \w+ ([^(]+)", output)
    return match.group(1).strip() if match else ""


def extract_ubsan_fallback_location(output: str) -> str:
    """Return ``file:line:column`` from an UBSan ``runtime error:`` frame."""
    match = re.search(r"([^:]+:\d+:\d+): runtime error:", output)
    return match.group(1) if match else ""


def extract_msan_fallback_location(output: str) -> str:
    """Return the location from a ``WARNING: MemorySanitizer: ... at`` frame."""
    match = re.search(r"MemorySanitizer:.*? at ([^:]+:\d+)", output)
    return match.group(1) if match else ""


def extract_crash_location(output: str, sanitizer: str) -> str:
    """Extract a file+line style crash location from fuzzer output.

    Looks for the ``#0`` stack frame first (most reliable), then falls
    back to Java stack traces when the output mentions ``.java``, then
    to a sanitiser-specific fallback, and finally to a raw ``/src/`` path
    match.
    """
    lines = output.split("\n")

    for raw in lines:
        line = raw.strip()
        if not line.startswith("#0 "):
            continue

        parts = line.split(" in ", 1)
        if len(parts) < 2:
            continue

        func_info = parts[1]
        if " (" in func_info:
            func_info = func_info.split(" (", 1)[0]

        # Strip trailing ``:col`` column indicator when a ``:line`` is
        # already present, e.g. ``file.c:123:13`` -> ``file.c:123``.
        last_colon = func_info.rfind(":")
        if last_colon != -1:
            prev_colon = func_info[:last_colon].rfind(":")
            if prev_colon != -1:
                func_info = func_info[:last_colon]

        return func_info

    if ".java" in output:
        java_loc = extract_java_fallback_location(output)
        if java_loc:
            return java_loc

    sanitizer_lc = sanitizer.lower()
    if sanitizer_lc in ("address", "asan"):
        return extract_asan_fallback_location(output)
    if sanitizer_lc in ("undefined", "ubsan"):
        return extract_ubsan_fallback_location(output)
    if sanitizer_lc in ("memory", "msan"):
        return extract_msan_fallback_location(output)

    for line in lines:
        if "/src/" in line and ".c:" in line:
            match = re.search(r"(/src/[^:]+:\d+)", line)
            if match:
                return match.group(1)

    return ""


def generate_vulnerability_signature(output: str, sanitizer: str) -> str:
    """Return a deduplication key for a crash.

    When a specific location can be extracted, the signature is the
    location itself. Otherwise it falls back to
    ``{SANITIZER}:generic:{md5(output)}``.
    """
    crash_location = extract_crash_location(output, sanitizer)
    if not crash_location:
        digest = hashlib.md5(output.encode()).hexdigest()
        return f"{sanitizer.upper()}:generic:{digest}"
    return crash_location
