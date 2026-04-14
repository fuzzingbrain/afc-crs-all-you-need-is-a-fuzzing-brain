"""Large-diff processor.

When a commit diff is huge (>50 KB is typical), LLM context budgets
force us to cherry-pick the most security-relevant hunks rather than
pass everything. This module does the cherry-picking: it splits the
diff per file, classifies each file as C/Java/other/binary, scores
every file by counting security-keyword hits plus a change-volume term,
and emits a processed summary that prioritises the top-scoring files
within a soft byte budget.

The keyword lists are intentionally literal and broad — the goal is
cheap ranking, not precise tagging.
"""
from __future__ import annotations

import logging
import os
import re
from typing import List, Tuple

logger = logging.getLogger(__name__)

_C_EXTENSIONS: Tuple[str, ...] = (".c", ".h")
_JAVA_EXTENSIONS: Tuple[str, ...] = (".java",)
_BINARY_INDICATORS: Tuple[str, ...] = ("Binary files", "GIT binary patch")

_C_SECURITY_KEYWORDS: Tuple[str, ...] = (
    "overflow", "underflow", "bounds", "check", "validate", "sanitize", "input",
    "malloc", "free", "alloc", "realloc", "memcpy", "strcpy", "strncpy", "strlcpy",
    "buffer", "size", "length", "null", "nullptr", "crash", "assert",
    "error", "vulnerability", "exploit", "security", "unsafe", "safe",
    "race", "deadlock", "lock", "mutex", "semaphore", "atomic",
    "format", "printf", "sprintf", "fprintf", "snprintf", "scanf", "sscanf",
    "exec", "system", "popen", "shell", "command", "injection",
    "crypt", "encrypt", "decrypt", "hash", "sign", "verify",
    "random", "prng", "secret", "key", "token", "permission",
    "privilege", "sandbox", "container", "isolation",
    "sizeof", "pointer", "array", "index", "out-of-bounds",
    "integer", "signed", "unsigned", "cast", "conversion",
    "stack", "heap", "use-after-free", "double-free",
)

_JAVA_SECURITY_KEYWORDS: Tuple[str, ...] = (
    "overflow", "underflow", "bounds", "check", "validate", "sanitize", "input",
    "buffer", "size", "length", "null", "crash", "assert", "exception",
    "error", "vulnerability", "exploit", "security", "unsafe", "safe",
    "race", "deadlock", "lock", "mutex", "semaphore", "atomic", "concurrent",
    "format", "printf", "String.format", "injection", "sql", "query",
    "auth", "password", "crypt", "encrypt", "decrypt", "hash", "sign", "verify",
    "certificate", "random", "SecureRandom", "secret", "key", "token", "permission",
    "privilege", "sandbox", "isolation", "escape",
    "ClassLoader", "Reflection", "serialization", "deserialization",
    "XSS", "CSRF", "SSRF", "XXE", "RCE", "JNDI", "LDAP", "JMX",
    "ArrayIndexOutOfBoundsException", "NullPointerException",
)

_HIGH_RISK_C_PATTERNS: Tuple[str, ...] = (
    "memcpy", "strcpy", "strcat", "sprintf", "gets", "malloc", "free",
    "sizeof", "[", "]", "->", "char *", "void *", "int *",
)

_HIGH_RISK_JAVA_PATTERNS: Tuple[str, ...] = (
    "Runtime.exec", "ProcessBuilder", "System.load", "URLClassLoader",
    "ObjectInputStream", "readObject", "Class.forName", "reflection",
    "setAccessible", "doPrivileged", "native", "JNI", "array", "index",
    "Exception", "try", "catch", "finally", "throw",
)

_PROCESSED_BYTE_BUDGET = 40_000
_MAX_PRIMARY_FILES = 10
_MAX_SECONDARY_FILES = 3


def _split_file_diffs(diff_content: str) -> Tuple[str, List[str]]:
    """Split a raw diff into ``(header, [file_diff, ...])``."""
    parts = re.split(r"diff --git ", diff_content)
    if parts and not parts[0].strip().startswith("a/"):
        header = parts[0]
        body = parts[1:]
    else:
        header = ""
        body = parts

    return header, ["diff --git " + d if d.strip() else d for d in body]


def _classify_files(
    file_diffs: List[str],
) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]], int, int]:
    """Bucket file diffs into ``(c_files, java_files, binary_count, other_count)``."""
    c_files: List[Tuple[str, str]] = []
    java_files: List[Tuple[str, str]] = []
    binary_count = 0
    other_count = 0

    for file_diff in file_diffs:
        if not file_diff.strip():
            continue

        if any(indicator in file_diff for indicator in _BINARY_INDICATORS):
            binary_count += 1
            continue

        match = re.search(r"a/([^\s]+)", file_diff)
        if not match:
            other_count += 1
            continue

        filename = match.group(1)
        ext = os.path.splitext(filename)[1].lower()
        if ext in _C_EXTENSIONS:
            c_files.append((filename, file_diff))
        elif ext in _JAVA_EXTENSIONS:
            java_files.append((filename, file_diff))
        else:
            other_count += 1

    return c_files, java_files, binary_count, other_count


def _score_file_diff(
    file_diff: str,
    keywords: Tuple[str, ...],
    high_risk_patterns: Tuple[str, ...],
) -> int:
    """Return a heuristic security-relevance score for a single file diff."""
    score = 0
    lower = file_diff.lower()
    for kw in keywords:
        score += lower.count(kw) * 2

    added_lines = len(re.findall(r"^\+(?!\+\+)", file_diff, re.MULTILINE))
    removed_lines = len(re.findall(r"^-(?!--)", file_diff, re.MULTILINE))
    score += (added_lines + removed_lines) // 5

    for pattern in high_risk_patterns:
        score += file_diff.count(pattern) * 3

    return score


def _score_files(
    files: List[Tuple[str, str]],
    keywords: Tuple[str, ...],
    high_risk_patterns: Tuple[str, ...],
) -> List[Tuple[int, str, str]]:
    """Score every file and return a descending-sorted ``(score, name, diff)`` list."""
    scored = [
        (_score_file_diff(diff, keywords, high_risk_patterns), name, diff)
        for name, diff in files
    ]
    scored.sort(reverse=True)
    return scored


def _render_file_block(i: int, label: str, filename: str, score: int, file_diff: str) -> str:
    return f"# {label} File {i + 1}: {filename} (relevance score: {score})\n{file_diff}\n\n"


def process_large_diff(diff_content: str) -> str:
    """Return a shortened security-focused variant of ``diff_content``.

    Large diffs blow past the LLM context; this helper keeps the most
    security-relevant files and drops the rest. Output layout:

    1. Original header (commit subject etc.).
    2. Summary line with total file count.
    3. The top-scoring files from the primary language (C or Java,
       whichever scores highest), up to 10 files.
    4. The top-scoring files from the other language, up to 3, only if
       the running size stays under ~40 KB.
    """
    header, file_diffs = _split_file_diffs(diff_content)
    total_files = len(file_diffs)
    logger.debug("Diff contains %d files", total_files)

    c_files, java_files, binary_count, other_count = _classify_files(file_diffs)
    logger.debug(
        "Categorised: %d C, %d Java, %d binary, %d other",
        len(c_files),
        len(java_files),
        binary_count,
        other_count,
    )

    scored_c = _score_files(c_files, _C_SECURITY_KEYWORDS, _HIGH_RISK_C_PATTERNS)
    scored_java = _score_files(java_files, _JAVA_SECURITY_KEYWORDS, _HIGH_RISK_JAVA_PATTERNS)

    parts: List[str] = [header, "\n\n", f"# Processed diff summary: {total_files} files changed\n"]

    c_max = scored_c[0][0] if scored_c else 0
    java_max = scored_java[0][0] if scored_java else 0
    prioritise_c = bool(c_files) and (not java_files or c_max >= java_max)

    primary_scored = scored_c if prioritise_c else scored_java
    secondary_scored = scored_java if prioritise_c else scored_c
    primary_label = "C" if prioritise_c else "Java"
    secondary_label = "Java" if prioritise_c else "C"
    primary_total = len(c_files) if prioritise_c else len(java_files)
    secondary_total = len(java_files) if prioritise_c else len(c_files)

    parts.append(
        f"# Showing most security-relevant changes from {primary_label} files "
        f"({primary_total} total {primary_label} files)\n\n"
    )
    for i, (score, filename, file_diff) in enumerate(primary_scored[:_MAX_PRIMARY_FILES]):
        parts.append(_render_file_block(i, primary_label, filename, score, file_diff))

    running = len("".join(parts))
    if secondary_scored and running < _PROCESSED_BYTE_BUDGET:
        take = min(_MAX_SECONDARY_FILES, len(secondary_scored))
        parts.append(f"\n# Selected {secondary_label} files ({take} of {secondary_total})\n\n")
        for i, (score, filename, file_diff) in enumerate(secondary_scored[:take]):
            parts.append(_render_file_block(i, secondary_label, filename, score, file_diff))

    processed = "".join(parts)
    logger.debug(
        "Processed diff size: %d bytes (original: %d bytes)",
        len(processed),
        len(diff_content),
    )
    return processed
