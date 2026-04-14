"""Fuzzer source-file discovery.

Heuristics and helpers for locating the source file that a fuzzer binary
was compiled from. Covers the common naming conventions used in OSS-Fuzz
projects and a ``libxyz``/``xyz`` stripping rule.
"""
from __future__ import annotations


def is_likely_source_for_fuzzer(file_base: str, fuzzer_name: str, base_name: str) -> bool:
    """Return True when ``file_base`` plausibly names the source for ``fuzzer_name``.

    ``file_base`` is the source file's basename without extension,
    ``fuzzer_name`` is the fuzzer binary name, and ``base_name`` is a
    pre-stripped variant (typically ``fuzzer_name`` with the trailing
    ``_fuzzer`` removed). The function checks a number of conventional
    mappings used throughout OSS-Fuzz projects.

    Args:
        file_base: Source file basename without extension.
        fuzzer_name: Fuzzer binary name.
        base_name: Name used as a comparison target after common suffix/
            prefix stripping.

    Returns:
        ``True`` if the file is a plausible source for the fuzzer under
        any of the supported naming conventions.
    """
    # Exact matches
    if file_base == fuzzer_name or file_base == base_name:
        return True

    # fuzzer_name == "xyz_fuzzer" and file_base == "xyz"
    if fuzzer_name == f"{file_base}_fuzzer":
        return True

    # Variants keyed off base_name: xyz_fuzz, fuzz_xyz, xyz_test, test_xyz
    if base_name == f"{file_base}_fuzz":
        return True
    if base_name == f"fuzz_{file_base}":
        return True
    if base_name == f"{file_base}_test":
        return True
    if base_name == f"test_{file_base}":
        return True

    # Prefix match (e.g. fuzzer_name == "xyz_abc_fuzzer", file_base == "xyz_abc").
    if fuzzer_name.startswith(f"{file_base}_"):
        return True

    # libxyz <-> xyz stripping in either direction.
    if base_name == file_base.replace("lib", ""):
        return True
    if file_base == base_name.replace("lib", ""):
        return True

    return False
