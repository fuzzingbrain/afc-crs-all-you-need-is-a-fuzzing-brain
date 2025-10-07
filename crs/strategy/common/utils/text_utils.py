"""
Text processing utilities
"""
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from common.logging.logger import StrategyLogger


def truncate_output(output: str, max_lines: int = 200, logger: Optional['StrategyLogger'] = None) -> str:
    """
    Truncate output to show only the first and last parts if it's too long.

    Args:
        output: The output string to truncate
        max_lines: Maximum number of lines to show
        logger: Optional StrategyLogger for logging

    Returns:
        str: Truncated output
    """
    lines = output.split('\n')
    if len(lines) <= max_lines:
        return output

    # Show first half and last half
    first_part = lines[:max_lines//2]
    last_part = lines[-(max_lines//2):]

    if logger:
        logger.debug(f"Truncated output from {len(lines)} lines to {max_lines} lines")

    return '\n'.join(first_part) + '\n\n[...truncated...]\n\n' + '\n'.join(last_part)


def is_likely_source_for_fuzzer(file_base: str, fuzzer_name: str, base_name: str) -> bool:
    """
    Check if a file is likely to be the source file for a fuzzer based on naming patterns

    Args:
        file_base: File basename without extension
        fuzzer_name: Name of the fuzzer
        base_name: Base name to compare

    Returns:
        True if the file is likely a source for the fuzzer
    """
    # Exact matches
    if file_base == fuzzer_name or file_base == base_name:
        return True

    # Common patterns:
    # 1. fuzzer_name = "xyz_fuzzer" and file_base = "xyz"
    if fuzzer_name == f"{file_base}_fuzzer":
        return True

    # 2. fuzzer_name = "xyz_fuzzer" and file_base = "xyz_fuzz"
    if base_name == f"{file_base}_fuzz":
        return True

    # 3. fuzzer_name = "xyz_fuzzer" and file_base = "fuzz_xyz"
    if base_name == f"fuzz_{file_base}":
        return True

    # 4. fuzzer_name = "xyz_fuzzer" and file_base = "xyz_test"
    if base_name == f"{file_base}_test":
        return True

    # 5. fuzzer_name = "xyz_fuzzer" and file_base = "test_xyz"
    if base_name == f"test_{file_base}":
        return True

    # 6. fuzzer_name = "xyz_abc_fuzzer" and file_base = "xyz_abc"
    if fuzzer_name.startswith(f"{file_base}_"):
        return True

    # 7. fuzzer_name = "xyz_fuzzer" and file_base = "libxyz"
    if base_name == file_base.replace("lib", ""):
        return True

    # 8. fuzzer_name = "libxyz_fuzzer" and file_base = "xyz"
    if file_base == base_name.replace("lib", ""):
        return True

    return False


def strip_license_text(source_code: str) -> str:
    """
    Strip copyright and license text from source code

    Args:
        source_code: Source code with potential license headers

    Returns:
        Source code with license text removed
    """
    # Common patterns that indicate license blocks
    license_start_patterns = [
        "/*",
        "/**",
        "// Copyright",
        "/* Copyright",
        "# Copyright",
        "// Licensed",
        "/* Licensed",
        "# Licensed",
        "// SPDX-License-Identifier",
        "/* SPDX-License-Identifier"
    ]

    license_end_patterns = [
        "*/",
        "**/"
    ]

    # Check if the source starts with a license block
    lines = source_code.split('\n')
    in_license_block = False
    license_end_line = -1

    # First, try to find a license block with clear start and end markers
    for i, line in enumerate(lines):
        stripped_line = line.strip()

        # Check for license block start
        if not in_license_block:
            for pattern in license_start_patterns:
                if stripped_line.startswith(pattern) and ("copyright" in stripped_line.lower() or
                                                         "license" in stripped_line.lower() or
                                                         "permission" in stripped_line.lower() or
                                                         "redistribution" in stripped_line.lower()):
                    in_license_block = True
                    break

        # Check for license block end if we're in a block
        elif in_license_block:
            for pattern in license_end_patterns:
                if stripped_line.endswith(pattern) and not any(p in stripped_line for p in license_start_patterns):
                    license_end_line = i
                    break

            # If we found the end, stop looking
            if license_end_line >= 0:
                break

    # If we found a license block with clear markers, remove it
    if in_license_block and license_end_line >= 0:
        return '\n'.join(lines[license_end_line+1:]).strip()

    # If we didn't find a clear license block, try a heuristic approach
    # Look for the first non-comment, non-empty line
    first_code_line = 0
    for i, line in enumerate(lines):
        stripped_line = line.strip()
        # Skip empty lines
        if not stripped_line:
            continue

        # If it's not a comment line, this is likely the start of actual code
        if not stripped_line.startswith('//') and not stripped_line.startswith('/*') and not stripped_line.startswith('*') and not stripped_line.startswith('#'):
            first_code_line = i
            break

    # If the first several lines contain copyright/license keywords, skip them
    if first_code_line > 0:
        header_text = '\n'.join(lines[:first_code_line]).lower()
        if ("copyright" in header_text or "license" in header_text or
            "permission" in header_text or "redistribution" in header_text):
            return '\n'.join(lines[first_code_line:]).strip()

    # If we couldn't identify a license block, return the original code
    return source_code


def filter_instrumented_lines(text: str, max_line_length: int = 200) -> str:
    """
    Filter out instrumentation and warning lines from fuzzer output

    Args:
        text: The text to filter
        max_line_length: Maximum length for any single line

    Returns:
        Filtered text with instrumentation lines removed and long lines truncated
    """
    if not text:
        return text

    filtered_lines = []
    for line in text.splitlines():
        # Skip lines containing "INFO: Instrumented"
        if line.startswith("INFO: ") or "Server VM warning:" in line:
            continue
        # Drop noisy sanitizer/SQLite warnings
        if line.lstrip().startswith("WARNING:"):
            continue
        # Truncate long lines
        if len(line) > max_line_length:
            truncated = line[:max_line_length] + f" ... (truncated, full length: {len(line)})"
            filtered_lines.append(truncated)
        else:
            filtered_lines.append(line)

    return '\n'.join(filtered_lines)
