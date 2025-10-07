"""
Crash output parsing utilities
"""
import hashlib
import re


def extract_java_fallback_location(output: str) -> str:
    """
    Return 'pkg.Class.method:LINE' from a Java stack trace

    Args:
        output: Crash output containing Java stack trace

    Returns:
        Formatted location string or empty string if not found
    """
    for line in output.split('\n'):
        line = line.strip()
        # Matches: at org.foo.Bar.baz(Bar.java:42)
        m = re.match(r'at\s+([\w\.$]+)\(([^:]+):(\d+)\)', line)
        if m:
            qualified_method = m.group(1)   # org.foo.Bar.baz
            line_no          = m.group(3)   # 42
            return f"{qualified_method}:{line_no}"
    return ""


def extract_asan_fallback_location(output: str) -> str:
    """
    Extract location from ASAN output if #0 line isn't found

    Args:
        output: Crash output from AddressSanitizer

    Returns:
        Crash location or empty string
    """
    # Look for "SUMMARY: AddressSanitizer: <type> <location>"
    match = re.search(r'SUMMARY: AddressSanitizer: \w+ ([^(]+)', output)
    if match:
        return match.group(1).strip()

    return ""


def extract_ubsan_fallback_location(output: str) -> str:
    """
    Extract location from UBSAN output

    Args:
        output: Crash output from UndefinedBehaviorSanitizer

    Returns:
        Crash location or empty string
    """
    # Look for the file and line where UBSAN detected the issue
    match = re.search(r'([^:]+:\d+:\d+): runtime error:', output)
    if match:
        return match.group(1)

    return ""


def extract_msan_fallback_location(output: str) -> str:
    """
    Extract location from MSAN output

    Args:
        output: Crash output from MemorySanitizer

    Returns:
        Crash location or empty string
    """
    # Look for "WARNING: MemorySanitizer: <description> <location>"
    match = re.search(r'MemorySanitizer:.*? at ([^:]+:\d+)', output)
    if match:
        return match.group(1)

    return ""


def extract_crash_location(output: str, sanitizer: str) -> str:
    """
    Extract the crash location from the output

    Args:
        output: The crash output
        sanitizer: The sanitizer type

    Returns:
        The crash location or empty string if not found
    """
    # Look for the #0 line in the stack trace which indicates the crash point
    lines = output.split('\n')

    # First try to find the #0 line which is the most reliable indicator
    for line in lines:
        line = line.strip()
        if line.startswith('#0 '):
            # Extract the function and location after "in"
            parts = line.split(' in ', 1)
            if len(parts) < 2:
                continue

            # Get the function name and file location
            func_info = parts[1]

            # Clean up any extra information in parentheses
            if ' (' in func_info:
                func_info = func_info.split(' (', 1)[0]

            # Remove column information (e.g., ":13" in "file.c:123:13")
            last_colon_idx = func_info.rfind(':')
            if last_colon_idx != -1:
                # Check if there's another colon before this one (for the line number)
                prev_colon_idx = func_info[:last_colon_idx].rfind(':')
                if prev_colon_idx != -1:
                    # This is likely a column number, remove it
                    func_info = func_info[:last_colon_idx]

            return func_info

    if ".java" in output:
        java_loc = extract_java_fallback_location(output)
        if java_loc:
            return java_loc

    # If we couldn't find a #0 line, look for sanitizer-specific patterns
    sanitizer = sanitizer.lower()
    if sanitizer in ["address", "asan"]:
        return extract_asan_fallback_location(output)
    elif sanitizer in ["undefined", "ubsan"]:
        return extract_ubsan_fallback_location(output)
    elif sanitizer in ["memory", "msan"]:
        return extract_msan_fallback_location(output)

    # If all else fails, look for any file path with a line number
    for line in lines:
        if '/src/' in line and '.c:' in line:
            # This might be a file reference
            match = re.search(r'(/src/[^:]+:\d+)', line)
            if match:
                return match.group(1)

    return ""


def generate_vulnerability_signature(output: str, sanitizer: str) -> str:
    """
    Create a unique signature for a vulnerability to identify duplicates
    based on the crash output and sanitizer

    Args:
        output: The crash output
        sanitizer: The sanitizer type (address, undefined, memory, etc.)

    Returns:
        A unique signature for the vulnerability
    """
    def hash_string(s: str) -> str:
        """Create a hash of a string"""
        return hashlib.md5(s.encode()).hexdigest()

    # Extract the crash location from the stack trace
    crash_location = extract_crash_location(output, sanitizer)

    # If we couldn't extract a specific location, fall back to a hash
    if not crash_location:
        return f"{sanitizer.upper()}:generic:{hash_string(output)}"

    # Create a signature with the sanitizer type and crash location
    return f"{crash_location}"


def extract_crash_trace(fuzzer_output: str) -> str:
    """
    Extract crash trace from fuzzer output.
    Handles C/C++ ASAN errors and Java exceptions.

    Args:
        fuzzer_output: Output from the fuzzer

    Returns:
        Extracted crash trace
    """
    # Define patterns to look for
    patterns = [
        # C/C++ ASAN errors
        {"marker": "ERROR:", "end_marker": None},
        # Standard Jazzer format
        {"marker": "Uncaught exception:", "end_marker": "Reproducer file written to:"},
        # Alternative Java exception format
        {"marker": "Java Exception:", "end_marker": "Reproducer file written to:"},
        # Generic Java exception format (fallback)
        {"marker": "Exception in thread", "end_marker": None}
    ]

    # Try each pattern
    for pattern in patterns:
        marker_index = fuzzer_output.find(pattern["marker"])
        if marker_index != -1:
            # Found a match
            if pattern["end_marker"]:
                end_index = fuzzer_output.find(pattern["end_marker"], marker_index)
                if end_index != -1:
                    return fuzzer_output[marker_index:end_index].strip()

            # If no end marker or end marker not found, take everything to the end
            return fuzzer_output[marker_index:].strip()

    return fuzzer_output


def extract_crash_output(output: str, max_size: int = 4096) -> str:
    """
    Extract the relevant crash output from fuzzer output.
    Handles various sanitizer errors, libFuzzer crashes, and Java exceptions.

    Args:
        output: Full fuzzer output
        max_size: Maximum size to return in bytes

    Returns:
        Most relevant part of the crash output (up to max_size bytes)
    """
    # Define patterns to look for, in order of priority
    patterns = [
        # AddressSanitizer errors
        {"marker": "ERROR: AddressSanitizer", "backtrack": False},
        # UndefinedBehaviorSanitizer errors
        {"marker": "ERROR: UndefinedBehaviorSanitizer", "backtrack": False},
        # MemorySanitizer errors
        {"marker": "ERROR: MemorySanitizer", "backtrack": False},
        {"marker": "WARNING: MemorySanitizer", "backtrack": False},
        # ThreadSanitizer errors
        {"marker": "ERROR: ThreadSanitizer", "backtrack": False},
        # LeakSanitizer errors
        {"marker": "ERROR: LeakSanitizer", "backtrack": False},
        # libFuzzer crash indicator
        {"marker": "==ERROR: libFuzzer", "backtrack": False},
        # SEGV indicator (with backtracking to find the start of the report)
        {"marker": "SUMMARY: AddressSanitizer: SEGV", "backtrack": True},
        # Generic sanitizer summary (with backtracking)
        {"marker": "SUMMARY: ", "backtrack": True},
        # Java exceptions - Jazzer format
        {"marker": "Uncaught exception:", "backtrack": False},
        # Alternative Java exception format
        {"marker": "Java Exception:", "backtrack": False},
        # Generic Java exception format
        {"marker": "Exception in thread", "backtrack": False}
    ]

    # Try each pattern
    for pattern in patterns:
        marker_index = output.find(pattern["marker"])
        if marker_index != -1:
            # Found a match
            start_idx = marker_index

            # If backtracking is enabled, try to find the start of the error report
            if pattern["backtrack"]:
                # Look for the nearest "==" before the marker
                error_start = output[:marker_index].rfind("==")
                if error_start != -1:
                    start_idx = error_start
                else:
                    error_start = output[:marker_index].rfind("runtime error:")
                    if error_start != -1:
                        start_idx = error_start

            # Extract up to max_size bytes
            if len(output) - start_idx > max_size:
                return output[start_idx:start_idx + max_size]
            else:
                return output[start_idx:]

    # If no specific error marker found, return the last max_size bytes of output
    if len(output) > max_size:
        return output[-max_size:]

    return output
