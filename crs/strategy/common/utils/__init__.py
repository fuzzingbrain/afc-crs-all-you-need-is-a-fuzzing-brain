"""Utility functions for strategies"""

# Text utilities
from common.utils.text_utils import (
    truncate_output,
    is_likely_source_for_fuzzer,
    strip_license_text,
    filter_instrumented_lines,
)

# Code extraction utilities
from common.utils.code_extract import (
    extract_code,
    is_python_code,
    extract_python_code_from_response,
    extract_function_name_from_code,
)

# Git and diff utilities
from common.utils.git_utils import (
    process_large_diff,
    get_commit_info,
)

# Crash parsing utilities
from common.utils.crash_utils import (
    extract_java_fallback_location,
    extract_asan_fallback_location,
    extract_ubsan_fallback_location,
    extract_msan_fallback_location,
    extract_crash_location,
    generate_vulnerability_signature,
    extract_crash_trace,
)

__all__ = [
    # Text utilities
    'truncate_output',
    'is_likely_source_for_fuzzer',
    'strip_license_text',
    'filter_instrumented_lines',
    # Code extraction
    'extract_code',
    'is_python_code',
    'extract_python_code_from_response',
    'extract_function_name_from_code',
    # Git/diff
    'process_large_diff',
    'get_commit_info',
    # Crash parsing
    'extract_java_fallback_location',
    'extract_asan_fallback_location',
    'extract_ubsan_fallback_location',
    'extract_msan_fallback_location',
    'extract_crash_location',
    'generate_vulnerability_signature',
    'extract_crash_trace',
]
