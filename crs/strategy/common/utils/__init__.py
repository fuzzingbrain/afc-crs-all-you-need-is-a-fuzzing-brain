# SPDX-License-Identifier: Apache-2.0
"""Utility functions for strategies"""

# Text utilities
from .text_utils import (
    truncate_output,
    is_likely_source_for_fuzzer,
    strip_license_text,
    filter_instrumented_lines,
)

# Code extraction utilities
from .code_extract import (
    extract_code,
    is_python_code,
    extract_python_code_from_response,
    extract_function_name_from_code,
    extract_function_body,
)

# Git and diff utilities
from .git_utils import (
    process_large_diff,
    get_commit_info,
    extract_diff_functions_using_funtarget,
    parse_commit_diff,
)

# Code analysis utilities
from .code_analysis import (
    extract_call_paths_from_analysis_service,
    run_static_analysis_local,
    load_qx_analysis_results,
    get_reachable_functions_qx,
)

# Crash parsing utilities
from .crash_utils import (
    extract_java_fallback_location,
    extract_asan_fallback_location,
    extract_ubsan_fallback_location,
    extract_msan_fallback_location,
    extract_crash_location,
    generate_vulnerability_signature,
    extract_crash_trace,
    extract_crash_output,
)

# Task and file utilities
from .task_utils import (
    load_task_detail,
    cleanup_seed_corpus,
    extract_and_save_crash_input,
    run_fuzzer_with_coverage,
)

# Fuzzer utilities
from .fuzzer_utils import (
    find_fuzzer_source,
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
    'extract_function_body',
    # Git/diff
    'process_large_diff',
    'get_commit_info',
    'extract_diff_functions_using_funtarget',
    'parse_commit_diff',
    # Code analysis
    'extract_call_paths_from_analysis_service',
    'run_static_analysis_local',
    'load_qx_analysis_results',
    'get_reachable_functions_qx',
    # Crash parsing
    'extract_java_fallback_location',
    'extract_asan_fallback_location',
    'extract_ubsan_fallback_location',
    'extract_msan_fallback_location',
    'extract_crash_location',
    'generate_vulnerability_signature',
    'extract_crash_trace',
    'extract_crash_output',
    # Task/file utilities
    'load_task_detail',
    'cleanup_seed_corpus',
    'extract_and_save_crash_input',
    'run_fuzzer_with_coverage',
    # Fuzzer utilities
    'find_fuzzer_source',
]
