# SPDX-License-Identifier: Apache-2.0
"""Crash output parsing utilities (backward-compatibility shim).

All implementations have moved to ``common.crash.location`` and
``common.crash.output``. This module re-exports them so existing
``from common.utils.crash_utils import ...`` imports keep working.
New code should import from the canonical modules directly.
"""
from common.crash.location import (  # noqa: F401
    extract_asan_fallback_location,
    extract_crash_location,
    extract_java_fallback_location,
    extract_msan_fallback_location,
    extract_ubsan_fallback_location,
    generate_vulnerability_signature,
)
from common.crash.output import (  # noqa: F401
    extract_crash_output,
    extract_crash_trace,
)
