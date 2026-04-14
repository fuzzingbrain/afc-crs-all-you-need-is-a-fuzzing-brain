"""Crash-section extraction from fuzzer transcripts.

Given the combined stdout/stderr of a libFuzzer run, pull out the most
relevant error section for LLM prompting or triage. Two entry points:

* :func:`extract_crash_trace` - looser match, returns the span from a
  known error marker to a known end marker (or end-of-output).
* :func:`extract_crash_output` - prioritised marker search with optional
  backtracking to the nearest ``==`` banner, capped at ``max_size``
  bytes.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Marker:
    marker: str
    end_marker: Optional[str] = None
    backtrack: bool = False


_TRACE_PATTERNS: Tuple[_Marker, ...] = (
    _Marker("ERROR:"),
    _Marker("Uncaught exception:", end_marker="Reproducer file written to:"),
    _Marker("Java Exception:", end_marker="Reproducer file written to:"),
    _Marker("Exception in thread"),
)

_OUTPUT_PATTERNS: Tuple[_Marker, ...] = (
    _Marker("ERROR: AddressSanitizer"),
    _Marker("ERROR: UndefinedBehaviorSanitizer"),
    _Marker("ERROR: MemorySanitizer"),
    _Marker("WARNING: MemorySanitizer"),
    _Marker("ERROR: ThreadSanitizer"),
    _Marker("ERROR: LeakSanitizer"),
    _Marker("==ERROR: libFuzzer"),
    _Marker("SUMMARY: AddressSanitizer: SEGV", backtrack=True),
    _Marker("SUMMARY: ", backtrack=True),
    _Marker("Uncaught exception:"),
    _Marker("Java Exception:"),
    _Marker("Exception in thread"),
)


def extract_crash_trace(fuzzer_output: str) -> str:
    """Return the crash span from a known start marker to a known end marker.

    Handles C/C++ AddressSanitizer ``ERROR:`` blocks, standard Jazzer
    ``Uncaught exception:`` / ``Java Exception:`` blocks (ending at
    ``Reproducer file written to:``), and generic
    ``Exception in thread`` stack traces. When no pattern matches, the
    original input is returned unchanged.
    """
    for pattern in _TRACE_PATTERNS:
        marker_index = fuzzer_output.find(pattern.marker)
        if marker_index == -1:
            continue

        if pattern.end_marker:
            end_index = fuzzer_output.find(pattern.end_marker, marker_index)
            if end_index != -1:
                return fuzzer_output[marker_index:end_index].strip()

        return fuzzer_output[marker_index:].strip()

    return fuzzer_output


def _backtrack_to_banner(output: str, marker_index: int) -> int:
    """Walk backwards from ``marker_index`` to the nearest ``==`` / ``runtime error:`` banner."""
    banner_index = output[:marker_index].rfind("==")
    if banner_index != -1:
        return banner_index
    alt = output[:marker_index].rfind("runtime error:")
    return alt if alt != -1 else marker_index


def extract_crash_output(output: str, max_size: int = 4096) -> str:
    """Return the most relevant slice of a fuzzer crash transcript.

    Walks a prioritised list of sanitiser / libFuzzer / Java markers.
    When a match is found and backtracking is enabled for that marker,
    rewinds to the nearest ``==`` or ``runtime error:`` banner so the
    returned slice includes the full report header. Truncated to
    ``max_size`` bytes.

    Args:
        output: The full fuzzer transcript.
        max_size: Maximum number of bytes to return.

    Returns:
        The crash slice. When no known marker is present, returns the
        last ``max_size`` bytes of ``output``.
    """
    for pattern in _OUTPUT_PATTERNS:
        marker_index = output.find(pattern.marker)
        if marker_index == -1:
            continue

        start_idx = (
            _backtrack_to_banner(output, marker_index)
            if pattern.backtrack
            else marker_index
        )

        if len(output) - start_idx > max_size:
            return output[start_idx:start_idx + max_size]
        return output[start_idx:]

    if len(output) > max_size:
        return output[-max_size:]
    return output
