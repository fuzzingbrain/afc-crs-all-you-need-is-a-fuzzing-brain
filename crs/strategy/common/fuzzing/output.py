"""Fuzzer output post-processing (log filtering, line truncation).

Helpers that operate on captured fuzzer stdout/stderr before it is logged
or passed to an LLM. Distinct from ``common.fuzzing.runner``'s private
``_filter_libfuzzer_noise`` helper, which trims progress spam inside the
runner; the filters in this module target sanitiser instrumentation
chatter that appears in a wider set of contexts.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_TRUNCATION_SUFFIX = " ... (truncated, full length: {length})"


def filter_instrumented_lines(text: str, max_line_length: int = 200) -> str:
    """Drop instrumentation/warning chatter and truncate long lines.

    - Lines starting with ``INFO:`` (libFuzzer / sanitiser banners) are
      dropped.
    - Lines containing ``Server VM warning:`` (JVM chatter) are dropped.
    - Lines starting with ``WARNING:`` after trimming leading whitespace
      are dropped.
    - Lines longer than ``max_line_length`` are truncated with a marker
      indicating the original length.

    Args:
        text: Raw transcript to filter.
        max_line_length: Maximum single-line length. Longer lines are
            truncated and the original length recorded in the marker.

    Returns:
        The filtered transcript. Empty / falsy input is passed through.
    """
    if not text:
        return text

    filtered = []
    for line in text.splitlines():
        if line.startswith("INFO: ") or "Server VM warning:" in line:
            continue
        if line.lstrip().startswith("WARNING:"):
            continue
        if len(line) > max_line_length:
            filtered.append(line[:max_line_length] + _TRUNCATION_SUFFIX.format(length=len(line)))
        else:
            filtered.append(line)

    return "\n".join(filtered)
