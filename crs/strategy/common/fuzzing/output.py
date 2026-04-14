"""Fuzzer output post-processing (log filtering, line truncation).

Helpers that operate on captured fuzzer stdout/stderr before it is logged
or passed to an LLM. Distinct from ``common.fuzzing.runner``'s private
``_filter_libfuzzer_noise`` helper, which trims progress spam inside the
runner; the filters in this module target sanitiser instrumentation
chatter that appears in a wider set of contexts.
"""
from __future__ import annotations

import logging
from typing import List

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


def _truncate_line(line: str, max_line_length: int) -> str:
    """Truncate ``line`` with a marker recording the original length."""
    if len(line) <= max_line_length:
        return line
    return line[:max_line_length] + _TRUNCATION_SUFFIX.format(length=len(line))


def log_fuzzer_output(
    combined_output: str,
    max_line_length: int = 200,
    head_lines: int = 200,
    tail_lines: int = 200,
) -> None:
    """Log the head and tail of a fuzzer transcript at info level.

    The transcript is split into lines; the first ``head_lines`` and
    last ``tail_lines`` are logged, each line truncated to
    ``max_line_length`` characters. When the transcript is shorter
    than ``head_lines`` lines, only the head block is emitted.

    Args:
        combined_output: Full fuzzer stdout+stderr transcript.
        max_line_length: Per-line truncation cap.
        head_lines: Number of leading lines to log.
        tail_lines: Number of trailing lines to log.
    """
    lines = combined_output.splitlines()
    if not lines:
        return

    head: List[str] = [_truncate_line(l, max_line_length) for l in lines[:head_lines]]
    logger.info("Fuzzer output START (first %d lines):\n%s", head_lines, "\n".join(head))

    if len(lines) > head_lines:
        skipped = max(0, len(lines) - head_lines - tail_lines)
        if skipped:
            logger.info("\n... (%d lines skipped) ...\n", skipped)
        tail: List[str] = [_truncate_line(l, max_line_length) for l in lines[-tail_lines:]]
        if tail:
            logger.info("Fuzzer output END (last %d lines):\n%s", tail_lines, "\n".join(tail))
