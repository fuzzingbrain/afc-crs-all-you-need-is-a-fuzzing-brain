"""Parsing helpers for LLM response text.

Extracts code blocks from markdown-formatted LLM output, heuristically
distinguishes Python from other languages, and drives an LLM-assisted
re-extraction pass when the initial parse fails. Used by strategies
that ask the LLM to emit a standalone Python script (e.g. POV
generators).
"""
from __future__ import annotations

import logging
import re
import time
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from common.llm.client import LLMClient

logger = logging.getLogger(__name__)


_PYTHON_INDICATOR_PATTERNS = (
    r"^\s*def\s+\w+\s*\(",
    r"^\s*class\s+\w+",
    r"^\s*import\s+\w+",
    r"^\s*from\s+\w+\s+import",
    r"if __name__\s*==",
    r"with\s+open\(",
    r"\.write\(",
    r"\.encode\(",
    r"#!/usr/bin/env python",
    r"^\s*@\w+",
)

_OTHER_LANGUAGE_PATTERNS = (
    r"^\s*#include\s*[<\"]",
    r"^\s*void\s+\w+\s*\(",
    r"^\s*int\s+main\s*\(",
    r"^\s*public\s+class\s+\w+",
    r"^\s*private\s+\w+\s+\w+\s*\(",
    r"^\s*package\s+\w+",
    r"^\s*struct\s+\w+\s*\{",
    r"^\s*typedef\s+",
)

_PYTHON_BLOCK_PATTERN = r"```python\s+([\s\S]*?)```"
_ANY_BLOCK_PATTERN = r"```(?:\w+)?\s*([\s\S]*?)```"
_GENERIC_BLOCK_PATTERN = r"```(?:python)?\s*([\s\S]*?)```"


def extract_code(text: str) -> Optional[str]:
    """Return the first fenced code block in ``text`` (``python`` tag optional)."""
    matches = re.findall(_GENERIC_BLOCK_PATTERN, text)
    if not matches:
        return None
    code = matches[0].strip()
    logger.debug("Extracted %d chars of code from markdown", len(code))
    return code


def is_python_code(text: str) -> bool:
    """Heuristic: does ``text`` look like Python and not another language?

    Scores Python-typical and non-Python-typical signatures separately
    (ignoring ``#`` comment lines when looking for non-Python patterns,
    since ``#`` is itself a Python comment). A block is Python iff it
    has at least one Python indicator and zero non-Python indicators.
    """
    if not text or len(text.strip()) < 10:
        return False

    python_score = 0
    other_lang_score = 0

    for raw in text.strip().split("\n"):
        line = raw
        if re.match(r"^\s*#", line):
            continue  # skip comment lines for non-Python scoring
        for pattern in _PYTHON_INDICATOR_PATTERNS:
            if re.search(pattern, line):
                python_score += 1
        for pattern in _OTHER_LANGUAGE_PATTERNS:
            if re.search(pattern, line):
                other_lang_score += 1

    return python_score > 0 and other_lang_score == 0


def _extract_python_from_blocks(text: str) -> Optional[str]:
    """Try to find a Python code block in ``text`` without calling the LLM."""
    python_blocks = re.findall(_PYTHON_BLOCK_PATTERN, text)
    if python_blocks:
        candidate = python_blocks[-1].strip()
        if candidate and is_python_code(candidate):
            logger.debug(
                "Extracted %d chars from explicit ```python block (last of %d)",
                len(candidate),
                len(python_blocks),
            )
            return candidate
        logger.warning(
            "Found %d ```python blocks but validation failed", len(python_blocks)
        )

    all_blocks = re.findall(_ANY_BLOCK_PATTERN, text)
    if all_blocks:
        logger.debug("Found %d total code blocks, validating each", len(all_blocks))
        for idx in range(len(all_blocks) - 1, -1, -1):
            candidate = all_blocks[idx].strip()
            if candidate and is_python_code(candidate):
                logger.debug(
                    "Validated code block #%d/%d as Python (%d chars)",
                    idx + 1,
                    len(all_blocks),
                    len(candidate),
                )
                return candidate
        logger.warning("None of the code blocks validated as Python")

    if is_python_code(text):
        logger.debug("Entire response appears to be Python; using directly")
        return text.strip()

    return None


def _llm_reextract_python(
    text: str,
    llm_client: "LLMClient",
    max_retries: int,
) -> Optional[str]:
    """Ask the LLM to re-emit only the Python portion of a messy response."""
    prompt = (
        "Please extract ONLY the Python code from the following text. "
        "The text may contain explanations and code examples in other languages "
        "(C, Java, etc.). Find the Python script and return it wrapped in "
        "```python ``` markdown blocks. No explanations, no comments outside the code.\n\n"
        f"Text to extract from:\n{text}"
    )
    messages = [{"role": "user", "content": prompt}]

    for attempt in range(max_retries + 1):
        try:
            logger.debug("LLM re-extraction attempt %d/%d", attempt + 1, max_retries + 1)
            start = time.time()
            response, success = llm_client.call(messages)
            logger.debug("LLM re-extraction finished in %.2fs", time.time() - start)

            if not success:
                logger.warning("LLM call failed on attempt %d", attempt + 1)
                continue

            python_blocks = re.findall(_PYTHON_BLOCK_PATTERN, response)
            if python_blocks:
                candidate = python_blocks[-1].strip()
                if candidate:
                    logger.debug("LLM re-extraction successful (%d chars)", len(candidate))
                    return candidate

            any_blocks = re.findall(_ANY_BLOCK_PATTERN, response)
            for block in reversed(any_blocks):
                candidate = block.strip()
                if candidate and is_python_code(candidate):
                    logger.debug("LLM provided valid Python (%d chars)", len(candidate))
                    return candidate

            if is_python_code(response):
                logger.debug("LLM response is Python; using directly")
                return response.strip()

            logger.warning(
                "LLM re-extraction attempt %d did not yield valid Python", attempt + 1
            )
        except Exception as exc:  # noqa: BLE001 — barrier for retryable failures
            logger.error("Error in LLM re-extraction attempt %d: %s", attempt + 1, exc)

    return None


def extract_python_code_from_response(
    text: str,
    llm_client: "LLMClient",
    max_retries: int = 2,
    timeout: int = 30,  # noqa: ARG001  reserved for future per-call timeout
) -> Optional[str]:
    """Extract standalone Python code from an LLM response.

    Tries four strategies in order:

    1. Explicit ``\u0060\u0060\u0060python`` fenced blocks.
    2. Any fenced block that validates as Python via :func:`is_python_code`.
    3. Entire response interpreted as Python when there are no fences.
    4. Ask the LLM to re-extract the Python with :func:`_llm_reextract_python`.

    Args:
        text: Raw LLM response.
        llm_client: LLM client used for the fallback re-extraction pass.
        max_retries: How many fallback attempts to make on LLM call failures.
        timeout: Kept for call-site compatibility; no effect yet.

    Returns:
        The extracted Python source, or ``None`` when extraction failed
        after the fallback.
    """
    logger.debug("Extracting Python code from response")

    direct = _extract_python_from_blocks(text)
    if direct is not None:
        return direct

    logger.debug("Direct extraction failed; invoking LLM fallback")
    return _llm_reextract_python(text, llm_client, max_retries)
