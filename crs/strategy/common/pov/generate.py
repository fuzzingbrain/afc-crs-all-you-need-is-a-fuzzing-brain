# SPDX-License-Identifier: Apache-2.0
"""LLM-driven POV generator.

Wraps a single "ask the LLM for Python code that crashes the fuzzer"
round-trip with retry, refusal detection, timeout-crash sentinel
handling, and Python code extraction from markdown responses.

This is the fuzzing-strategy equivalent of
``common.llm.response.extract_python_code_from_response``; the
extraction itself delegates to that helper, and this module adds the
fuzzing-specific pre/post processing (refusal list, infinite-loop
detection, per-project sentinel write).
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from common.llm.response import extract_python_code_from_response

if TYPE_CHECKING:
    from common.llm.client import LLMClient

logger = logging.getLogger(__name__)

# Phrases that indicate the LLM refused to generate exploit code and
# should trigger a retry rather than being appended to the history.
_REFUSAL_PHRASES = (
    "cannot comply",
    "can't comply",
    "against my",
    "ethical guidelines",
)

# Sentinel file written into the project directory when the LLM says
# the crash is reached via an infinite loop, so sibling workers can
# classify libFuzzer timeouts as real crashes.
_DETECT_TIMEOUT_CRASH_SENTINEL = "detect_timeout_crash"


def _maybe_mark_timeout_crash(project_dir: str, response: str) -> None:
    """Set the timeout-as-crash sentinel when the LLM describes an infinite loop."""
    if "infinite loop" not in response:
        return

    logger.info("Infinite loop detected in POV response; setting DETECT_TIMEOUT_CRASH")
    try:
        Path(project_dir, _DETECT_TIMEOUT_CRASH_SENTINEL).touch(exist_ok=True)
    except OSError as exc:
        logger.error("Unable to create sentinel detect_timeout_crash file: %s", exc)

    os.environ["DETECT_TIMEOUT_CRASH"] = "1"


def _is_refusal(response: str) -> bool:
    """Return True if ``response`` looks like a refusal to generate exploit code."""
    lower = response.lower()
    for phrase in _REFUSAL_PHRASES:
        if phrase in lower:
            logger.info(
                "Model refused to generate POV with message: %r...",
                response[:100],
            )
            return True
    return False


def generate_pov(
    llm_client: "LLMClient",
    project_dir: str,
    messages: List[Dict[str, Any]],
    model_name: Optional[str] = None,
) -> Optional[str]:
    """Ask the LLM for POV generator code and return the extracted Python.

    Args:
        llm_client: LLM client used for the generation round-trip.
        project_dir: Project working directory (used for the timeout
            sentinel when the LLM hints at infinite-loop crashes).
        messages: Existing conversation (the assistant response is
            appended on success so follow-up calls can iterate).
        model_name: Optional explicit model name override.

    Returns:
        The extracted Python source ready to feed into a runner, or
        ``None`` on failure, refusal, or missing code block.
    """
    start = time.time()

    kwargs = {} if model_name is None else {"model_name": model_name}
    response, success = llm_client.call(messages, **kwargs)

    if (not success) or (response is None) or (not response.strip()):
        logger.warning("Failed to get valid response from %s", model_name)
        return None

    logger.debug("generate_pov response:\n%s", response)

    _maybe_mark_timeout_crash(project_dir, response)

    if _is_refusal(response):
        return None

    messages.append({"role": "assistant", "content": response})

    elapsed = time.time() - start
    logger.info("POV generation by %s took %.2fs", model_name, elapsed)

    code = extract_python_code_from_response(response, llm_client)
    if code is None:
        logger.warning("No Python code found in the response")
    return code
