# SPDX-License-Identifier: Apache-2.0
"""
Prompts module for agent system prompts.

This module loads prompts from markdown files in the prompts directory.
"""

from pathlib import Path
from loguru import logger

# Get the directory where this __init__.py file is located
_PROMPTS_DIR = Path(__file__).parent

# Thresholds the prompts state are written as <<name>> and filled from the
# configuration, so the number the model is asked to aim at and the number the
# code measures against come from one place. The angle-bracket form is used
# rather than str.format because the prompts contain JSON examples, and a lone
# brace in one of those would break formatting for the whole file.
_PLACEHOLDER_OPEN = "<<"
_PLACEHOLDER_CLOSE = ">>"


def _fill_thresholds(text: str, scoring=None) -> str:
    """Replace <<name>> with the configured value of `name`."""
    if _PLACEHOLDER_OPEN not in text:
        return text
    if scoring is None:
        from ...core.config import ScoringConfig

        scoring = ScoringConfig()
    for name, value in scoring.to_dict().items():
        text = text.replace(
            f"{_PLACEHOLDER_OPEN}{name}{_PLACEHOLDER_CLOSE}", _pretty(value)
        )
    return text


def _pretty(value: float) -> str:
    """0.7 rather than 0.7000000000000001, and 1.0 rather than 1.

    These land next to other scores in a range like "0.3-1.0"; an integer in
    that position reads as a different kind of number than its neighbours.
    """
    text = f"{value:g}"
    return text if "." in text else f"{text}.0"


def render_prompt(text: str, scoring=None) -> str:
    """A prompt with this run's thresholds in it.

    Call this when a run's configuration may differ from the defaults; the
    module-level constants below are already filled with the defaults, which is
    what every caller that does not configure scoring wants.
    """
    return _fill_thresholds(text, scoring)


def _load_prompt_from_markdown(filename: str) -> str:
    """
    Load a prompt from a markdown file.

    Args:
        filename: Name of the markdown file (e.g., "direction_planning_prompt.md")

    Returns:
        The prompt content as a string

    Raises:
        FileNotFoundError: If the prompt file doesn't exist
        IOError: If there's an error reading the file
    """
    prompt_file = _PROMPTS_DIR / filename
    try:
        return _fill_thresholds(prompt_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.error(f"Prompt file not found: {prompt_file}")
        raise
    except Exception as e:
        logger.error(f"Failed to load prompt file {prompt_file}: {e}")
        raise


# Load prompts from markdown files
DIRECTION_PLANNING_PROMPT = _load_prompt_from_markdown("direction_planning_prompt.md")
FULLSCAN_SP_FIND_PROMPT = _load_prompt_from_markdown("fullscan_sp_find_prompt.md")
FUNCTION_ANALYSIS_PROMPT = _load_prompt_from_markdown("function_analysis_prompt.md")
POV_AGENT_SYSTEM_PROMPT = _load_prompt_from_markdown("pov_agent_prompt.md")
REPORT_SYSTEM_PROMPT = _load_prompt_from_markdown("pov_report_prompt.md")
REPORT_USER_TEMPLATE = _load_prompt_from_markdown("pov_report_user_template.md")
FIND_SUSPICIOUS_POINTS_PROMPT = _load_prompt_from_markdown(
    "find_suspicious_points_prompt.md"
)
VERIFY_SUSPICIOUS_POINTS_PROMPT = _load_prompt_from_markdown(
    "verify_suspicious_points_prompt.md"
)
VERIFY_SUSPICIOUS_POINTS_DELTA_PROMPT = _load_prompt_from_markdown(
    "verify_suspicious_points_delta_prompt.md"
)

# Sanitizer guidance templates
from .sanitizer_guidance import (
    ADDRESS_SANITIZER_GUIDANCE,
    MEMORY_SANITIZER_GUIDANCE,
    UNDEFINED_SANITIZER_GUIDANCE,
    GENERAL_SANITIZER_GUIDANCE,
)

# Sanitizer patterns for function analysis (structured data, kept in Python)
SANITIZER_PATTERNS = {
    "address": """- Buffer overflow: memcpy, strcpy with unchecked length
- Out-of-bounds access: array indexing without validation
- Use-after-free: accessing freed memory
- Double-free: calling free() twice on same pointer
- Heap corruption: write beyond allocation size""",
    "memory": """- Uninitialized memory read: using variables before initialization
- Uninitialized struct fields: accessing unset struct members
- Information leak: copying uninitialized data""",
    "undefined": """- Integer overflow: signed arithmetic overflow
- Null pointer dereference: accessing through NULL
- Division by zero: unchecked divisor
- Shift errors: shifting by invalid amount""",
}
