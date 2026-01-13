"""
Prompts module for agent system prompts.

This module loads prompts from markdown files in the prompts directory.
"""

from pathlib import Path
from loguru import logger

# Get the directory where this __init__.py file is located
_PROMPTS_DIR = Path(__file__).parent


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
        return prompt_file.read_text(encoding="utf-8")
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
FIND_SUSPICIOUS_POINTS_PROMPT = _load_prompt_from_markdown("find_suspicious_points_prompt.md")
VERIFY_SUSPICIOUS_POINTS_PROMPT = _load_prompt_from_markdown("verify_suspicious_points_prompt.md")

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