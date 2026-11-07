# SPDX-License-Identifier: Apache-2.0
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
        filename: Name of the markdown file (e.g., "lg_planning_prompt.md")

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
LG_PLANNING_PROMPT = _load_prompt_from_markdown("lg_planning_prompt.md")
FULLSCAN_VH_FIND_PROMPT = _load_prompt_from_markdown("fullscan_vh_find_prompt.md")
FUNCTION_ANALYSIS_PROMPT = _load_prompt_from_markdown("function_analysis_prompt.md")
POC_AGENT_SYSTEM_PROMPT = _load_prompt_from_markdown("poc_agent_prompt.md")
REPORT_SYSTEM_PROMPT = _load_prompt_from_markdown("poc_report_prompt.md")
REPORT_USER_TEMPLATE = _load_prompt_from_markdown("poc_report_user_template.md")
FIND_VULNERABILITY_HYPOTHESES_PROMPT = _load_prompt_from_markdown(
    "find_vulnerability_hypotheses_prompt.md"
)
VERIFY_VULNERABILITY_HYPOTHESES_PROMPT = _load_prompt_from_markdown(
    "verify_vulnerability_hypotheses_prompt.md"
)
VERIFY_VULNERABILITY_HYPOTHESES_DELTA_PROMPT = _load_prompt_from_markdown(
    "verify_vulnerability_hypotheses_delta_prompt.md"
)
# Seed agent: one static system prompt per mode (dynamic data stays in the
# per-mode user message built by SeedAgent.get_initial_message).
SEED_LOGIC_GROUP_SYSTEM_PROMPT = _load_prompt_from_markdown("seed_logic_group_system.md")
SEED_FP_SYSTEM_PROMPT = _load_prompt_from_markdown("seed_fp_system.md")
SEED_DELTA_SYSTEM_PROMPT = _load_prompt_from_markdown("seed_delta_system.md")

# Sanitizer guidance templates
from .sanitizer_guidance import (
    ADDRESS_SANITIZER_GUIDANCE,
    MEMORY_SANITIZER_GUIDANCE,
    UNDEFINED_SANITIZER_GUIDANCE,
    GENERAL_SANITIZER_GUIDANCE,
)

