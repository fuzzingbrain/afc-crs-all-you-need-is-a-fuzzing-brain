# SPDX-License-Identifier: Apache-2.0
"""LLM-driven patch generation."""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from common.llm.response import extract_json_data_from_response

if TYPE_CHECKING:
    from common.llm.client import LLMClient

logger = logging.getLogger(__name__)


INITIAL_PATCH_TEMPLATE = """# Vulnerability Patching Task

## Your Role
You are a world-leading security engineer tasked with fixing a vulnerability in code. Your goal is to generate minimal, precise patches that address only the vulnerability without changing other functionality.
Do not apologize when you are wrong. Just keep optimizing the result directly and proceed the progress. Do not lie or guess when you are unsure about the answer.

## Input Information
### Vulnerability Report
{crash_log}

### Context Information
The vulnerability is introduced by the following commit:
{commit_diff}

### Relevant Functions
{functions_metadata_str}

Please return the fixed functions to patch the vulnerability.

## Requirements
1. Fix ONLY the vulnerability - do not add features or refactor code
2. Preserve all existing functionality and logic
3. Make minimal changes (fewest lines of code possible)
4. Focus on security best practices

## Output Format
Return ONLY a JSON dictionary where keys are function names and values are code blocks:
{{
"function_name1": "function_content_with_fix",
"function_name2": "function_content_with_fix",
...
}}

IMPORTANT:
- Return the fixed content for each changed function
- Do NOT return diffs, patches, or partial code snippets
- Do NOT include explanations or comments outside the JSON
- Include ALL lines of the original function in your response, with your fixes applied

Return ONLY the JSON dictionary described above.
"""


def _strip_json_code_fence(text: str) -> str:
    """Strip a leading ``\u0060\u0060\u0060json`` fence if present."""
    if "```json" not in text or "```" not in text:
        return text
    start = text.find("```json")
    if start == -1:
        return text
    start += len("```json")
    end = text.rfind("```")
    if end <= start:
        return text
    return text[start:end].strip()


def generate_patch(
    llm_client: "LLMClient",
    messages: List[Dict[str, Any]],
    model_name: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Ask the LLM for a patch and return a ``{function_name: new_code}`` dict.

    Recognises both the function-name / code-string and the
    ``{"file", "changes"}`` response shapes; file-changes payloads are
    turned into a textual patch block keyed by file name.

    Args:
        llm_client: LLM client used for the call.
        messages: Conversation history. The assistant response is
            appended on success so the caller can iterate.
        model_name: Optional explicit model.

    Returns:
        Patch dict (possibly empty), or ``None`` when the call / parse
        failed.
    """
    start = time.time()

    kwargs = {} if model_name is None else {"model_name": model_name}
    response, success = llm_client.call(messages, **kwargs)
    if not success or response is None:
        return None

    messages.append({"role": "assistant", "content": response})
    logger.info("Patch generation took %.2fs", time.time() - start)
    logger.debug("generate_patch response:\n%s", response)

    response_text = _strip_json_code_fence(response)
    extracted = extract_json_data_from_response(response_text, llm_client)
    if not extracted:
        logger.warning("Failed to extract code from patch response")
        return None

    patch_code_dict: Dict[str, Any] = {}
    for key, value in extracted:
        if isinstance(value, str):
            patch_code_dict[key] = value
            logger.debug("Extracted patch for function: %s", key)
        elif isinstance(value, dict) and "changes" in value:
            file_name = value.get("file", key)
            patch_code_dict[file_name] = _file_changes_to_patch_text(file_name, value.get("changes", []))
            logger.debug("Extracted patch for file: %s (%d changes)", file_name, len(value.get("changes", [])))

    return patch_code_dict


def _file_changes_to_patch_text(file_name: str, changes: List[Dict[str, Any]]) -> str:
    """Convert a ``{"changes": [...]}`` payload to a textual diff stub."""
    patch_text = f"--- a/{file_name}\n+++ b/{file_name}\n"
    for change in changes:
        line_num = change.get("line", 0)
        old_line = change.get("old", "")
        new_line = change.get("new", "")

        if old_line and not new_line:
            patch_text += f"@@ -{line_num},1 +{line_num},0 @@\n-{old_line}\n"
        elif not old_line and new_line:
            patch_text += f"@@ -{line_num},0 +{line_num},1 @@\n+{new_line}\n"
        else:
            patch_text += f"@@ -{line_num},1 +{line_num},1 @@\n-{old_line}\n+{new_line}\n"

    return patch_text
