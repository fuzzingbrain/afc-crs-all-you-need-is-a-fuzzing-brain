"""
SP Deduplication Module

Uses LLM to compare suspicious point descriptions and identify duplicates.
When multiple harnesses discover the same vulnerability, we merge them
into a single SP with multiple sources instead of creating duplicates.
"""

import json
from typing import List, Optional, Dict, Any
from loguru import logger

# Maximum number of existing SPs to compare against in a single LLM call
SP_DEDUP_MAX_COMPARE = 20


def check_sp_duplicate(
    new_description: str,
    existing_sps: List[Dict[str, Any]],
    model: str = None,
) -> Optional[str]:
    """
    Check if a new SP description duplicates any existing SP in the same function.

    Uses LLM to semantically compare descriptions. This is more robust than
    exact string matching since different harnesses may describe the same
    vulnerability slightly differently.

    Args:
        new_description: Description of the new suspicious point
        existing_sps: List of existing SPs in the same function, each with:
            - suspicious_point_id: SP ID
            - description: SP description
            - vuln_type: Vulnerability type (optional, not used for matching)
        model: Optional model override

    Returns:
        ID of the duplicate SP if found, None otherwise
    """
    if not existing_sps:
        return None

    # Limit the number of SPs to compare (for cost/latency)
    compare_sps = existing_sps[:SP_DEDUP_MAX_COMPARE]

    if len(existing_sps) > SP_DEDUP_MAX_COMPARE:
        logger.warning(
            f"Too many existing SPs ({len(existing_sps)}), "
            f"only comparing against first {SP_DEDUP_MAX_COMPARE}"
        )

    try:
        from ..llms import LLMClient

        client = LLMClient()

        # Build the comparison prompt
        prompt = _build_sp_dedup_prompt(new_description, compare_sps)

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a vulnerability analysis assistant. "
                    "Your task is to determine if a new suspicious point (SP) "
                    "describes the same vulnerability as any existing SP. "
                    "Focus on the semantic meaning, not exact wording. "
                    "Two SPs are duplicates if they describe the same bug at "
                    "the same location with the same root cause."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        # Use a smaller/faster model for dedup checks to save cost
        response = client.call(
            messages,
            model=model or "gpt-4o-mini",  # Fast and cheap for simple comparison
            temperature=0.0,  # Deterministic
            max_tokens=200,
        )

        # Parse the response
        return _parse_sp_dedup_response(response.content, compare_sps)

    except Exception as e:
        logger.error(f"LLM SP dedup check failed: {e}")
        # On error, assume not a duplicate (safer to create new SP)
        return None


def _build_sp_dedup_prompt(
    new_description: str,
    existing_sps: List[Dict[str, Any]],
) -> str:
    """Build the prompt for SP dedup comparison."""
    sp_list = []
    for i, sp in enumerate(existing_sps, 1):
        sp_id = sp.get("suspicious_point_id", sp.get("_id", "unknown"))
        desc = sp.get("description", "")
        sp_list.append(f"SP-{i} (ID: {sp_id}): {desc}")

    existing_text = "\n".join(sp_list)

    return f"""Determine if the NEW suspicious point describes the same vulnerability as any EXISTING suspicious point.

NEW SP:
"{new_description}"

EXISTING SPs:
{existing_text}

Two SPs are duplicates if they:
1. Describe the same type of vulnerability (e.g., buffer overflow, use-after-free)
2. Point to the same code location or control flow
3. Have the same root cause

Respond with JSON only:
- If duplicate found: {{"duplicate": true, "duplicate_of": "SP-N"}} where N is the number of the matching SP
- If no duplicate: {{"duplicate": false, "duplicate_of": null}}"""


def _parse_sp_dedup_response(
    response: str,
    existing_sps: List[Dict[str, Any]],
) -> Optional[str]:
    """Parse LLM response to extract duplicate SP ID."""
    try:
        # Clean up response (remove markdown code blocks if present)
        response = response.strip()
        if response.startswith("```"):
            # Remove code block markers
            lines = response.split("\n")
            response = "\n".join(
                line for line in lines
                if not line.startswith("```")
            )

        result = json.loads(response)

        if not result.get("duplicate"):
            return None

        duplicate_ref = result.get("duplicate_of")
        if not duplicate_ref:
            return None

        # Parse "SP-N" format
        if duplicate_ref.startswith("SP-"):
            try:
                idx = int(duplicate_ref[3:]) - 1  # 1-indexed to 0-indexed
                if 0 <= idx < len(existing_sps):
                    sp = existing_sps[idx]
                    return sp.get("suspicious_point_id", sp.get("_id"))
            except ValueError:
                pass

        # Maybe it's a direct ID
        for sp in existing_sps:
            sp_id = sp.get("suspicious_point_id", sp.get("_id"))
            if sp_id == duplicate_ref:
                return sp_id

        logger.warning(f"Could not resolve SP duplicate reference: {duplicate_ref}")
        return None

    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse SP dedup response as JSON: {e}")
        logger.debug(f"Response was: {response}")

        # Try simple text parsing as fallback
        response_lower = response.lower()
        if "no duplicate" in response_lower or "not a duplicate" in response_lower:
            return None
        if "duplicate" in response_lower:
            # Try to extract SP-N reference
            import re
            match = re.search(r"SP-(\d+)", response, re.IGNORECASE)
            if match:
                idx = int(match.group(1)) - 1
                if 0 <= idx < len(existing_sps):
                    sp = existing_sps[idx]
                    return sp.get("suspicious_point_id", sp.get("_id"))

        return None


async def check_sp_duplicate_async(
    new_description: str,
    existing_sps: List[Dict[str, Any]],
    model: str = None,
) -> Optional[str]:
    """
    Async version of check_sp_duplicate.

    Args:
        new_description: Description of the new suspicious point
        existing_sps: List of existing SPs in the same function
        model: Optional model override

    Returns:
        ID of the duplicate SP if found, None otherwise
    """
    if not existing_sps:
        return None

    compare_sps = existing_sps[:SP_DEDUP_MAX_COMPARE]

    if len(existing_sps) > SP_DEDUP_MAX_COMPARE:
        logger.warning(
            f"Too many existing SPs ({len(existing_sps)}), "
            f"only comparing against first {SP_DEDUP_MAX_COMPARE}"
        )

    try:
        from ..llms import LLMClient

        client = LLMClient()

        prompt = _build_sp_dedup_prompt(new_description, compare_sps)

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a vulnerability analysis assistant. "
                    "Your task is to determine if a new suspicious point (SP) "
                    "describes the same vulnerability as any existing SP. "
                    "Focus on the semantic meaning, not exact wording. "
                    "Two SPs are duplicates if they describe the same bug at "
                    "the same location with the same root cause."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        response = await client.acall(
            messages,
            model=model or "gpt-4o-mini",
            temperature=0.0,
            max_tokens=200,
        )

        return _parse_sp_dedup_response(response.content, compare_sps)

    except Exception as e:
        logger.error(f"Async LLM SP dedup check failed: {e}")
        return None
