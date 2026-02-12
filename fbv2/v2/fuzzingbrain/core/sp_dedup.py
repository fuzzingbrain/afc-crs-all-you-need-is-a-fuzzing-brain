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
                    "You are a vulnerability deduplication assistant. "
                    "Your task is to determine if a new SP describes the EXACT SAME "
                    "vulnerability as an existing SP. Be conservative: only mark as "
                    "duplicate if you are CERTAIN they are the same bug. "
                    "When uncertain, say NOT duplicate. "
                    "It's better to have extra SPs than to miss real vulnerabilities."
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
        raw_id = sp.get("suspicious_point_id") or sp.get("_id") or "unknown"
        sp_id = str(raw_id)
        desc = sp.get("description", "")
        sp_list.append(f"SP-{i} (ID: {sp_id}): {desc}")

    existing_text = "\n".join(sp_list)

    return f"""Determine if the NEW suspicious point describes the EXACT SAME vulnerability as any EXISTING suspicious point.

NEW SP:
"{new_description}"

EXISTING SPs:
{existing_text}

Two SPs are duplicates ONLY if they describe the EXACT SAME bug:
1. Same vulnerability type AND
2. Same code location (same variable, same statement, same operation) AND
3. Same root cause

NOT duplicates if:
- Different variables or buffers involved
- Different operations (e.g., different memcpy calls, different array accesses)
- Different control flow paths
- Similar but not identical issues

IMPORTANT: When uncertain, answer "no duplicate".
It's better to have extra SPs than to miss real vulnerabilities.

Respond with JSON only:
- If CERTAIN it's a duplicate: {{"duplicate": true, "duplicate_of": "SP-N"}}
- If uncertain or not duplicate: {{"duplicate": false, "duplicate_of": null}}"""


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
            response = "\n".join(line for line in lines if not line.startswith("```"))

        result = json.loads(response)

        if not result.get("duplicate"):
            return None

        duplicate_ref = result.get("duplicate_of")
        if not duplicate_ref:
            return None

        # Helper to get SP ID as string (handles ObjectId from MongoDB)
        def get_sp_id(sp_dict):
            sp_id = sp_dict.get("suspicious_point_id") or sp_dict.get("_id")
            return str(sp_id) if sp_id else None

        # Parse "SP-N" format or plain number
        if duplicate_ref.startswith("SP-"):
            try:
                idx = int(duplicate_ref[3:]) - 1  # 1-indexed to 0-indexed
                if 0 <= idx < len(existing_sps):
                    return get_sp_id(existing_sps[idx])
            except ValueError:
                pass
        elif duplicate_ref.isdigit():
            # Handle plain number (e.g., "1" instead of "SP-1")
            try:
                idx = int(duplicate_ref) - 1  # 1-indexed to 0-indexed
                if 0 <= idx < len(existing_sps):
                    return get_sp_id(existing_sps[idx])
            except ValueError:
                pass

        # Maybe it's a direct ID
        for sp in existing_sps:
            sp_id = get_sp_id(sp)
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
                    return get_sp_id(existing_sps[idx])

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
                    "You are a vulnerability deduplication assistant. "
                    "Your task is to determine if a new SP describes the EXACT SAME "
                    "vulnerability as an existing SP. Be conservative: only mark as "
                    "duplicate if you are CERTAIN they are the same bug. "
                    "When uncertain, say NOT duplicate. "
                    "It's better to have extra SPs than to miss real vulnerabilities."
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
