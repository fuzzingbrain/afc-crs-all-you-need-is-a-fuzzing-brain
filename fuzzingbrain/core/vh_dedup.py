# SPDX-License-Identifier: Apache-2.0
"""
VH Deduplication Module

Uses LLM to compare vulnerability hypothesis descriptions and identify duplicates.
When multiple harnesses discover the same vulnerability, we merge them
into a single VH with multiple sources instead of creating duplicates.
"""

import json
from typing import List, Optional, Dict, Any
from loguru import logger

# Maximum number of existing VHs to compare against in a single LLM call
VH_DEDUP_MAX_COMPARE = 20


def _dedup_model() -> Optional[str]:
    """The run's utility model: a fast yes/no judgement."""
    from ..llms.routing import Role, model_for

    return model_for(Role.UTILITY).id


def check_vh_duplicate(
    new_description: str,
    existing_vhs: List[Dict[str, Any]],
    model: str = None,
    run_id: str = "",
    worker_id: str = "",
    agent_id: str = "",
) -> Optional[str]:
    """
    Check if a new VH description duplicates any existing VH in the same function.

    Uses LLM to semantically compare descriptions. This is more robust than
    exact string matching since different harnesses may describe the same
    vulnerability slightly differently.

    Args:
        new_description: Description of the new vulnerability hypothesis
        existing_vhs: List of existing VHs in the same function, each with:
            - vulnerability_hypothesis_id: VH ID
            - description: VH description
            - vuln_type: Vulnerability type (optional, not used for matching)
        model: Optional model override

    Returns:
        ID of the duplicate VH if found, None otherwise
    """
    if not existing_vhs:
        return None

    # Limit the number of VHs to compare (for cost/latency)
    compare_vhs = existing_vhs[:VH_DEDUP_MAX_COMPARE]

    if len(existing_vhs) > VH_DEDUP_MAX_COMPARE:
        logger.warning(
            f"Too many existing VHs ({len(existing_vhs)}), "
            f"only comparing against first {VH_DEDUP_MAX_COMPARE}"
        )

    try:
        from ..llms import LLMClient

        client = LLMClient(run_id=run_id or "", worker_id=worker_id or "", agent_id=agent_id or "", role="utility")

        # Build the comparison prompt
        prompt = _build_vh_dedup_prompt(new_description, compare_vhs)

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a vulnerability deduplication assistant. "
                    "Your task is to determine if a new VH describes the EXACT SAME "
                    "vulnerability as an existing VH. Be conservative: only mark as "
                    "duplicate if you are CERTAIN they are the same bug. "
                    "When uncertain, say NOT duplicate. "
                    "It's better to have extra VHs than to miss real vulnerabilities."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        # A small model is the right shape for "are these the same point?", but
        # naming one provider's here overrode the config's model choice for the
        # whole run: every dedup call went to gpt-4o-mini, failed, and fell back
        # to Opus after a wasted round trip. Ask the config instead.
        response = client.call(
            messages,
            model=model or _dedup_model(),
            temperature=0.0,  # Deterministic
            max_tokens=200,
        )

        # Parse the response
        return _parse_vh_dedup_response(response.content, compare_vhs)

    except Exception as e:
        logger.error(f"LLM VH dedup check failed: {e}")
        # On error, assume not a duplicate (safer to create new VH)
        return None


def _build_vh_dedup_prompt(
    new_description: str,
    existing_vhs: List[Dict[str, Any]],
) -> str:
    """Build the prompt for VH dedup comparison."""
    vh_list = []
    for i, vh in enumerate(existing_vhs, 1):
        raw_id = vh.get("vulnerability_hypothesis_id") or vh.get("_id") or "unknown"
        vh_id = str(raw_id)
        desc = vh.get("description", "")
        vh_list.append(f"VH-{i} (ID: {vh_id}): {desc}")

    existing_text = "\n".join(vh_list)

    return f"""Determine if the NEW vulnerability hypothesis describes the EXACT SAME vulnerability as any EXISTING vulnerability hypothesis.

NEW VH:
"{new_description}"

EXISTING VHs:
{existing_text}

Two VHs are duplicates ONLY if they describe the EXACT SAME bug:
1. Same vulnerability type AND
2. Same code location (same variable, same statement, same operation) AND
3. Same root cause

NOT duplicates if:
- Different variables or buffers involved
- Different operations (e.g., different memcpy calls, different array accesses)
- Different control flow paths
- Similar but not identical issues

IMPORTANT: When uncertain, answer "no duplicate".
It's better to have extra VHs than to miss real vulnerabilities.

Respond with JSON only:
- If CERTAIN it's a duplicate: {{"duplicate": true, "duplicate_of": "VH-N"}}
- If uncertain or not duplicate: {{"duplicate": false, "duplicate_of": null}}"""


def _vh_id_of(vh_dict: Dict[str, Any]) -> Optional[str]:
    """Get a VH's ID as a string (handles ObjectId from MongoDB)."""
    vh_id = vh_dict.get("vulnerability_hypothesis_id") or vh_dict.get("_id")
    return str(vh_id) if vh_id else None


def _parse_vh_dedup_response(
    response: str,
    existing_vhs: List[Dict[str, Any]],
) -> Optional[str]:
    """Parse LLM response to extract duplicate VH ID."""
    try:
        # Clean up response (remove markdown code blocks if present)
        response = response.strip()
        if response.startswith("```"):
            # Remove code block markers
            lines = response.split("\n")
            response = "\n".join(line for line in lines if not line.startswith("```"))

        result = json.loads(response)

        # Valid JSON that isn't an object (e.g. bare "42", "true", a string, a
        # list) has no "duplicate" field — .get would raise AttributeError,
        # which is NOT a JSONDecodeError and would escape this handler.
        if not isinstance(result, dict):
            return None

        if not result.get("duplicate"):
            return None

        duplicate_ref = result.get("duplicate_of")
        if not duplicate_ref:
            return None

        # Parse "VH-N" format or plain number
        if duplicate_ref.startswith("VH-"):
            try:
                idx = int(duplicate_ref[3:]) - 1  # 1-indexed to 0-indexed
                if 0 <= idx < len(existing_vhs):
                    return _vh_id_of(existing_vhs[idx])
            except ValueError:
                pass
        elif duplicate_ref.isdigit():
            # Handle plain number (e.g., "1" instead of "VH-1")
            try:
                idx = int(duplicate_ref) - 1  # 1-indexed to 0-indexed
                if 0 <= idx < len(existing_vhs):
                    return _vh_id_of(existing_vhs[idx])
            except ValueError:
                pass

        # Maybe it's a direct ID
        for vh in existing_vhs:
            vh_id = _vh_id_of(vh)
            if vh_id == duplicate_ref:
                return vh_id

        logger.warning(f"Could not resolve VH duplicate reference: {duplicate_ref}")
        return None

    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse VH dedup response as JSON: {e}")
        logger.debug(f"Response was: {response}")

        # Try simple text parsing as fallback
        response_lower = response.lower()
        if "no duplicate" in response_lower or "not a duplicate" in response_lower:
            return None
        if "duplicate" in response_lower:
            # Try to extract VH-N reference
            import re

            match = re.search(r"VH-(\d+)", response, re.IGNORECASE)
            if match:
                idx = int(match.group(1)) - 1
                if 0 <= idx < len(existing_vhs):
                    return _vh_id_of(existing_vhs[idx])

        return None


async def check_vh_duplicate_async(
    new_description: str,
    existing_vhs: List[Dict[str, Any]],
    model: str = None,
    run_id: str = "",
    worker_id: str = "",
    agent_id: str = "",
) -> Optional[str]:
    """
    Async version of check_vh_duplicate.

    Args:
        new_description: Description of the new vulnerability hypothesis
        existing_vhs: List of existing VHs in the same function
        model: Optional model override

    Returns:
        ID of the duplicate VH if found, None otherwise
    """
    if not existing_vhs:
        return None

    compare_vhs = existing_vhs[:VH_DEDUP_MAX_COMPARE]

    if len(existing_vhs) > VH_DEDUP_MAX_COMPARE:
        logger.warning(
            f"Too many existing VHs ({len(existing_vhs)}), "
            f"only comparing against first {VH_DEDUP_MAX_COMPARE}"
        )

    try:
        from ..llms import LLMClient

        client = LLMClient(run_id=run_id or "", worker_id=worker_id or "", agent_id=agent_id or "", role="utility")

        prompt = _build_vh_dedup_prompt(new_description, compare_vhs)

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a vulnerability deduplication assistant. "
                    "Your task is to determine if a new VH describes the EXACT SAME "
                    "vulnerability as an existing VH. Be conservative: only mark as "
                    "duplicate if you are CERTAIN they are the same bug. "
                    "When uncertain, say NOT duplicate. "
                    "It's better to have extra VHs than to miss real vulnerabilities."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        response = await client.acall(
            messages,
            model=model or _dedup_model(),
            temperature=0.0,
            max_tokens=200,
        )

        return _parse_vh_dedup_response(response.content, compare_vhs)

    except Exception as e:
        logger.error(f"Async LLM VH dedup check failed: {e}")
        return None
