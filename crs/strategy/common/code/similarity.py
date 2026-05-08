# SPDX-License-Identifier: Apache-2.0
"""Structural similarity metrics for source snippets.

Used when an LLM proposes a patched function and we need to sanity-check
that the proposed replacement still looks like the original (same rough
signature, same parameter count, similar opening lines) before writing
it over the source tree.
"""
from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher
from typing import Dict, List

logger = logging.getLogger(__name__)

_PARAM_SPLIT_RE = re.compile(r",\s*(?![^<>()]*[>)])")
_CONTENT_PREVIEW_LINES = 10


def _extract_params(signature: str) -> List[str]:
    """Return the comma-split parameter list from a function signature line."""
    params_match = re.search(r"\((.*?)\)", signature)
    if not params_match:
        return []
    return [p.strip() for p in _PARAM_SPLIT_RE.split(params_match.group(1))]


def calculate_function_similarity(patch_code: str, original_code: str) -> Dict[str, float]:
    """Return a small similarity report comparing two function bodies.

    The returned dict carries four keys:

    - ``signature_similarity``: raw ratio of the first lines.
    - ``param_count_similarity``: ``1.0`` when parameter counts match,
      ``0.5`` otherwise.
    - ``content_similarity``: ratio over the first few lines of each
      body (cheap proxy for whole-body similarity).
    - ``weighted_similarity``: weighted average (0.6 signature, 0.3
      param count, 0.1 content). Callers can compare this single number
      against a threshold.
    """
    patch_lines = patch_code.strip().split("\n")
    original_lines = original_code.strip().split("\n")

    patch_signature = patch_lines[0] if patch_lines else ""
    original_signature = original_lines[0] if original_lines else ""

    signature_similarity = SequenceMatcher(None, patch_signature, original_signature).ratio()

    patch_params = _extract_params(patch_signature)
    original_params = _extract_params(original_signature)
    param_count_similarity = 1.0 if len(patch_params) == len(original_params) else 0.5

    preview_lines = min(_CONTENT_PREVIEW_LINES, min(len(patch_lines), len(original_lines)))
    content_similarity = SequenceMatcher(
        None,
        "\n".join(patch_lines[:preview_lines]),
        "\n".join(original_lines[:preview_lines]),
    ).ratio()

    weighted = (
        signature_similarity * 0.6
        + param_count_similarity * 0.3
        + content_similarity * 0.1
    )

    return {
        "signature_similarity": signature_similarity,
        "param_count_similarity": param_count_similarity,
        "content_similarity": content_similarity,
        "weighted_similarity": weighted,
    }
