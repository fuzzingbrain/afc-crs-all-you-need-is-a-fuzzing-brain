# SPDX-License-Identifier: Apache-2.0
"""Code extraction utilities (backward-compatibility shim).

The canonical homes are:
    * extract_function_body          -> common.code.extract
    * extract_function_name_from_code -> common.code.extract
    * extract_code                    -> common.llm.response
    * is_python_code                  -> common.llm.response
    * extract_python_code_from_response -> common.llm.response

This module keeps the legacy import paths working while new code should
import from the canonical modules directly.
"""
from __future__ import annotations

from typing import Any, Optional, TYPE_CHECKING

from common.code.extract import (  # noqa: F401
    extract_function_body,
    extract_function_name_from_code,
)
from common.llm.response import (
    extract_code as _canonical_extract_code,
    extract_python_code_from_response as _canonical_extract_python_code_from_response,
    is_python_code,  # noqa: F401
)

if TYPE_CHECKING:
    from common.llm.client import LLMClient
    from common.logging.logger import StrategyLogger


def extract_code(text: str, logger: Optional["StrategyLogger"] = None, **_kwargs: Any) -> Optional[str]:
    """Legacy-signature shim; ``logger`` is accepted and ignored."""
    return _canonical_extract_code(text)


def extract_python_code_from_response(
    text: str,
    llm_client: "LLMClient",
    max_retries: int = 2,
    timeout: int = 30,
    logger: Optional["StrategyLogger"] = None,  # noqa: ARG001
    **_kwargs: Any,
) -> Optional[str]:
    """Legacy-signature shim; ``logger`` is accepted and ignored."""
    return _canonical_extract_python_code_from_response(
        text, llm_client, max_retries=max_retries, timeout=timeout
    )
