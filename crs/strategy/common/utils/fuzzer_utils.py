"""
Fuzzer-related utility functions.

Backward-compatibility shim. The canonical home is ``common.fuzzing``:
    * ``is_likely_source_for_fuzzer`` -> ``common.fuzzing.discovery``
    * ``find_fuzzer_source`` -> ``common.fuzzing.discovery``
"""
from __future__ import annotations

from typing import Any, Optional, TYPE_CHECKING

from common.fuzzing.discovery import (
    find_fuzzer_source as _canonical_find_fuzzer_source,
    is_likely_source_for_fuzzer,  # noqa: F401  re-exported
)

if TYPE_CHECKING:
    from common.llm.client import LLMClient
    from common.logging.logger import StrategyLogger


def find_fuzzer_source(
    fuzzer_path: str,
    project_name: str,
    project_src_dir: str,
    focus: str,
    language: str = "c",
    test_nginx: bool = False,
    llm_client: Optional["LLMClient"] = None,
    logger: Optional["StrategyLogger"] = None,  # noqa: ARG001  kept for legacy callers
    **_kwargs: Any,
) -> str:
    """Legacy-signature wrapper around :func:`common.fuzzing.discovery.find_fuzzer_source`.

    Accepts (and ignores) the historical ``logger=`` keyword so existing
    call sites keep working; new code should call
    ``common.fuzzing.discovery.find_fuzzer_source`` directly, which uses
    a module-level stdlib logger.
    """
    return _canonical_find_fuzzer_source(
        fuzzer_path=fuzzer_path,
        project_name=project_name,
        project_src_dir=project_src_dir,
        focus=focus,
        language=language,
        test_nginx=test_nginx,
        llm_client=llm_client,
    )
