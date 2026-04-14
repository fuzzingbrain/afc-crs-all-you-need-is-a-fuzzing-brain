"""
Git and diff processing utilities (backward-compatibility shim).

The canonical homes are:
    * ``process_large_diff``                  -> ``common.diff.process``
    * ``get_commit_info``                     -> ``common.diff.commit``
    * ``parse_commit_diff``                   -> ``common.diff.commit``
    * ``extract_diff_functions_using_funtarget`` -> ``common.diff.funtarget``

This module keeps the legacy import paths (``from common.utils import
get_commit_info`` etc.) working. The shim functions accept an optional
``logger=`` kwarg for compatibility with old call sites and silently
ignore it; new code should import from the canonical modules.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from common.diff.commit import (
    get_commit_info as _canonical_get_commit_info,
    parse_commit_diff,  # noqa: F401  takes no logger, direct re-export
)
from common.diff.funtarget import (
    extract_diff_functions_using_funtarget as _canonical_extract_diff_functions_using_funtarget,
)
from common.diff.process import (
    process_large_diff as _canonical_process_large_diff,
)

if TYPE_CHECKING:
    from common.logging.logger import StrategyLogger


def process_large_diff(
    diff_content: str,
    logger: Optional["StrategyLogger"] = None,  # noqa: ARG001
    **_kwargs: Any,
) -> str:
    """Legacy-signature shim; ``logger`` is accepted and ignored."""
    return _canonical_process_large_diff(diff_content)


def get_commit_info(
    project_dir: str,
    language: str,
    logger: Optional["StrategyLogger"] = None,  # noqa: ARG001
    **_kwargs: Any,
) -> Tuple[str, str]:
    """Legacy-signature shim; ``logger`` is accepted and ignored."""
    return _canonical_get_commit_info(project_dir, language)


def extract_diff_functions_using_funtarget(
    project_src_dir: str,
    out_dir: str,
    logger: Optional["StrategyLogger"] = None,  # noqa: ARG001
    **_kwargs: Any,
) -> Optional[List[Dict[str, Any]]]:
    """Legacy-signature shim; ``logger`` is accepted and ignored."""
    return _canonical_extract_diff_functions_using_funtarget(project_src_dir, out_dir)
