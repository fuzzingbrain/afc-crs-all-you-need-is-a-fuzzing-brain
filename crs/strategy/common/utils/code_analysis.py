"""Code analysis utilities (backward-compatibility shim).

The canonical home is :mod:`common.analysis_client.client`. This module
re-exports the public helpers so existing
``from common.utils.code_analysis import ...`` imports keep working;
new code should import from the canonical module directly.
"""
from common.analysis_client.client import (  # noqa: F401
    extract_call_paths_from_analysis_service,
    get_reachable_functions_qx,
    load_qx_analysis_results,
    run_static_analysis_local,
)
