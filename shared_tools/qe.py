"""Shared export of QE utilities from multi_agent.

This module re-exports the QE run/build/test/apply/revert helpers and state types
so other systems can use the same implementation without duplication.
"""

from __future__ import annotations

# Re-export state types
from multi_agent.state import (  # noqa: F401
    PatcherAgentState,
    PatchAttempt,
    PatchStatus,
    PatchOutput,
    PatchInput,
)

# Re-export QE functions
from multi_agent.agents.qe import (  # noqa: F401
    run as run_qe,
    run_build,
    run_pov,
    run_tests,
)

# Also surface apply/revert helpers
from multi_agent.agents.qe import (  # noqa: F401
    _apply_diff as apply_diff,
    _revert_diff as revert_diff,
    _apply_diff_in_source as apply_diff_in_source,
    _revert_diff_in_source as revert_diff_in_source,
)


