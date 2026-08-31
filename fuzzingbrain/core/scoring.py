# SPDX-License-Identifier: Apache-2.0
"""The thresholds this process judges by.

A worker is its own Celery process and never sees the Config object the main
process built, so the run's thresholds have to be handed to it explicitly and
put somewhere both the prompts and the strategies can read. That is what this
module is: one value per process, set once at startup, read everywhere.

Reading it through `get_scoring()` rather than importing the object means a
worker that sets it after the strategy modules are already imported still gets
the run's numbers rather than the defaults.
"""

from __future__ import annotations

from typing import Optional

from .config import ScoringConfig

_scoring: Optional[ScoringConfig] = None


def get_scoring() -> ScoringConfig:
    """This run's thresholds; the environment's, until a run sets them."""
    global _scoring
    if _scoring is None:
        _scoring = ScoringConfig.from_env()
    return _scoring


def set_scoring(scoring: Optional[ScoringConfig]) -> None:
    """Install the run's thresholds. Called once, early, per process."""
    global _scoring
    if scoring is not None:
        _scoring = scoring
