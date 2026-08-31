# SPDX-License-Identifier: Apache-2.0
"""How many of everything this process may run at once.

A worker is its own Celery process and never sees the Config object the main
process built, so the run's concurrency has to be handed to it and put
somewhere the strategies can read. That is what this module is: one value per
process, set once at startup, read everywhere.

Reading it through `get_concurrency()` rather than importing the object means a
worker that installs the run's settings after the strategy modules are already
imported still gets the run's numbers rather than the defaults.
"""

from __future__ import annotations

from typing import Optional

from .config import ConcurrencyConfig

_concurrency: Optional[ConcurrencyConfig] = None


def get_concurrency() -> ConcurrencyConfig:
    """This run's concurrency; the environment's, until a run sets it."""
    global _concurrency
    if _concurrency is None:
        _concurrency = ConcurrencyConfig.from_env()
    return _concurrency


def set_concurrency(concurrency: Optional[ConcurrencyConfig]) -> None:
    """Install the run's concurrency. Called once, early, per process."""
    global _concurrency
    if concurrency is not None:
        _concurrency = concurrency
