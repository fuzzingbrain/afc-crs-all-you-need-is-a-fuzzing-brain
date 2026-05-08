# SPDX-License-Identifier: Apache-2.0
"""Strategy registry.

Every strategy exposed to the outside world is registered here so the
CLI entry point at :mod:`strategies.__main__` and the Go runner can
look them up by name instead of globbing filenames.

Each entry is a (``StrategyName``, :class:`StrategySpec`) pair. A spec
carries the class object and a pair of flags that are automatically
stamped onto the :class:`~common.config.StrategyConfig` before the
strategy runs: ``full_scan`` (full-scan vs delta) and ``do_patch_only``
(patch phase vs POV phase). That keeps the delta / full / patch
variants sharing one class per family but surfaced as distinct names.

New strategies should be added to :data:`REGISTRY` here and their
imports listed so :func:`get_strategy_spec` can resolve them.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Type

from core.base_strategy import BaseStrategy

from .as0 import AS0DeltaStrategy, AS0FullStrategy
from .patch import PatchStrategy


@dataclass(frozen=True)
class StrategySpec:
    """Metadata for a registered strategy.

    Attributes:
        strategy_class: The concrete :class:`BaseStrategy` subclass.
        full_scan: Whether the strategy should run in full-scan mode
            (stamped onto ``StrategyConfig.full_scan``).
        do_patch_only: Whether the strategy is a patch strategy
            (stamped onto ``StrategyConfig.do_patch_only``). When True
            the strategy does not try to generate a POV.
    """

    strategy_class: Type[BaseStrategy]
    full_scan: bool = False
    do_patch_only: bool = False


REGISTRY: Dict[str, StrategySpec] = {
    "as0_delta": StrategySpec(AS0DeltaStrategy, full_scan=False),
    "as0_full": StrategySpec(AS0FullStrategy, full_scan=True),
    "patch_delta": StrategySpec(PatchStrategy, full_scan=False, do_patch_only=True),
    "patch_full": StrategySpec(PatchStrategy, full_scan=True, do_patch_only=True),
}


def get_strategy_spec(name: str) -> StrategySpec:
    """Return the spec registered under ``name``.

    Raises:
        KeyError: When no strategy is registered under ``name``.
    """
    if name not in REGISTRY:
        known = ", ".join(sorted(REGISTRY))
        raise KeyError(f"Unknown strategy '{name}'. Known: {known}")
    return REGISTRY[name]


def list_strategies() -> list:
    """Return the list of registered strategy names (sorted)."""
    return sorted(REGISTRY)


__all__ = [
    "REGISTRY",
    "StrategySpec",
    "get_strategy_spec",
    "list_strategies",
]
