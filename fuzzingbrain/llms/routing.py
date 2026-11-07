# SPDX-License-Identifier: Apache-2.0
"""Which model each agent role uses -- one place, decided by the task.

The task names either ``force_model`` (one model for every role) or ``models``
(a model for each of finder, verifier, poc, seed, utility); not both, and no
role without a model. There are no profiles, no defaults and no environment
overrides: what ran is what the task says.

The logic group planner has no role of its own in the task: it reasons like
the verifier and uses the verifier's model (its calls are still recorded as
role ``lg_planner``).

``allow_fallback``:
    false  a failing call is retried on the same model only, then raises
    true   after the retries the call moves on to the run's other models

Parsed once at the worker boundary into an immutable ``ModelRouter``; call
sites ask ``model_for(Role.X)``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Mapping, Optional

import logging

from .models import ModelInfo, get_model_info

logger = logging.getLogger(__name__)


class Role(str, Enum):
    """Every distinct LLM job in the pipeline. Agents declare a role, not a model."""

    LG_PLANNER = "lg_planner"  # logic group planning (uses the verifier's model)
    FINDER = "finder"          # VH discovery
    VERIFIER = "verifier"      # VH verification
    POC = "poc"                # PoC synthesis
    SEED = "seed"              # seed generation
    UTILITY = "utility"        # PoC report, dedup, summaries


# The roles a task names a model for.
TASK_ROLES = ("finder", "verifier", "poc", "seed", "utility")
# Roles that borrow another role's model.
_BORROWS = {Role.LG_PLANNER: Role.VERIFIER}


@dataclass(frozen=True)
class RoutingConfig:
    """The routing inputs, validated."""

    models: Mapping[str, str] = field(default_factory=dict)  # role -> model id
    force_model: Optional[str] = None
    allow_fallback: bool = False

    @classmethod
    def from_task(cls, task: Optional[Mapping] = None) -> "RoutingConfig":
        task = task or {}
        cfg = cls(
            models=dict(task.get("models") or {}),
            force_model=task.get("force_model") or None,
            allow_fallback=bool(task.get("allow_fallback", False)),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.force_model and self.models:
            raise ValueError("routing: give force_model or models, not both")
        if self.force_model:
            get_model_info(self.force_model)
            return
        if not self.models:
            raise ValueError(
                f"routing: no model given: set force_model, or models for every role {list(TASK_ROLES)}"
            )
        unknown = sorted(set(self.models) - set(TASK_ROLES))
        if unknown:
            raise ValueError(f"routing: unknown roles {unknown}; known={list(TASK_ROLES)}")
        missing = [r for r in TASK_ROLES if not self.models.get(r)]
        if missing:
            raise ValueError(f"routing: models is missing roles {missing}; every role needs a model")
        for role, mid in self.models.items():
            get_model_info(mid)

    def resolve(self) -> Dict[Role, ModelInfo]:
        out: Dict[Role, ModelInfo] = {}
        for role in Role:
            if self.force_model:
                out[role] = get_model_info(self.force_model)
            else:
                src = _BORROWS.get(role, role)
                out[role] = get_model_info(self.models[src.value])
        return out


class ModelRouter:
    """Immutable, resolve-once router."""

    def __init__(self, config: RoutingConfig):
        self._config = config
        self._resolved: Dict[Role, ModelInfo] = config.resolve()

    @classmethod
    def from_task(cls, task: Optional[Mapping] = None) -> "ModelRouter":
        return cls(RoutingConfig.from_task(task))

    @property
    def allow_fallback(self) -> bool:
        return self._config.allow_fallback

    def model_for(self, role) -> ModelInfo:
        role = role if isinstance(role, Role) else Role(role)
        return self._resolved[role]

    def resolved_map(self) -> Dict[str, str]:
        """role -> model id, for the run record and the preflight report."""
        return {r.value: m.id for r, m in self._resolved.items()}

    def distinct_models(self) -> List[ModelInfo]:
        seen: Dict[str, ModelInfo] = {}
        for m in self._resolved.values():
            seen.setdefault(m.id, m)
        return list(seen.values())

    def fallbacks_for(self, model: ModelInfo) -> List[ModelInfo]:
        """The models a failing call on ``model`` may move on to."""
        if not self._config.allow_fallback:
            return []
        return [m for m in self.distinct_models() if m.id != model.id]

    def log_summary(self) -> None:
        parts = "  ".join(f"{r.value}={m.id}" for r, m in self._resolved.items())
        logger.info(f"routing[allow_fallback={self._config.allow_fallback}]: {parts}")


# ---------------------------------------------------------------------------
# The run's router. A worker process handles one run, so a module global is
# run-scoped; set once in worker.tasks.run_worker.
# ---------------------------------------------------------------------------
_active_router: Optional[ModelRouter] = None


class NoRouterError(RuntimeError):
    """A model was asked for before the run's router was installed."""


def set_active_router(router: ModelRouter) -> None:
    global _active_router
    _active_router = router
    router.log_summary()


def active_router() -> ModelRouter:
    if _active_router is None:
        raise NoRouterError(
            "no model routing installed: the task's models/force_model are set "
            "on the worker (set_active_router) before any LLM call"
        )
    return _active_router


def get_active_router() -> Optional[ModelRouter]:
    return _active_router


def reset_active_router() -> None:
    global _active_router
    _active_router = None


def model_for(role) -> ModelInfo:
    """The run's model for a role -- the call-site entry point."""
    return active_router().model_for(role)
