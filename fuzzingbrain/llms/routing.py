# SPDX-License-Identifier: Apache-2.0
"""Central model routing -- one source of truth for which model each agent role uses.

Resolution cascade, highest wins:

    1. force_model        every role uses this one model (single-model A/B runs)
    2. per-role override  models.<role> / FB_MODEL_<ROLE>
    3. profile            a named, consistent bundle (period-correct / current)
    4. profile.base       defensive backstop, logged when hit

Parsed once at the boundary (``RoutingConfig.from_sources``) into an immutable
``ModelRouter`` that is injected downstream. Nothing deep in the stack reads the
environment; call sites ask ``router.model_for(Role.X)`` and get a concrete model.

This replaces the scattered ``stage_model(..) or CLAUDE_X`` picks and the two
``default_model`` fallbacks.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Mapping, Optional

from loguru import logger

from .models import (
    ModelInfo,
    get_model_by_id,
    GPT_4_1,
    GPT_4_1_MINI,
    GPT_4_1_NANO,
    O3,
    CLAUDE_OPUS_4_5,
    CLAUDE_SONNET_4_5,
    CLAUDE_HAIKU_4_5,
)

class Role(str, Enum):
    """Every distinct LLM job in the pipeline. Agents declare a role, not a model."""

    FINDER = "finder"          # SP discovery (SPGenerator)
    VERIFIER = "verifier"      # SP verification + direction planning (reasoning)
    POC = "poc"                # PoV synthesis (POVAgent)
    SEED = "seed"              # seed generation (SeedAgent)
    UTILITY = "utility"        # PoV report + aux summaries (low stakes)
    COMPRESSION = "compression"  # context compression, every agent, high volume


@dataclass(frozen=True)
class Profile:
    """A consistent model per role. Typed, not a dict with a magic ``_base`` key."""

    finder: ModelInfo
    verifier: ModelInfo
    poc: ModelInfo
    seed: ModelInfo
    utility: ModelInfo
    compression: ModelInfo
    base: ModelInfo

    def model_for(self, role: "Role") -> ModelInfo:
        return getattr(self, role.value)


PROFILES: Dict[str, Profile] = {
    # AIxCC finals code-freeze era (pre 2025-06-07): a fast non-reasoning finder,
    # a reasoning model for verify/PoV, a cheap model for utility.
    "period-correct": Profile(
        finder=GPT_4_1,
        seed=GPT_4_1,
        verifier=O3,
        poc=O3,
        utility=GPT_4_1_MINI,
        compression=GPT_4_1_NANO,
        base=O3,
    ),
    # Note: an all-Anthropic period-correct profile is not possible -- the AIxCC
    # finals-era Claude models (Opus 4 / Sonnet 4 2025-05, 3.5 Haiku 2024-10) are
    # retired from the first-party API (404); the oldest still served is Sonnet 4.5
    # (2025-09), already post-freeze. Only OpenAI's o3 / GPT-4.1 (2025-04) remain.
    #
    # Reproduces today's de-facto picks, for regression/baseline. finder/verifier/
    # poc are the Sonnet defaults; seed/utility are the opus the leak sites hit;
    # compression is the haiku every BaseAgent uses.
    "current": Profile(
        finder=CLAUDE_SONNET_4_5,
        verifier=CLAUDE_SONNET_4_5,
        poc=CLAUDE_SONNET_4_5,
        seed=CLAUDE_OPUS_4_5,
        utility=CLAUDE_OPUS_4_5,
        compression=CLAUDE_HAIKU_4_5,
        base=CLAUDE_OPUS_4_5,
    ),
}

DEFAULT_PROFILE = "current"

_TRUE = {"1", "true", "True", "yes", "on"}


def _resolve_model(model_id: str, where: str) -> ModelInfo:
    m = get_model_by_id(model_id)
    if m is None:
        raise ValueError(
            f"routing: unknown model id {model_id!r} ({where}); "
            f"check the id against fuzzingbrain/llms/models.py"
        )
    return m


@dataclass(frozen=True)
class Resolved:
    role: Role
    model: ModelInfo
    source: str  # "force" | "override" | "profile" | "base"


@dataclass(frozen=True)
class RoutingConfig:
    """The routing inputs, parsed and validated once at the boundary."""

    profile: str
    force_model: Optional[str] = None
    overrides: Optional[Mapping[str, str]] = None  # role name -> model id
    strict_models: bool = False

    @classmethod
    def from_sources(
        cls,
        task: Optional[Mapping] = None,
        env: Optional[Mapping] = None,
    ) -> "RoutingConfig":
        """Build from a task-config dict and the process env. task wins over env."""
        task = task or {}
        env = env if env is not None else os.environ

        profile = (
            task.get("model_profile")
            or env.get("FB_MODEL_PROFILE")
            or DEFAULT_PROFILE
        )
        force = task.get("force_model") or env.get("LLM_DEFAULT_MODEL") or None

        overrides: Dict[str, str] = dict(task.get("models") or {})
        for role in Role:
            if role.value not in overrides:
                ev = env.get(f"FB_MODEL_{role.value.upper()}")
                if ev:
                    overrides[role.value] = ev

        strict = bool(task.get("strict_models", False)) or (
            env.get("FB_STRICT_MODELS") in _TRUE
        )

        cfg = cls(
            profile=profile,
            force_model=force,
            overrides=overrides,
            strict_models=strict,
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        """Fail fast on a bad profile / role / model id, at load time."""
        if self.profile not in PROFILES:
            raise ValueError(
                f"routing: unknown profile {self.profile!r}; known={list(PROFILES)}"
            )
        if self.force_model:
            _resolve_model(self.force_model, "force_model")
        known_roles = {r.value for r in Role}
        for role, mid in (self.overrides or {}).items():
            if role not in known_roles:
                raise ValueError(
                    f"routing: unknown role {role!r} in models override; "
                    f"known={sorted(known_roles)}"
                )
            _resolve_model(mid, f"override[{role}]")

    def resolve(self) -> Dict[Role, Resolved]:
        prof = PROFILES[self.profile]
        force = _resolve_model(self.force_model, "force_model") if self.force_model else None
        ov = self.overrides or {}
        out: Dict[Role, Resolved] = {}
        for role in Role:
            if force is not None:
                out[role] = Resolved(role, force, "force")
            elif role.value in ov:
                out[role] = Resolved(
                    role, _resolve_model(ov[role.value], f"override[{role.value}]"), "override"
                )
            else:
                m = prof.model_for(role)
                if m is not None:
                    out[role] = Resolved(role, m, "profile")
                else:
                    out[role] = Resolved(role, prof.base, "base")
        return out


class ModelRouter:
    """Immutable, resolve-once router. Inject this; do not read env downstream."""

    def __init__(self, config: RoutingConfig):
        self._config = config
        self._resolved: Dict[Role, Resolved] = config.resolve()

    @classmethod
    def from_sources(cls, task: Optional[Mapping] = None, env: Optional[Mapping] = None) -> "ModelRouter":
        return cls(RoutingConfig.from_sources(task, env))

    @property
    def profile(self) -> str:
        return self._config.profile

    @property
    def strict_models(self) -> bool:
        return self._config.strict_models

    def model_for(self, role) -> ModelInfo:
        role = role if isinstance(role, Role) else Role(role)
        return self._resolved[role].model

    def source_for(self, role) -> str:
        role = role if isinstance(role, Role) else Role(role)
        return self._resolved[role].source

    def resolved_map(self) -> Dict[str, str]:
        """role -> model id, for persistence with the task and the run report."""
        return {r.value: res.model.id for r, res in self._resolved.items()}

    def log_summary(self) -> None:
        parts = []
        for r, res in self._resolved.items():
            parts.append(f"{r.value}={res.model.id}({res.source})")
            if res.source == "base":
                logger.warning(
                    f"routing: role {r.value} fell to profile.base={res.model.id} "
                    f"-- no explicit model configured"
                )
        logger.info(
            f"routing[profile={self._config.profile} "
            f"strict={self._config.strict_models}]: {'  '.join(parts)}"
        )


# ---------------------------------------------------------------------------
# Task-scoped active router (transitional bridge to full DI)
#
# Built once at the worker boundary (worker.tasks.run_worker) and read by every
# agent call site via ``model_for(role)``. A FuzzingBrain worker process handles
# one task, so a module global is task-scoped. This is the single access point
# that replaces ``stage_model`` and the scattered ``or CLAUDE_X`` picks.
# Follow-up: thread the router through constructors (DI) and drop the global.
# ---------------------------------------------------------------------------
_active_router: Optional[ModelRouter] = None


def set_active_router(router: ModelRouter) -> None:
    """Install the task's router at the boundary and log its resolved map."""
    global _active_router
    _active_router = router
    router.log_summary()


def active_router() -> ModelRouter:
    """The task's router, or a lazily-built one from env + the default profile."""
    global _active_router
    if _active_router is None:
        _active_router = ModelRouter.from_sources()
    return _active_router


def reset_active_router() -> None:
    global _active_router
    _active_router = None


def model_for(role) -> ModelInfo:
    """The active router's model for a role -- the call-site entry point."""
    return active_router().model_for(role)
