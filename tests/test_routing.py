# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the central model router (fuzzingbrain/llms/routing.py).

Covers the resolution cascade (force > override > profile > base), boundary
parsing (task wins over env), fail-fast validation, strict-mode parsing, and the
resolved-map output. Run: venv/bin/python -m pytest tests/test_routing.py -q
"""
import pytest

from fuzzingbrain.llms.routing import (
    Role,
    Profile,
    PROFILES,
    RoutingConfig,
    ModelRouter,
)


# --- profile contents -------------------------------------------------------

def test_period_correct_profile_is_all_openai_period_models():
    r = ModelRouter.from_sources(task={"model_profile": "period-correct"}, env={})
    m = r.resolved_map()
    assert m == {
        "finder": "gpt-4.1",
        "verifier": "o3",
        "poc": "o3",
        "seed": "gpt-4.1",
        "utility": "gpt-4.1-mini",
        "compression": "gpt-4.1-nano",
    }
    # every resolved role came from the profile, nothing fell to base
    for role in Role:
        assert r.source_for(role) == "profile"


def test_current_profile_reproduces_todays_picks():
    r = ModelRouter.from_sources(task={"model_profile": "current"}, env={})
    m = r.resolved_map()
    assert m["finder"] == "claude-sonnet-4-5-20250929"
    assert m["seed"] == "claude-opus-4-5-20251101"
    assert m["utility"] == "claude-opus-4-5-20251101"


def test_default_profile_when_nothing_set():
    r = ModelRouter.from_sources(task={}, env={})
    assert r.profile == "current"


# --- cascade precedence -----------------------------------------------------

def test_force_model_overrides_everything():
    r = ModelRouter.from_sources(
        task={"model_profile": "period-correct", "force_model": "o3",
              "models": {"finder": "gpt-4.1"}},
        env={},
    )
    for role in Role:
        assert r.model_for(role).id == "o3"
        assert r.source_for(role) == "force"


def test_per_role_override_beats_profile():
    r = ModelRouter.from_sources(
        task={"model_profile": "period-correct", "models": {"verifier": "gpt-4.1-mini"}},
        env={},
    )
    assert r.model_for(Role.VERIFIER).id == "gpt-4.1-mini"
    assert r.source_for(Role.VERIFIER) == "override"
    # untouched roles still come from the profile
    assert r.model_for(Role.FINDER).id == "gpt-4.1"
    assert r.source_for(Role.FINDER) == "profile"


def test_env_override_applies_when_task_absent():
    r = ModelRouter.from_sources(
        task={"model_profile": "period-correct"},
        env={"FB_MODEL_VERIFIER": "gpt-4.1-mini"},
    )
    assert r.model_for(Role.VERIFIER).id == "gpt-4.1-mini"
    assert r.source_for(Role.VERIFIER) == "override"


def test_task_override_wins_over_env():
    r = ModelRouter.from_sources(
        task={"model_profile": "period-correct", "models": {"verifier": "o3"}},
        env={"FB_MODEL_VERIFIER": "gpt-4.1-mini"},
    )
    assert r.model_for(Role.VERIFIER).id == "o3"


def test_force_from_env_legacy_var():
    r = ModelRouter.from_sources(
        task={"model_profile": "period-correct"},
        env={"LLM_DEFAULT_MODEL": "gpt-4.1"},
    )
    for role in Role:
        assert r.model_for(role).id == "gpt-4.1"
        assert r.source_for(role) == "force"


# --- strict-mode parsing ----------------------------------------------------

def test_strict_models_off_by_default():
    assert ModelRouter.from_sources(task={}, env={}).strict_models is False


def test_strict_models_from_task_and_env():
    assert ModelRouter.from_sources(task={"strict_models": True}, env={}).strict_models is True
    assert ModelRouter.from_sources(task={}, env={"FB_STRICT_MODELS": "1"}).strict_models is True
    assert ModelRouter.from_sources(task={}, env={"FB_STRICT_MODELS": "0"}).strict_models is False


# --- fail-fast validation ---------------------------------------------------

def test_unknown_profile_raises():
    with pytest.raises(ValueError, match="unknown profile"):
        RoutingConfig.from_sources(task={"model_profile": "does-not-exist"}, env={})


def test_unknown_force_model_raises():
    with pytest.raises(ValueError, match="unknown model id"):
        RoutingConfig.from_sources(task={"force_model": "gpt-9-turbo"}, env={})


def test_unknown_role_in_overrides_raises():
    with pytest.raises(ValueError, match="unknown role"):
        RoutingConfig.from_sources(task={"models": {"planner": "o3"}}, env={})


def test_unknown_override_model_raises():
    with pytest.raises(ValueError, match="unknown model id"):
        RoutingConfig.from_sources(task={"models": {"finder": "nope-1"}}, env={})


# --- invariants -------------------------------------------------------------

def test_every_profile_defines_every_role_and_base():
    for name, prof in PROFILES.items():
        assert isinstance(prof, Profile)
        for role in Role:
            assert prof.model_for(role) is not None, f"{name} missing {role}"
        assert prof.base is not None


def test_model_for_accepts_string_role():
    r = ModelRouter.from_sources(task={"model_profile": "period-correct"}, env={})
    assert r.model_for("finder").id == "gpt-4.1"
