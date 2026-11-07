# SPDX-License-Identifier: Apache-2.0
"""Model routing: the task names the models; nothing is defaulted."""

import pytest

from fuzzingbrain.llms.models import UnknownModelError
from fuzzingbrain.llms.routing import ModelRouter, Role, RoutingConfig, TASK_ROLES

PERIOD_CORRECT = {
    "finder": "gpt-4.1", "seed": "gpt-4.1", "utility": "gpt-4.1",
    "verifier": "o3", "poc": "o3",
}


def test_every_role_from_models():
    r = ModelRouter.from_task({"models": PERIOD_CORRECT})
    for role in TASK_ROLES:
        assert r.model_for(role).id == PERIOD_CORRECT[role]


def test_lg_planner_uses_the_verifier_model():
    r = ModelRouter.from_task({"models": dict(PERIOD_CORRECT, verifier="gpt-4.1-mini")})
    assert r.model_for(Role.LG_PLANNER).id == "gpt-4.1-mini"
    assert r.resolved_map()["lg_planner"] == "gpt-4.1-mini"


def test_force_model_sets_every_role():
    r = ModelRouter.from_task({"force_model": "claude-sonnet-4-5"})
    assert {m for m in r.resolved_map().values()} == {"claude-sonnet-4-5"}
    assert set(r.resolved_map()) == {x.value for x in Role}


def test_force_model_and_models_are_exclusive():
    with pytest.raises(ValueError, match="not both"):
        RoutingConfig.from_task({"force_model": "o3", "models": PERIOD_CORRECT})


def test_no_model_is_an_error():
    with pytest.raises(ValueError, match="no model"):
        RoutingConfig.from_task({})


def test_missing_role_is_an_error():
    with pytest.raises(ValueError, match="missing roles"):
        RoutingConfig.from_task({"models": {"finder": "o3"}})


def test_unknown_role_is_an_error():
    with pytest.raises(ValueError, match="unknown roles"):
        RoutingConfig.from_task({"models": dict(PERIOD_CORRECT, planner="o3")})


def test_unknown_model_is_an_error():
    with pytest.raises(UnknownModelError):
        RoutingConfig.from_task({"force_model": "gpt-9-turbo"})
    with pytest.raises(UnknownModelError):
        RoutingConfig.from_task({"models": dict(PERIOD_CORRECT, finder="nope-1")})


def test_current_models_are_priced():
    r = ModelRouter.from_task({"force_model": "claude-opus-5-5"})
    m = r.model_for(Role.POC)
    assert m.price_input > 0 and m.price_output > 0


def test_fallbacks_follow_allow_fallback():
    off = ModelRouter.from_task({"models": PERIOD_CORRECT})
    o3 = off.model_for(Role.POC)
    assert off.allow_fallback is False and off.fallbacks_for(o3) == []
    on = ModelRouter.from_task({"models": PERIOD_CORRECT, "allow_fallback": True})
    assert [m.id for m in on.fallbacks_for(o3)] == ["gpt-4.1"]


def test_client_retries_only_the_same_model_without_fallback():
    from fuzzingbrain.llms.client import LLMClient
    from fuzzingbrain.llms import routing

    routing.set_active_router(ModelRouter.from_task({"models": PERIOD_CORRECT}))
    try:
        c = LLMClient(role="poc")
        assert [m.id for m in c._next_models("o3")] == ["o3"]
        c._tried_models.add("o3")
        assert c._next_models("o3") == []
        routing.set_active_router(
            ModelRouter.from_task({"models": PERIOD_CORRECT, "allow_fallback": True})
        )
        assert [m.id for m in c._next_models("o3")] == ["gpt-4.1"]
        assert c._model_info(None).id == "o3"  # the client's role
    finally:
        routing.reset_active_router()


def test_no_router_is_an_error():
    from fuzzingbrain.llms import routing

    routing.reset_active_router()
    with pytest.raises(routing.NoRouterError):
        routing.model_for(Role.FINDER)


def test_call_cost_records_prices():
    from fuzzingbrain.llms.models import call_cost, get_model_info

    info = get_model_info("claude-sonnet-4-5")
    cin, cout, total, prices = call_cost(info, 1_000_000, 1_000_000, cache_read_tokens=500_000)
    assert prices["input"] == info.price_input and prices["cache_read"] < prices["input"]
    assert total == pytest.approx(cin + cout)
    assert cin == pytest.approx(0.5 * info.price_input + 0.5 * prices["cache_read"])
