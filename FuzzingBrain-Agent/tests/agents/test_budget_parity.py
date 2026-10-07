"""The budget this agent spends has to be the budget a bare model spends.

The bench compares fb-agent + model against the same model run bare (the `api`
arm) and against `claude -p` (the `claudecode` arm). That comparison is only
meaningful if all three are given the same resources, so two rules hold here:

  * no dollar cap -- the api arm has none, so neither may we;
  * a turn means the same thing -- one usable model reply, with an unusable one
    re-drawn free up to 3 times, which is what the api arm does.

Upstream defaults break both (cost_limit 3.0; a re-draw costs a call), so these
are regression tests against drifting back, not tests of upstream behaviour.
"""

from pathlib import Path

import yaml

from minisweagent.agents.default import AgentConfig, DefaultAgent
from minisweagent.environments.local import LocalEnvironment
from minisweagent.exceptions import FormatError

CONFIG_DIR = Path(__file__).parents[2] / "src" / "minisweagent" / "config"


# ---- no dollar cap ---------------------------------------------------------

def test_the_agent_ships_without_a_dollar_cap():
    assert AgentConfig(system_template="", instance_template="").cost_limit == 0.0


def test_no_shipped_config_reintroduces_a_dollar_cap():
    offenders = {}
    for cfg in sorted(CONFIG_DIR.rglob("*.yaml")):
        limit = (yaml.safe_load(cfg.read_text()) or {}).get("agent", {}).get("cost_limit")
        if limit:  # 0, 0., and absent are all fine
            offenders[cfg.name] = limit
    assert not offenders, f"these configs cap spend: {offenders}"


# ---- a turn is one usable model reply --------------------------------------

class _NeverParses:
    """A model whose every reply fails to parse, so each call is a re-draw."""

    def __init__(self):
        self.calls = 0

    def query(self, messages, **kwargs):
        self.calls += 1
        raise FormatError({"role": "user", "content": "No tool calls found in the response.",
                           "extra": {"interrupt_type": "FormatError", "cost": 0.0}})

    def format_message(self, role: str, content: str) -> dict:
        return {"role": role, "content": content}

    def get_template_vars(self) -> dict:
        return {}

    def serialize(self) -> dict:
        return {}


def _agent(**overrides) -> DefaultAgent:
    return DefaultAgent(
        model=_NeverParses(), env=LocalEnvironment(),
        system_template="", instance_template="", action_observation_template="",
        **overrides,
    )


def test_a_turn_is_charged_once_and_its_redraws_are_free():
    # The api arm charges `turns_used = turn + 1` before its first call and then
    # re-draws up to 3 times for free: 4 calls, 1 turn.
    agent = _agent(max_consecutive_format_errors=4, turn_limit=0)
    agent.run("never parses")
    assert agent.model.calls == 4
    assert agent.n_turns == 1


def test_the_free_redraws_run_out():
    # A 5th unusable reply is past the api arm's 3 re-draws, so it starts a
    # second turn rather than being refunded for ever.
    agent = _agent(max_consecutive_format_errors=6, turn_limit=0)
    agent.run("never parses")
    assert agent.model.calls == 6
    assert agent.n_turns == 3  # calls 1 and 5 charged, plus the 6th that gave up


def test_an_unlimited_format_error_setting_does_not_make_turns_free():
    # max_consecutive_format_errors=0 means "never give up"; it must not also
    # mean "never charge a turn", or turn_limit would stop bounding the run.
    agent = _agent(max_consecutive_format_errors=0, turn_limit=5)
    agent.run("never parses")
    assert agent.n_turns == 5
