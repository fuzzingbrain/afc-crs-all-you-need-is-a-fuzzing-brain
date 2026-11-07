# SPDX-License-Identifier: Apache-2.0
"""The PoC tool context must be registered under the id the tools query by.

``BaseAgent.run_async`` mints an ``AgentContext.agent_id`` and binds the
isolated MCP server to it. The PoC tools resolve their context by that exact
key, with no fallback, so registering under any other id makes every PoC tool
answer "not initialised" for the whole run -- which is what happened: the setup
ran before ``run_async`` existed to mint the id, so it landed under
``self.worker_id`` and the two keys were consecutive ObjectIds that never met.
"""

import pytest

from fuzzingbrain.agents.poc_agent import POCAgent
from fuzzingbrain.tools import poc as P

STORE_KEY = "6a8ffc48b36d5447f576188e"  # what worker_id was, in the failing run
LOOKUP_KEY = "6a8ffc48b36d5447f576188f"  # what ctx.agent_id was: one digit apart


class _Ctx:
    """Stands in for AgentContext: the agent only reads agent_id and sets vh_id."""

    def __init__(self, agent_id):
        self.agent_id = agent_id
        self.vh_id = None


@pytest.fixture
def agent():
    with P._poc_contexts_lock:
        P._poc_contexts.clear()
    a = POCAgent(
        fuzzer="libpng_read_fuzzer",
        run_id="3aa25c01736d484da8d6374b",
        worker_id=STORE_KEY,
        fuzzer_code="int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){return 0;}",
        verbose=False,
    )
    a.vulnerability_hypothesis = {"id": "6a8ffc66699de4c4", "vulnerability_hypothesis_id": "6a8ffc66699de4c4", "function_name": "png_handle_iCCP"}
    yield a
    with P._poc_contexts_lock:
        P._poc_contexts.clear()


def test_context_is_registered_under_the_agent_id(agent):
    agent._configure_context(_Ctx(LOOKUP_KEY))
    assert P._get_context_by_worker_id(LOOKUP_KEY) is not None
    assert P._ensure_context(worker_id=LOOKUP_KEY) is None, "tools must be usable"


def test_the_worker_id_is_not_the_key(agent):
    """The regression itself: registering under worker_id is what broke create_poc."""
    agent._configure_context(_Ctx(LOOKUP_KEY))
    assert P._get_context_by_worker_id(STORE_KEY) is None


def test_setup_cannot_run_before_the_context_exists(agent):
    """Why the call sits in _configure_context and not before run_async."""
    assert agent.mcp_context_id == STORE_KEY, "no context yet: falls back to worker_id"
    assert agent.mcp_context_id != LOOKUP_KEY


def test_the_agent_row_names_its_vh(agent):
    # The VH goes into the agents row when the context opens (vh_id is
    # required for a POCAgent), not into the context afterwards.
    assert agent._agent_row() == {"vh_id": "6a8ffc66699de4c4"}


def test_no_vulnerability_hypothesis_registers_nothing(agent):
    agent.vulnerability_hypothesis = None
    agent._configure_context(_Ctx(LOOKUP_KEY))
    assert P._get_context_by_worker_id(LOOKUP_KEY) is None


def test_uninitialised_tools_do_not_name_a_tool_the_agent_lacks():
    """The old text said "Call set_poc_context first" -- not a tool the agent
    has. A model told to call something unavailable can only retry, which is
    how one agent spent 100 iterations and 462s on 47 identical failures."""
    err = P._ensure_context(worker_id="unregistered")["error"]
    assert "set_poc_context" not in err
    assert "retrying" in err.lower()
