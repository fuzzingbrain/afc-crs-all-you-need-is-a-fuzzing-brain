# SPDX-License-Identifier: Apache-2.0
"""
POV tool context id regression tests.

``create_pov`` always returned "POV context not set. Call set_pov_context
first.", so a POV agent could never make a single attempt.

The tool call chain is:

    set_pov_context(worker_id=agent.mcp_context_id)     -> _pov_contexts[<id A>]
    create_isolated_mcp_server(worker_id=ctx.agent_id)  -> create_pov looks up <id B>

``mcp_context_id`` resolves to ``ctx.agent_id`` once the AgentContext exists and
falls back to ``worker_id`` while it does not. ``_setup_pov_context()`` used to
run from ``generate_pov_async()``, before ``run_async()`` creates the
AgentContext, so the context was always filed under ``worker_id`` while
``mcp_factory`` bound ``ctx.agent_id`` into every POV tool closure. The tools
therefore looked up an id the context was never filed under.

Fixed in 5cfd0b2e by setting the POV context up from ``_configure_context()``,
which runs after ``self._context = ctx``.

Observed in run sqlite_91990ded..._111050: context stored under
6a68d67fbc725ac4fcb5dba9, tools looked up 6a68dadbbc725ac4fcb5dd59. Those are
the ids used below.

No LLM calls, no mongo, no docker.
"""

import pytest

from fuzzingbrain.agents.pov_agent import POVAgent
from fuzzingbrain.tools.pov import (
    _pov_contexts,
    _ensure_context,
    create_pov_impl,
)


# Real ids from the 07-28 run that produced the failure.
WORKER_ID = "6a68d67fbc725ac4fcb5dba9"
AGENT_ID = "6a68dadbbc725ac4fcb5dd59"

SP = {
    "suspicious_point_id": "sp_test_1",
    "function_name": "sqlite3VdbeMemSetTex",
    "vuln_type": "heap-buffer-overflow",
}


class FakeCtx:
    """Stand-in for AgentContext: only agent_id matters here."""

    def __init__(self, agent_id):
        self.agent_id = agent_id
        self.sp_id = None


class FakePovs:
    def __init__(self):
        self.saved = []

    def save(self, pov):
        self.saved.append(pov)
        return True


class FakeRepos:
    """Enough of RepositoryManager for _create_pov_core to reach a save."""

    def __init__(self):
        self.povs = FakePovs()


@pytest.fixture(autouse=True)
def clean_pov_contexts():
    """Clear the module-level context registry before and after each test."""
    _pov_contexts.clear()
    yield
    _pov_contexts.clear()


@pytest.fixture
def make_agent(tmp_path):
    def _make(worker_id=WORKER_ID):
        agent = POVAgent(
            fuzzer="ossfuzz",
            sanitizer="address",
            task_id="task_test",
            worker_id=worker_id,
            output_dir=tmp_path,
            repos=FakeRepos(),
        )
        agent.suspicious_point = SP
        return agent

    return _make


def test_mcp_context_id_falls_back_to_worker_id(make_agent):
    """Before run_async() creates the AgentContext, the id is worker_id."""
    agent = make_agent()
    assert agent.mcp_context_id == WORKER_ID


def test_mcp_context_id_becomes_agent_id_once_context_is_set(make_agent):
    """Once _context exists, the id is the one mcp_factory will bind."""
    agent = make_agent()
    agent._context = FakeCtx(AGENT_ID)
    assert agent.mcp_context_id == AGENT_ID


def test_configure_context_keys_pov_context_by_agent_id(make_agent):
    """The regression: the context must land under the id the tools look up.

    Replays the real ordering from base.run_async:
        self._context = ctx
        self._configure_context(ctx)
        create_isolated_mcp_server(worker_id=ctx.agent_id)
    """
    agent = make_agent()
    ctx = FakeCtx(AGENT_ID)
    agent._context = ctx
    agent._configure_context(ctx)

    assert list(_pov_contexts.keys()) == [AGENT_ID]


def test_ensure_context_passes_for_the_bound_id(make_agent):
    """The gate that produced the failure in the 07-28 run."""
    agent = make_agent()
    ctx = FakeCtx(AGENT_ID)
    agent._context = ctx
    agent._configure_context(ctx)

    assert _ensure_context(worker_id=AGENT_ID) is None


def test_create_pov_is_not_rejected_for_the_bound_id(make_agent):
    """The real tool entry point gets past the context gate.

    FakeRepos only implements .povs, so an AttributeError deeper in POV
    packaging still means the context was found — which is what this asserts.
    """
    agent = make_agent()
    ctx = FakeCtx(AGENT_ID)
    agent._context = ctx
    agent._configure_context(ctx)

    try:
        result = create_pov_impl(
            generator_code="def generate():\n    return b'A'*100\n",
            worker_id=AGENT_ID,  # what mcp_factory binds
        )
        error = result.get("error", "")
    except AttributeError:
        # Reached POV packaging; the fake repos are deliberately incomplete.
        error = ""

    assert not error.startswith("POV context not set")
