# SPDX-License-Identifier: Apache-2.0
"""The index and call graph tools load only when there is an index to read."""

import asyncio

import pytest

from fuzzingbrain.tools.mcp_factory import create_isolated_mcp_server

GATED = {
    "get_function",
    "get_function_source",
    "get_functions_by_file",
    "search_functions",
    "get_callers",
    "get_callees",
    "get_call_graph",
    "find_all_paths",
    "check_reachability",
    "get_reachable_functions",
}
ALWAYS = {"Read", "Grep", "Glob", "get_diff"}


def _names(**kwargs):
    async def go():
        mcp = create_isolated_mcp_server(agent_id="gating-probe", **kwargs)
        return {t.name for t in await mcp.list_tools()}

    return asyncio.run(go())


def test_index_tools_are_offered_when_an_index_exists():
    names = _names(include_static_analysis_tools=True)
    assert GATED & names, "the index tools should be registered"
    assert ALWAYS <= names


def test_index_tools_are_withheld_when_there_is_no_index():
    """Advertising them over an empty index makes get_function_source return
    nothing, which the model reads as 'no such function' rather than 'no
    index' -- and then it has no way to read code at all."""
    names = _names(include_static_analysis_tools=False)
    assert GATED & names == set()


def test_file_tools_survive_the_gate():
    """This is what makes the gate safe: without them, switching the index off
    would leave the agent unable to read source at all."""
    assert ALWAYS <= _names(include_static_analysis_tools=False)


def test_findings_tools_survive_the_gate():
    names = _names(include_static_analysis_tools=False)
    assert {"create_suspicious_point", "update_suspicious_point"} <= names


def test_gate_removes_only_the_index_tools():
    on = _names(include_static_analysis_tools=True)
    off = _names(include_static_analysis_tools=False)
    assert on - off <= GATED, "the gate must not take anything else with it"
    assert off - on == set()


# ------------------------------------------------------------------ prompts


class _Probe:
    """Exercises the hint helpers without constructing a real agent."""

    from fuzzingbrain.agents.base import BaseAgent

    read_function_hint = BaseAgent.read_function_hint
    find_callers_hint = BaseAgent.find_callers_hint

    def __init__(self, available):
        self._available = available

    @property
    def include_static_analysis_tools(self):
        return self._available


@pytest.mark.parametrize("available", [True, False])
def test_prompts_name_only_tools_the_agent_has(available):
    """Naming a tool the agent was not given costs an iteration: the call
    fails and the model has to work out why."""
    probe = _Probe(available)
    hints = probe.read_function_hint("png_handle_iCCP") + probe.find_callers_hint(
        "png_handle_iCCP"
    )
    if available:
        assert "get_function_source" in hints and "get_callers" in hints
    else:
        assert "get_function_source" not in hints and "get_callers" not in hints
        assert "Grep" in hints and "Read" in hints
    assert "png_handle_iCCP" in hints
