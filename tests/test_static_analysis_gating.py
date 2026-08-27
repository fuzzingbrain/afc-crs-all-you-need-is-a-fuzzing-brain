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


# ------------------------------------------------------------------ coverage


COVERAGE = {
    "run_coverage",
    "get_coverage_feedback",
    "check_pov_reaches_target",
    "list_available_fuzzers",
}


def test_coverage_tools_are_offered_when_the_build_exists():
    assert COVERAGE <= _names(include_coverage_tools=True)


def test_coverage_tools_are_withheld_without_a_coverage_build():
    """All four read the coverage build output. Offered over a missing build
    they fail in a way that reads as 'this target has no coverage'."""
    assert COVERAGE & _names(include_coverage_tools=False) == set()


def test_trace_pov_survives_a_missing_coverage_build():
    """trace_pov traces with gdb against the ASAN binary and only falls back to
    coverage, so it loses detail rather than breaking. Gating it with the
    coverage tools would be the mistake this test exists to catch."""
    assert "trace_pov" in _names(include_coverage_tools=False)


def test_coverage_gate_removes_only_the_coverage_tools():
    on = _names(include_coverage_tools=True)
    off = _names(include_coverage_tools=False)
    assert on - off == COVERAGE
    assert off - on == set()


def test_the_two_gates_are_independent():
    both_off = _names(include_static_analysis_tools=False, include_coverage_tools=False)
    assert GATED & both_off == set()
    assert COVERAGE & both_off == set()
    assert ALWAYS <= both_off, "reading source must survive both gates"
    assert "trace_pov" in both_off


def test_coverage_error_says_the_build_is_missing_not_the_context():
    """'Coverage context not set' reads as a configuration slip. What actually
    happened is that the coverage build produced nothing, which is allowed."""
    from fuzzingbrain.tools import coverage

    ok, _, msg = coverage.run_coverage_fuzzer("some_fuzzer", b"x", None)
    assert ok is False
    assert "No coverage build for this run" in msg
    assert "context" not in msg.lower()
