# SPDX-License-Identifier: Apache-2.0
"""DirectionPlanningAgent surfaces a vuln_hint in its initial message.

A caller-supplied bug report must reach the planning prompt so the agent
creates a focused direction instead of exploring blind.
"""

from fuzzingbrain.agents.direction_planning_agent import DirectionPlanningAgent


def _agent():
    return DirectionPlanningAgent(fuzzer="vacm_fuzzer", sanitizer="address")


def test_hint_appears_in_initial_message():
    msg = _agent().get_initial_message(
        fuzzer_code="int LLVMFuzzerTestOneInput(){}",
        reachable_count=42,
        vuln_hint="NULL deref in vacm_parse_config_group at vacm.c:414",
    )
    assert "Known Vulnerability Report" in msg
    assert "vacm_parse_config_group" in msg


def test_no_hint_keeps_message_clean():
    msg = _agent().get_initial_message(fuzzer_code="x", reachable_count=1)
    assert "Known Vulnerability Report" not in msg
    # core planning content still present
    assert "Plan the analysis directions" in msg


def test_blank_hint_is_ignored():
    msg = _agent().get_initial_message(
        fuzzer_code="x", reachable_count=1, vuln_hint="   \n  "
    )
    assert "Known Vulnerability Report" not in msg
