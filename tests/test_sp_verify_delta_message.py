# SPDX-License-Identifier: Apache-2.0
"""
The verifier's opening message must agree with its system prompt.

In delta mode the system prompt says reachability is not the verifier's job.
The opening message used to say the opposite ("REACHABLE ... If either is NO
-> mark as FALSE POSITIVE immediately") and the steps opened with "CHECK
REACHABILITY". A verifier that followed the message found the curl harness
allow-listing ws/wss and marked the real cu-delta-01 bug a false positive,
without noticing the diff had changed the scheme lookup to let the new
protocol through.
"""

from fuzzingbrain.agents.sp_verifier import SPVerifier

SP = {
    "suspicious_point_id": "abc",
    "function_name": "verynormalprotocol_doing",
    "static_reachable": True,
    "description": "type confusion write",
    "score": 0.8,
}


def _message(scan_mode: str) -> str:
    v = SPVerifier(fuzzer="curl_fuzzer_ws", sanitizer="address", scan_mode=scan_mode, verbose=False)
    return v.get_initial_message(suspicious_point=SP, fuzzer_code="")


def test_delta_message_does_not_ask_for_reachability():
    msg = _message("delta")
    assert "CHECK REACHABILITY" not in msg
    assert "mark as FALSE POSITIVE immediately" not in msg
    assert "Start by verifying reachability" not in msg
    assert "assumed_reachable" in msg
    assert "NOT judged in delta mode" in msg


def test_delta_message_skips_pointer_hunt_for_unreachable_points():
    v = SPVerifier(fuzzer="f", sanitizer="address", scan_mode="delta", verbose=False)
    msg = v.get_initial_message(suspicious_point={**SP, "static_reachable": False}, fuzzer_code="")
    assert "static-unreachable" not in msg
    assert "function pointer" not in msg.lower()


def test_full_message_still_requires_reachability():
    msg = _message("full")
    assert "CHECK REACHABILITY" in msg
    assert "mark as FALSE POSITIVE immediately" in msg
