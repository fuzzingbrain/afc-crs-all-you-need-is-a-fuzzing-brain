"""gpt-5.5/5.6 go through the Responses API; chat params and results are converted."""
from types import SimpleNamespace

from fuzzingbrain.llms.client import (
    _from_responses, _is_responses_api_model, _to_responses_request)


def test_routing():
    assert _is_responses_api_model("gpt-5.6-sol") and _is_responses_api_model("gpt-5.5")
    assert not _is_responses_api_model("gpt-5-2025-08-07")
    assert not _is_responses_api_model("gpt-5.2") and not _is_responses_api_model("o3")


def test_request_conversion_keeps_the_tool_round_trip():
    tools = [{"type": "function", "function": {"name": "f", "description": "d",
                                               "parameters": {"type": "object"}}}]
    msgs = [{"role": "system", "content": "sys"},
            {"role": "user", "content": [{"type": "text", "text": "hi"}]},
            {"role": "assistant", "content": "",
             "tool_calls": [{"id": "c1", "type": "function",
                             "function": {"name": "f", "arguments": "{\"a\":1}"}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "42"}]
    req = _to_responses_request({"model": "gpt-5.6-sol", "messages": msgs, "tools": tools,
                                 "max_completion_tokens": 32000, "reasoning_effort": "low",
                                 "tool_choice": {"type": "function", "function": {"name": "f"}}})
    assert req["input"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
        {"type": "function_call", "call_id": "c1", "name": "f", "arguments": "{\"a\":1}"},
        {"type": "function_call_output", "call_id": "c1", "output": "42"}]
    assert req["tools"] == [{"type": "function", "name": "f", "description": "d",
                             "parameters": {"type": "object"}}]
    assert req["reasoning"] == {"effort": "low"} and req["max_output_tokens"] == 32000
    assert req["tool_choice"] == {"type": "function", "name": "f"} and req["store"] is False


def test_result_is_shaped_like_a_chat_completion():
    resp = SimpleNamespace(
        id="r1", model="gpt-5.6-sol", status="completed", output_text="",
        output=[SimpleNamespace(type="reasoning"),
                SimpleNamespace(type="function_call", call_id="c9", name="f", arguments="{}")],
        usage=SimpleNamespace(input_tokens=10, output_tokens=5, total_tokens=15,
                              input_tokens_details=SimpleNamespace(cached_tokens=4)))
    r = _from_responses(resp)
    msg = r.choices[0].message
    assert r.choices[0].finish_reason == "tool_calls" and msg.content is None
    assert (msg.tool_calls[0].id, msg.tool_calls[0].function.name) == ("c9", "f")
    assert (r.usage.prompt_tokens, r.usage.completion_tokens,
            r.usage.prompt_tokens_details.cached_tokens) == (10, 5, 4)
