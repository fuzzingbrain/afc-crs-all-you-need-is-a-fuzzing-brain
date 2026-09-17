# SPDX-License-Identifier: Apache-2.0
"""The LLM facade + the two provider adapters.

The Claude path is unchanged (its cache breakpoints are covered elsewhere);
these tests pin provider selection, cost/usage accounting, and — the new part —
that the OpenAI adapter translates the loop's internal blocks to the Responses
API and back without the loop having to change. The OpenAI SDK is mocked, so no
network and no key needed.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent import llm  # noqa: E402
from fbagent.llm import LLM, OpenAIAdapter, _Block, context_window  # noqa: E402


def test_provider_selection():
    assert LLM.__new__(LLM) is not None
    assert llm._is_openai("o3") and llm._is_openai("gpt-4.1")
    assert not llm._is_openai("claude-opus-5") and not llm._is_openai("claude-haiku-4-5")


def test_context_windows():
    assert context_window("claude-opus-5") == 1_000_000
    assert context_window("claude-haiku-4-5") == 200_000
    assert context_window("o3") == 200_000
    assert context_window("gpt-4.1") == 1_000_000


def test_openai_input_translation():
    """Internal blocks -> Responses input items: assistant text/tool_use, a
    tool_result user turn, and a plain string user turn."""
    a = OpenAIAdapter.__new__(OpenAIAdapter)
    messages = [
        {"role": "user", "content": "read harness/x.c"},
        {"role": "assistant", "content": [
            _Block("thinking", thinking="private"),
            _Block("text", text="let me look"),
            _Block("tool_use", id="c1", name="read", input={"path": "harness/x.c"}),
        ]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "c1", "content": "int main(){}"},
        ]},
    ]
    items = a._to_input(messages)
    kinds = [it.get("type") or it.get("role") for it in items]
    assert kinds == ["user", "assistant", "function_call", "function_call_output"]
    fc = next(it for it in items if it.get("type") == "function_call")
    assert fc["call_id"] == "c1" and fc["name"] == "read" and '"harness/x.c"' in fc["arguments"]
    fco = next(it for it in items if it.get("type") == "function_call_output")
    assert fco["call_id"] == "c1" and fco["output"] == "int main(){}"
    # thinking block dropped on the OpenAI path
    assert not any("private" in str(it) for it in items)


def test_openai_tool_schema_translation():
    tools = [{"name": "read", "description": "read a file",
              "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}}}]
    out = OpenAIAdapter._to_tools(tools)
    assert out == [{"type": "function", "name": "read", "description": "read a file",
                    "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}}]


def _fake_response(*, text=None, call=None, cached=0, in_tok=100, out_tok=20, status="completed"):
    output = []
    if text is not None:
        output.append(SimpleNamespace(type="message",
                       content=[SimpleNamespace(type="output_text", text=text)]))
    if call is not None:
        output.append(SimpleNamespace(type="function_call", call_id=call[0],
                       name=call[1], arguments=call[2]))
    usage = SimpleNamespace(input_tokens=in_tok, output_tokens=out_tok,
                            input_tokens_details=SimpleNamespace(cached_tokens=cached))
    return SimpleNamespace(output=output, status=status, incomplete_details=None,
                           usage=usage, model="o3-2025")


def test_openai_response_translation_tool_use():
    a = OpenAIAdapter.__new__(OpenAIAdapter)
    a.model = "o3"
    reply = a._from_response(_fake_response(text="I'll call read",
                                            call=("c9", "read", '{"path": "x.c"}'), cached=40))
    assert reply.stop_reason == "tool_use"
    types = [b.type for b in reply.content]
    assert "text" in types and "tool_use" in types
    tu = next(b for b in reply.content if b.type == "tool_use")
    assert tu.id == "c9" and tu.name == "read" and tu.input == {"path": "x.c"}
    # cached tokens split out of input, into cache_read
    assert reply.usage.cache_read_input_tokens == 40
    assert reply.usage.input_tokens == 60      # 100 total - 40 cached


def test_openai_response_translation_end_turn_and_truncation():
    a = OpenAIAdapter.__new__(OpenAIAdapter)
    a.model = "o3"
    assert a._from_response(_fake_response(text="done")).stop_reason == "end_turn"
    assert a._from_response(_fake_response(text="cut", status="incomplete")).stop_reason == "max_tokens"


def test_llm_accounting_openai(monkeypatch):
    """LLM.call accumulates usage/cost/cache_hit_rate the same for a mocked
    OpenAI adapter as for Claude."""
    obj = LLM.__new__(LLM)
    obj.model = "o3"; obj.provider = "openai"; obj.effort = "high"; obj.max_tokens = 32000
    obj.served_model = None; obj.last_prompt_tokens = 0
    obj.usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}

    class _Adapter:
        def call(self, system, messages, tools):
            a = OpenAIAdapter.__new__(OpenAIAdapter); a.model = "o3"
            return a._from_response(_fake_response(text="hi", in_tok=100, out_tok=20, cached=40))
    obj._adapter = _Adapter()

    resp = obj.call("sys", [{"role": "user", "content": "hi"}], [])
    assert resp.stop_reason == "end_turn"
    assert obj.usage == {"input": 60, "output": 20, "cache_read": 40, "cache_write": 0}
    assert obj.last_prompt_tokens == 100
    assert 0.0 < obj.cache_hit_rate < 1.0
    assert obj.cost_usd > 0
    assert obj.served_model == "o3-2025"


def test_cost_rates_differ_by_provider():
    claude = LLM.__new__(LLM); claude.model = "claude-opus-5"; claude.provider = "anthropic"
    claude.usage = {"input": 1_000_000, "output": 0, "cache_read": 0, "cache_write": 0}
    assert abs(claude.cost_usd - 5.0) < 1e-6
    oai = LLM.__new__(LLM); oai.model = "o3"; oai.provider = "openai"
    oai.usage = {"input": 1_000_000, "output": 0, "cache_read": 0, "cache_write": 0}
    assert abs(oai.cost_usd - 2.0) < 1e-6
