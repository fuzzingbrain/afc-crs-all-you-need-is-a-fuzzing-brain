# SPDX-License-Identifier: Apache-2.0
"""Prompt (KV) caching applied to stable prefixes for Anthropic calls."""

import copy

import pytest

from fuzzingbrain.llms.client import _apply_prompt_caching

CACHE = {"type": "ephemeral"}


def _is_cached_block(content, text):
    return content == [{"type": "text", "text": text, "cache_control": CACHE}]


def test_anthropic_system_prompt_is_cached():
    params = {
        "model": "claude-sonnet-4-6",
        "messages": [
            {"role": "system", "content": "big stable system prompt"},
            {"role": "user", "content": "question"},
        ],
    }
    _apply_prompt_caching(params)
    assert _is_cached_block(
        params["messages"][0]["content"], "big stable system prompt"
    )


def test_last_message_is_cached_incrementally():
    """The last message is cached so accumulated history hits cache next turn."""
    params = {
        "model": "claude-sonnet-4-6",
        "messages": [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": "a"},
            {"role": "tool", "tool_call_id": "t1", "content": "big tool result"},
        ],
    }
    _apply_prompt_caching(params)
    assert _is_cached_block(params["messages"][-1]["content"], "big tool result")
    assert params["messages"][-1]["tool_call_id"] == "t1"


def test_assistant_with_tool_calls_not_cached():
    """A message carrying tool_calls must keep its shape (not converted)."""
    params = {
        "model": "claude-x",
        "messages": [
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "1"}]},
        ],
    }
    _apply_prompt_caching(params)
    assert params["messages"][-1]["content"] == ""
    assert params["messages"][-1]["tool_calls"] == [{"id": "1"}]


def test_anthropic_tools_are_cached():
    params = {
        "model": "anthropic/claude-3-5-sonnet",
        "messages": [{"role": "user", "content": "q"}],
        "tools": [{"name": "a"}, {"name": "b"}],
    }
    _apply_prompt_caching(params)
    assert params["tools"][-1]["cache_control"] == CACHE
    assert "cache_control" not in params["tools"][0]


def test_non_anthropic_is_untouched():
    params = {
        "model": "gpt-4o",
        "messages": [{"role": "system", "content": "s"}],
        "tools": [{"name": "a"}],
    }
    before = copy.deepcopy(params)
    _apply_prompt_caching(params)
    assert params == before


def test_env_escape_hatch_disables_caching(monkeypatch):
    monkeypatch.setenv("FUZZINGBRAIN_DISABLE_PROMPT_CACHE", "1")
    params = {
        "model": "claude-sonnet-4-6",
        "messages": [{"role": "system", "content": "s"}],
    }
    before = copy.deepcopy(params)
    _apply_prompt_caching(params)
    assert params == before


def test_original_messages_not_mutated():
    """Fallback/retry reuse the caller's list; it must not be mutated in place."""
    original = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    snapshot = copy.deepcopy(original)
    params = {"model": "claude-x", "messages": original}
    _apply_prompt_caching(params)
    assert original == snapshot


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
