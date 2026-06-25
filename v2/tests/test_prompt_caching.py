# SPDX-License-Identifier: Apache-2.0
"""Prompt (KV) caching applied to stable prefixes for Anthropic calls."""

import copy

from fuzzingbrain.llms.client import _apply_prompt_caching

CACHE = {"type": "ephemeral"}


def test_anthropic_system_prompt_is_cached():
    params = {
        "model": "claude-sonnet-4-6",
        "messages": [
            {"role": "system", "content": "big stable system prompt"},
            {"role": "user", "content": "dynamic question"},
        ],
    }
    _apply_prompt_caching(params)
    sys_block = params["messages"][0]["content"][0]
    assert sys_block["text"] == "big stable system prompt"
    assert sys_block["cache_control"] == CACHE
    # Dynamic user message is left untouched.
    assert params["messages"][1] == {"role": "user", "content": "dynamic question"}


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


def test_original_messages_not_mutated():
    """Fallback/retry reuse the caller's list; it must not be mutated in place."""
    original = [{"role": "system", "content": "s"}]
    params = {"model": "claude-x", "messages": original}
    _apply_prompt_caching(params)
    assert original[0]["content"] == "s"
