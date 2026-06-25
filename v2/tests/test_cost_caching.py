# SPDX-License-Identifier: Apache-2.0
"""Cost accounting reflects prompt-cache discounts.

litellm folds cache_read + cache_creation into prompt_tokens; the cached
portions are billed at a discount. Without accounting for them a cache hit is
charged at full price and the budget over-counts (stopping runs early and
hiding the savings).
"""

from fuzzingbrain.llms.client import _calculate_cost

# A model with known per-million prices keeps the math exact.
ANTHROPIC = "claude-sonnet-4-6"
OPENAI = "gpt-4o"


def _input_cost(model, total, read=0, create=0):
    ci, _, _ = _calculate_cost(model, total, 0, read, create)
    return ci


def test_no_cache_matches_full_price():
    # With no cache tokens the result equals the plain full-price formula.
    full = _input_cost(ANTHROPIC, 1000)
    assert full > 0
    # Equivalent: all-regular input.
    assert _input_cost(ANTHROPIC, 1000, read=0, create=0) == full


def test_cache_read_is_cheaper_than_full_price():
    full = _input_cost(ANTHROPIC, 1000)
    # All 1000 input tokens were a cache hit -> billed at 0.1x.
    cached = _input_cost(ANTHROPIC, 1000, read=1000)
    assert cached < full
    # Anthropic cache read is 0.1x.
    assert abs(cached - full * 0.1) < 1e-12


def test_anthropic_cache_creation_is_premium():
    full = _input_cost(ANTHROPIC, 1000)
    created = _input_cost(ANTHROPIC, 1000, create=1000)
    # Cache writes cost 1.25x on Anthropic.
    assert abs(created - full * 1.25) < 1e-12


def test_openai_cached_input_half_price():
    full = _input_cost(OPENAI, 1000)
    cached = _input_cost(OPENAI, 1000, read=1000)
    assert abs(cached - full * 0.5) < 1e-12


def test_parts_clamped_to_total():
    # Over-reported cache tokens must not produce negative regular input.
    cost = _input_cost(ANTHROPIC, 100, read=1000, create=1000)
    assert cost >= 0
