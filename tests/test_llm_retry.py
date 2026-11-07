# SPDX-License-Identifier: Apache-2.0
"""Transient-error retry is wired through to the provider calls.

litellm honors num_retries (exponential backoff + Retry-After); the OpenAI SDK
honors max_retries. Failed attempts have no usage, so retries never
double-charge. These tests pin the wiring so it can't silently regress to 0.
"""

import pytest

import fuzzingbrain.llms.client as client_mod
from fuzzingbrain.llms.client import LLMClient
from fuzzingbrain.llms.config import LLMConfig
from fuzzingbrain.llms.exceptions import LLMAllModelsFailedError

MSGS = [{"role": "user", "content": "x"}]


def test_default_max_retries_is_positive():
    assert LLMConfig().max_retries > 0


def test_num_retries_passed_to_litellm():
    client = LLMClient(LLMConfig(max_retries=3))
    params = client._prepare_call_params(MSGS, "claude-sonnet-4-5")
    assert params["num_retries"] == 3


def test_zero_retries_omits_param():
    client = LLMClient(LLMConfig(max_retries=0))
    params = client._prepare_call_params(MSGS, "claude-sonnet-4-5")
    assert "num_retries" not in params


def test_exhausted_models_give_up_after_max_rounds(monkeypatch):
    """With nothing left to try, the client retries a bounded number of
    rounds and then raises, instead of sleeping/clearing/recursing forever."""
    client = LLMClient(LLMConfig(max_fallback_attempts=2))

    sleeps = []
    monkeypatch.setattr(client_mod.time, "sleep", lambda s: sleeps.append(s))
    monkeypatch.setattr(client, "_next_models", lambda _m: [])

    with pytest.raises(LLMAllModelsFailedError):
        client._try_fallback(MSGS, failed_model="claude-sonnet-4-5", original_model=None)

    # One cooldown per retry round, capped at max_fallback_attempts.
    assert len(sleeps) == 2
