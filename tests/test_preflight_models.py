# SPDX-License-Identifier: Apache-2.0
"""preflight check_models: exact ids, served aliases, unknown models."""
from types import SimpleNamespace

from fuzzingbrain.core import preflight


def _config(model):
    return SimpleNamespace(models={}, force_model=model, allow_fallback=False)


def _run(monkeypatch, model, served, aliases):
    monkeypatch.setattr(preflight, "_served_ids", lambda provider: set(served))
    monkeypatch.setattr(preflight, "_alias_target", lambda provider, mid: aliases.get(mid))
    r = preflight.Report()
    preflight.check_models(r, _config(model))
    assert len(r.checks) == 1
    return r.checks[0]


def test_listed_id_passes(monkeypatch):
    c = _run(monkeypatch, "claude-sonnet-4-5", {"claude-sonnet-4-5"}, {})
    assert c["ok"]


def test_alias_of_a_listed_dated_id_passes(monkeypatch):
    c = _run(monkeypatch, "claude-sonnet-4-5", {"claude-sonnet-4-5-20250929"},
             {"claude-sonnet-4-5": "claude-sonnet-4-5-20250929"})
    assert c["ok"]
    assert "claude-sonnet-4-5-20250929" in c["detail"]


def test_model_not_served_fails(monkeypatch):
    c = _run(monkeypatch, "claude-sonnet-4-5", {"claude-opus-5"}, {})
    assert not c["ok"]
    assert "not among" in c["detail"]


def test_model_list_error_fails(monkeypatch):
    def boom(provider):
        raise RuntimeError("HTTP 401 from anthropic model list")
    monkeypatch.setattr(preflight, "_served_ids", boom)
    r = preflight.Report()
    preflight.check_models(r, _config("claude-sonnet-4-5"))
    assert not r.checks[0]["ok"] and "401" in r.checks[0]["detail"]
