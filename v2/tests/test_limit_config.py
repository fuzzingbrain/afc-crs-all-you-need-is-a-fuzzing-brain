# SPDX-License-Identifier: Apache-2.0
"""Plumbing tests for the abuse-prevention limits and the static-analysis flag.

The enforcement of budget/timeout lives in the dispatcher loop and is covered
by test_stopping_conditions.py. These tests cover the other half: that the
configured *values* actually reach config / cross the analyzer process
boundary, so a set limit is never silently dropped.
"""

import json

from fuzzingbrain.core.config import Config
from fuzzingbrain.analyzer.models import AnalyzeRequest


class TestBudgetPlumbing:
    def test_budget_from_env(self, monkeypatch):
        monkeypatch.setenv("FUZZINGBRAIN_BUDGET_LIMIT", "20")
        cfg = Config.from_env()
        assert cfg.budget_limit == 20.0

    def test_budget_from_json(self, tmp_path):
        p = tmp_path / "task.json"
        p.write_text(json.dumps({"budget_limit": 12.5}))
        cfg = Config.from_json(str(p))
        assert cfg.budget_limit == 12.5

    def test_budget_default_is_finite(self):
        # A sane non-zero default so an unconfigured run still has a ceiling.
        assert Config().budget_limit > 0

    def test_timeout_from_env(self, monkeypatch):
        monkeypatch.setenv("FUZZINGBRAIN_TIMEOUT", "5")
        cfg = Config.from_env()
        assert cfg.timeout_minutes == 5


class TestStaticAnalysisFlagPlumbing:
    """The introspector opt-in flag must survive the analyzer process boundary."""

    def test_default_off(self):
        assert Config().enable_static_analysis is False
        assert (
            AnalyzeRequest(
                task_id="t", task_path="p", project_name="x", sanitizers=["address"]
            ).enable_static_analysis
            is False
        )

    def test_env_can_enable(self, monkeypatch):
        monkeypatch.setenv("FUZZINGBRAIN_ENABLE_STATIC_ANALYSIS", "true")
        assert Config.from_env().enable_static_analysis is True

    def test_request_roundtrip_preserves_flag(self):
        req = AnalyzeRequest(
            task_id="t",
            task_path="p",
            project_name="x",
            sanitizers=["address"],
            enable_static_analysis=True,
        )
        restored = AnalyzeRequest.from_dict(req.to_dict())
        assert restored.enable_static_analysis is True


class TestPerCallTimeout:
    """Every LLM call must carry a finite timeout so no single call hangs."""

    def test_default_llm_timeout_is_finite(self):
        from fuzzingbrain.llms.config import LLMConfig

        cfg = LLMConfig()
        assert 0 < cfg.timeout < float("inf")
        assert 0 < cfg.connect_timeout < float("inf")

    def test_prepared_params_always_set_timeout(self):
        from fuzzingbrain.llms.config import LLMConfig
        from fuzzingbrain.llms.client import LLMClient

        client = LLMClient(LLMConfig())
        params = client._prepare_call_params([{"role": "user", "content": "hi"}], None)
        assert params["timeout"] == LLMConfig().timeout
