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
    def test_budget_from_json(self, tmp_path):
        p = tmp_path / "task.json"
        p.write_text(json.dumps({"budget_limit": 12.5}))
        cfg = Config.from_json(str(p))
        assert cfg.budget_limit == 12.5

    def test_budget_default_is_finite(self):
        # A sane non-zero default so an unconfigured run still has a ceiling.
        assert Config().budget_limit == 20.0

    def test_timeout_default(self):
        assert Config().timeout_minutes == 30


class TestPrebuiltGraphPlumbing:
    """The prebuilt graph directory must survive the analyzer process boundary."""

    def test_request_roundtrip_preserves_graph_and_binaries(self):
        req = AnalyzeRequest(
            task_id="t",
            task_path="p",
            project_name="x",
            sanitizers=["address"],
            prebuild_dir="/g",
            prebuilt_fuzzers={"address": {"fuzz": "/b/fuzz"}},
        )
        restored = AnalyzeRequest.from_dict(req.to_dict())
        assert restored.prebuild_dir == "/g"
        assert restored.prebuilt_fuzzers == {"address": {"fuzz": "/b/fuzz"}}


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
