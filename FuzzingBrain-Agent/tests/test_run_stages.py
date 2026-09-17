# SPDX-License-Identifier: Apache-2.0
"""The three-stage entry point: arg parsing, calling the controller with a
shared LLM, and writing .fbbench/usage.json so the bench can cost the run.
controller + LLM are stubbed; no model, no network."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent import run_stages  # noqa: E402


def test_main_runs_controller_and_writes_usage(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["run_stages", "--timeout", "60",
                                      "--model", "claude-opus-5", "--max-usd", "20"])

    class _LLM:
        def __init__(self, model=None):
            self.model = "claude-opus-5"; self.provider = "anthropic"
            self.served_model = "claude-opus-5"; self.cost_usd = 1.23
            self.usage = {"input": 10, "output": 2, "cache_read": 5, "cache_write": 1}

    captured = {}

    def fake_run_task(*, llm, workspace, max_usd, deadline_s, discovery_frac):
        captured.update(max_usd=max_usd, deadline_s=deadline_s, ws=workspace)
        return {"harness": "harness/h.cc", "sanitizer": "address", "leads": 2,
                "solved": 1, "signatures": ["heap-buffer-overflow|foo@x.c:1"],
                "cost_usd": 1.23, "stop": "no_leads_left",
                "log": [{"stage": "discovery", "n": 2}, {"stage": "reproduce", "crashed": True}]}

    monkeypatch.setattr(run_stages, "LLM", _LLM)
    monkeypatch.setattr(run_stages.controller, "run_task", fake_run_task)

    rc = run_stages.main()
    assert rc == 0
    assert captured["max_usd"] == 20.0 and captured["deadline_s"] == 60
    usage = json.loads((tmp_path / ".fbbench" / "usage.json").read_text())
    assert usage["cost_usd"] == 1.23 and usage["solved"] == 1
    assert usage["usage"]["input"] == 10
    assert usage["signatures"] == ["heap-buffer-overflow|foo@x.c:1"]
