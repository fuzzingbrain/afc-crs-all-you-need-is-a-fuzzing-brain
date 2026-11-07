# SPDX-License-Identifier: Apache-2.0
"""Ctrl+C / SIGTERM on a run: it is recorded as cancelled and result.json is written."""
import json

import pytest

from fuzzingbrain import main as fb_main


class _Store:
    def __init__(self):
        self.ended = None

    def end_open_workers(self, run_id, status):
        return 1

    def end_running_agents(self, run_id=None, status="cancelled"):
        return 2

    def end_pending_attempts(self, run_id):
        return 0

    def end_run(self, run_id, status, end_reason=None, error=None):
        self.ended = (run_id, status)
        return True

    def run_summary(self, run_id):
        return {"cost": 1.5, "workers": [{"id": "w1", "status": "cancelled"}]}

    def crashes(self, run_id):
        return []


def test_signal_handler_writes_cancelled_result(tmp_path, monkeypatch):
    store = _Store()
    monkeypatch.setattr(fb_main, "_store", store)
    monkeypatch.setattr(fb_main, "_current_run_id", "run-1")
    monkeypatch.setattr(fb_main, "_current_out", tmp_path)
    monkeypatch.setattr(fb_main, "_shutdown_requested", False)
    monkeypatch.setattr(fb_main, "reset_terminal", lambda: None)
    monkeypatch.setattr("fuzzingbrain.core.logging.print_run_summary", lambda *a, **k: None)

    with pytest.raises(SystemExit) as exc:
        fb_main.signal_handler(15, None)
    assert exc.value.code == 0
    assert store.ended == ("run-1", "cancelled")
    doc = json.loads((tmp_path / "result.json").read_text())
    assert doc["run_id"] == "run-1"
    assert doc["status"] == "cancelled"
    assert doc["end_reason"] is None
    assert doc["cost"] == 1.5
    assert doc["workers"] == [{"id": "w1", "status": "cancelled"}]
