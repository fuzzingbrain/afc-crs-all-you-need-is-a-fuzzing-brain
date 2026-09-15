# SPDX-License-Identifier: Apache-2.0
"""The live progress log: one flushed line per step, and it never breaks a run."""

import json
import importlib

import pytest


@pytest.fixture
def prog(tmp_path, monkeypatch):
    monkeypatch.setenv("FBAGENT_PROGRESS", str(tmp_path / "p.jsonl"))
    from fbagent import progress
    importlib.reload(progress)
    return progress, tmp_path / "p.jsonl"


def _lines(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def test_start_writes_a_header_immediately(prog):
    progress, path = prog
    assert progress.start("sess", {"model": "claude-haiku-4-5"}) == str(path)
    assert _lines(path)[0]["kind"] == "start"
    assert _lines(path)[0]["model"] == "claude-haiku-4-5"


def test_every_step_is_readable_before_the_run_ends(prog):
    """The whole point: the file is complete-so-far while the agent is alive."""
    progress, path = prog
    progress.start("sess", {})
    progress.step(1, 0.10, ["bash"], ["clean: no fault | target ran 0 ms | 40 bytes"])
    progress.step(2, 0.21, ["read", "bash"], ["crash: abrt|f|g"])
    recs = _lines(path)
    assert [r["kind"] for r in recs] == ["start", "step", "step"]
    assert recs[1]["verdicts"][0].startswith("clean:")
    assert recs[2]["verdicts"][0].startswith("crash:")
    assert recs[2]["tools"] == ["read", "bash"]


def test_finish_records_the_outcome(prog):
    progress, path = prog
    progress.start("sess", {})
    progress.finish("end_turn", 142, 1.2046)
    end = _lines(path)[-1]
    assert end["kind"] == "end" and end["stop_reason"] == "end_turn"
    assert end["steps"] == 142 and end["usd"] == 1.2046


def test_it_can_be_switched_off(tmp_path, monkeypatch):
    monkeypatch.setenv("FBAGENT_PROGRESS", "0")
    from fbagent import progress
    importlib.reload(progress)
    assert progress.start("sess", {}) is None
    progress.step(1, 0.1, ["bash"], [])   # must not raise
    assert progress.path() is None


def test_a_broken_destination_never_takes_the_run_down(monkeypatch):
    monkeypatch.setenv("FBAGENT_PROGRESS", "/proc/definitely/not/writable.jsonl")
    from fbagent import progress
    importlib.reload(progress)
    assert progress.start("sess", {}) is None
    progress.step(1, 0.1, ["bash"], [])
    progress.finish("end_turn", 1, 0.1)
