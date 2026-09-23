# SPDX-License-Identifier: Apache-2.0
"""The verification role: records a verdict via update_hypothesis, applies recall-first
when the agent records none, and banks a submit-backed crash it stumbled into
(skipping reproduction). LLM faked; no network."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent import roles  # noqa: E402
from fbagent.hypothesis import POV_GENERATED, HypothesisPool  # noqa: E402
from tests.test_roles_reproduce import CRASH_VERDICT, _FakeLLM, _done, _tool_use  # noqa: E402


def _board(tmp_path):
    return HypothesisPool(tmp_path / ".fb" / "hypotheses.jsonl")


def test_verify_records_score_and_evidence(tmp_path, monkeypatch):
    from fbagent import tools as T
    monkeypatch.setattr(T, "run_tool", lambda n, a: ("read ok", False))
    monkeypatch.setattr(roles, "harness_source", lambda ws, **k: "(harness)")
    b = _board(tmp_path)
    vh = b.create(function="foo", description="heap-buffer-overflow", harness="h.cc")
    llm = _FakeLLM([
        _tool_use("v1", "update_hypothesis", {"score": 0.8, "evidence": "src/x.c:9 unchecked len",
                                        "pov_guidance": "seed: 8 bytes"}),
        _done("ASSESSMENT COMPLETE"),
    ])
    out = roles.run_verification(vh, llm=llm, board=b, workspace=str(tmp_path))
    assert out["crashed"] is False and out["score"] == 0.8
    got = b.get(vh.id)
    assert got.score == 0.8 and "unchecked len" in got.evidence


def test_verify_recall_first_when_no_verdict(tmp_path, monkeypatch):
    from fbagent import tools as T
    monkeypatch.setattr(T, "run_tool", lambda n, a: ("read ok", False))
    monkeypatch.setattr(roles, "harness_source", lambda ws, **k: "(harness)")
    b = _board(tmp_path)
    vh = b.create(function="foo", description="use-after-free")
    llm = _FakeLLM([_done("ASSESSMENT COMPLETE — ran out of time, no verdict")])
    out = roles.run_verification(vh, llm=llm, board=b, workspace=str(tmp_path))
    # recall-first: a VulnHypothesis with no recorded verdict proceeds, not dropped
    assert out["score"] == 0.5
    assert "recall-first" in b.get(vh.id).evidence


def test_verify_banks_stumbled_crash(tmp_path, monkeypatch):
    from fbagent import tools as T
    monkeypatch.setattr(T, "run_tool",
                        lambda n, a: (CRASH_VERDICT, False) if "./submit" in a.get("command", "")
                        else ("ok", False))
    monkeypatch.setattr(roles, "harness_source", lambda ws, **k: "(harness)")
    b = _board(tmp_path)
    vh = b.create(function="cupsUTF8ToCharset", description="heap-buffer-overflow", harness="h.cc")
    llm = _FakeLLM([
        _tool_use("v1", "bash", {"command": "./submit /tmp/x"}),
        _done("ASSESSMENT COMPLETE — it crashed"),
    ])
    out = roles.run_verification(vh, llm=llm, board=b, workspace=str(tmp_path))
    assert out["crashed"] is True and out["score"] == 1.0
    got = b.get(vh.id)
    assert got.status == POV_GENERATED and "cupsUTF8ToCharset" in got.signature
