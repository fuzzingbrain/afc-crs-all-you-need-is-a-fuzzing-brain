# SPDX-License-Identifier: Apache-2.0
"""The controller loop: orchestration only. The three stages are stubbed to
manipulate the board deterministically, so this pins the wiring — discovery
fills, verify gates at 0.5, reproduce runs the best Lead, crashes bank, failures
retry up to MAX_ATTEMPTS, and the loop stops on no-leads / budget — without any
model. bench.yaml parsing is checked against a real file."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent import controller, roles  # noqa: E402
from fbagent.lead import (FAILED, PENDING_POV, POV_GENERATED, REJECTED,  # noqa: E402
                          LeadBoard)


class _LLM:
    cost_usd = 0.0


def _mk_bench(tmp_path):
    (tmp_path / "harness").mkdir()
    (tmp_path / "harness" / "h.cc").write_text("int LLVMFuzzerTestOneInput(){}")
    (tmp_path / "bench.yaml").write_text(
        "bug_id: cups-01\nproject: cups\nlanguage: c\n"
        "harness:\n  sanitizer: asan\n  engine: libfuzzer\n  invocation: ['@@']\n")


def test_read_bench(tmp_path):
    _mk_bench(tmp_path)
    harness, san = controller._read_bench(tmp_path)
    assert harness == "harness/h.cc" and san == "address"


def test_full_loop_solves_and_gates(tmp_path, monkeypatch):
    _mk_bench(tmp_path)
    b = LeadBoard(tmp_path / ".fb" / "leads.jsonl")

    # discovery: create three Leads
    def disc(*, llm, board, workspace, harness, sanitizer, deadline_s, max_usd):
        board.create(function="good", description="heap-buffer-overflow", harness=harness)
        board.create(function="weak", description="use-after-free", harness=harness)
        board.create(function="fp", description="out-of-bounds", harness=harness)
        return {"created": ["L01", "L02", "L03"], "n": 3, "stop_reason": "end", "steps": 1}

    # verify: 'good' high, 'weak' mid (both proceed), 'fp' below gate -> rejected
    scores = {"good": 0.9, "weak": 0.6, "fp": 0.2}
    def ver(lead, *, llm, board, workspace, deadline_s, max_usd, harness_names=None):
        s = scores[lead.function]
        board.update(lead.id, allowed=None, score=s, evidence="x")
        return {"lead": lead.id, "crashed": False, "score": s, "stop_reason": "end"}

    # reproduce: 'good' crashes; 'weak' never does (will retry to FAILED)
    def rep(lead, *, llm, board, workspace, deadline_s, max_usd, harness_names=None):
        if lead.function == "good":
            board.record_crash(lead.id, "heap-buffer-overflow|good@x.c:1", candidate="/tmp/g")
            return {"lead": lead.id, "crashed": True, "signature": "heap-buffer-overflow|good@x.c:1"}
        board.update(lead.id, allowed=None, attempts=lead.attempts + 1, deepest_reached="mid")
        return {"lead": lead.id, "crashed": False, "deepest_reached": "mid"}

    monkeypatch.setattr(roles, "run_discovery", disc)
    monkeypatch.setattr(roles, "run_verification", ver)
    monkeypatch.setattr(roles, "run_reproduction", rep)

    out = controller.run_task(llm=_LLM(), workspace=str(tmp_path), board=b)
    assert out["solved"] == 1 and out["signatures"] == ["heap-buffer-overflow|good@x.c:1"]
    assert b.get("L01").status == POV_GENERATED
    assert b.get("L03").status == REJECTED          # fp gated out at 0.2
    assert b.get("L02").status == FAILED            # weak retried to MAX_ATTEMPTS
    assert b.get("L02").attempts == controller.MAX_ATTEMPTS
    assert out["stop"] == "no_leads_left"


def test_budget_stops_the_loop(tmp_path, monkeypatch):
    _mk_bench(tmp_path)
    b = LeadBoard(tmp_path / ".fb" / "leads.jsonl")

    class _Spender:
        cost_usd = 0.0

    llm = _Spender()

    def disc(**k):
        k["board"].create(function="a", description="overflow", harness="h.cc")
        k["board"].create(function="c", description="use-after-free", harness="h.cc")
        return {"created": [], "n": 2, "stop_reason": "end", "steps": 1}

    def ver(lead, **k):
        k["board"].update(lead.id, allowed=None, score=0.9, evidence="x")
        return {"lead": lead.id, "crashed": False, "score": 0.9, "stop_reason": "end"}

    def rep(lead, **k):
        llm.cost_usd += 10.0            # each attempt burns half the cap
        k["board"].update(lead.id, allowed=None, attempts=lead.attempts + 1)
        return {"lead": lead.id, "crashed": False, "deepest_reached": ""}

    monkeypatch.setattr(roles, "run_discovery", disc)
    monkeypatch.setattr(roles, "run_verification", ver)
    monkeypatch.setattr(roles, "run_reproduction", rep)

    out = controller.run_task(llm=llm, workspace=str(tmp_path), board=b, max_usd=20.0)
    assert out["stop"] == "budget"
    assert out["solved"] == 0
