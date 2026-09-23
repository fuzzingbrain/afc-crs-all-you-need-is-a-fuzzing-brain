# SPDX-License-Identifier: Apache-2.0
"""The .fb/ run store (design §0 directory layout): sessions, candidates,
crashes/<sig>/, ledger.jsonl. Pins that a reproduction crash actually writes
them, and that FPF ordering steers to the farthest VulnHypothesis from a solved fault."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent import controller, roles, store  # noqa: E402
from fbagent.hypothesis import PENDING_POV, HypothesisPool  # noqa: E402
from tests.test_roles_reproduce import CRASH_VERDICT, _FakeLLM, _done, _tool_use  # noqa: E402


def test_store_primitives(tmp_path):
    # candidate: copies an existing file into .fb/candidates/
    src = tmp_path / "x.bin"; src.write_bytes(b"\xc3")
    dst = store.save_candidate(tmp_path, "H01", 1, str(src))
    assert dst.endswith(".fb/candidates/H01-1.bin") and Path(dst).read_bytes() == b"\xc3"
    # crash: writes input.bin + stderr.txt + meta.json under a slugged sig dir
    d = store.save_crash(tmp_path, "heap-buffer-overflow|foo@x.c:1", str(src), "boom", "H01")
    assert (Path(d) / "input.bin").read_bytes() == b"\xc3"
    assert (Path(d) / "stderr.txt").read_text() == "boom"
    assert json.loads((Path(d) / "meta.json").read_text())["vh"] == "H01"
    # ledger: append-only jsonl
    store.ledger_append(tmp_path, {"stage": "reproduce", "vh": "H01"})
    store.ledger_append(tmp_path, {"stage": "verify", "vh": "H02"})
    lines = (tmp_path / ".fb" / "ledger.jsonl").read_text().splitlines()
    assert len(lines) == 2 and json.loads(lines[0])["vh"] == "H01"


def test_reproduction_writes_fb_artifacts(tmp_path, monkeypatch):
    # a real crashing candidate file on disk so save_candidate/save_crash copy it
    pov = tmp_path / "pov.bin"; pov.write_bytes(b"\xc3")
    from fbagent import tools as T
    monkeypatch.setattr(T, "run_tool",
                        lambda n, a: (CRASH_VERDICT, False) if "./submit" in a.get("command", "")
                        else ("ok", False))
    monkeypatch.setattr(roles, "harness_source", lambda ws, **k: "(harness)")
    b = HypothesisPool(tmp_path / ".fb" / "hypotheses.jsonl")
    vh = b.create(function="cupsUTF8ToCharset", description="heap-buffer-overflow",
                    harness="harness/h.cc")
    b.set_status(vh.id, "generating_pov")
    llm = _FakeLLM([
        _tool_use("r2", "bash", {"command": f"./submit {pov}"}),
        _done("ASSESSMENT COMPLETE"),
    ])
    roles.run_reproduction(vh, llm=llm, board=b, workspace=str(tmp_path))
    fb = tmp_path / ".fb"
    assert list((fb / "sessions").glob("reproduce-*.jsonl"))     # session archived
    assert list((fb / "candidates").glob("*-1.bin"))             # PoV saved
    assert list((fb / "crashes").glob("*/input.bin"))            # crash archived
    assert (fb / "ledger.jsonl").is_file()
    got = b.get(vh.id)
    assert ".fb/candidates/" in got.best_candidate               # VulnHypothesis points at the stored PoV


# ---- FPF ordering ----------------------------------------------------------
class _FakeCtx:
    """Minimal call-graph context: only .cg.edges, which _undirected_adj reads."""
    def __init__(self, edges):
        self.cg = type("G", (), {"edges": edges})()


def test_fpf_picks_farthest_from_solved(tmp_path):
    b = HypothesisPool(tmp_path / "hypotheses.jsonl")
    # graph: entry -> a -> b -> c  (undirected distances from 'a': b=1, c=2)
    ctx = _FakeCtx({"entry": {"a"}, "a": {"b"}, "b": {"c"}, "c": set()})
    solved = b.create(function="a", description="overflow")
    b.record_crash(solved.id, "overflow|a@x:1")                  # 'a' is solved
    near = b.create(function="b", description="use-after-free"); b.set_status(near.id, PENDING_POV)
    far = b.create(function="c", description="double-free"); b.set_status(far.id, PENDING_POV)
    near.score = far.score = 0.5
    pick = controller._fpf_pick(b, ctx)
    assert pick.function == "c"                                  # farthest from solved 'a'


def test_fpf_falls_back_to_score_without_graph(tmp_path):
    b = HypothesisPool(tmp_path / "hypotheses.jsonl")
    lo = b.create(function="a", description="overflow"); b.set_status(lo.id, PENDING_POV)
    hi = b.create(function="b", description="use-after-free"); b.set_status(hi.id, PENDING_POV)
    b.update(lo.id, allowed=None, score=0.4)
    b.update(hi.id, allowed=None, score=0.9)
    assert controller._fpf_pick(b, None).function == "b"        # no graph -> score
