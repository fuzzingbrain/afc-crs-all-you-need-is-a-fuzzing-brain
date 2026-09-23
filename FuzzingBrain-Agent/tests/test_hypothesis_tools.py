# SPDX-License-Identifier: Apache-2.0
"""Per-role tool sets and the HypothesisPool-bound runner: the whitelist each stage
exposes, and that create_hypothesis / update_hypothesis land on the board while everything
else falls through to the built-in tools."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent import hypothesis_tools  # noqa: E402
from fbagent.hypothesis import HypothesisPool  # noqa: E402


def _board(tmp_path):
    return HypothesisPool(tmp_path / ".fb" / "hypotheses.jsonl")


def test_role_whitelists():
    disc = {s["name"] for s in hypothesis_tools.build("discovery", None)[0]}
    ver = {s["name"] for s in hypothesis_tools.build("verify", None, vh_id="H01")[0]}
    rep = {s["name"] for s in hypothesis_tools.build("reproduce", None, vh_id="H01")[0]}
    assert "create_hypothesis" in disc and "trace" not in disc      # discovery: no dynamic tools
    assert "update_hypothesis" in ver and "trace" in ver
    assert "gates" in rep and "trace" in rep
    assert "create_hypothesis" not in rep and "update_hypothesis" not in rep


def test_create_hypothesis_writes_board(tmp_path):
    b = _board(tmp_path)
    schemas, run = hypothesis_tools.build("discovery", b, origin="discovery/llm",
                                    harness="h.cc", sanitizer="address")
    out, err = run("create_hypothesis", {"function": "foo",
                                   "description": "heap-buffer-overflow via memcpy",
                                   "important_controlflow": "foo: sink"})
    assert not err and "H01" in out and "heap-buffer-overflow" in out
    vh = b.all()[0]
    assert vh.function == "foo" and vh.origin == "discovery/llm" and vh.harness == "h.cc"


def test_update_hypothesis_writes_board(tmp_path):
    b = _board(tmp_path)
    vh = b.create(function="foo", description="overflow")
    _, run = hypothesis_tools.build("verify", b, vh_id=vh.id)
    out, err = run("update_hypothesis", {"score": 0.8, "evidence": "src/x.c:9 memcpy unchecked",
                                   "pov_guidance": "seed: 8 bytes"})
    assert not err and "0.8" in out
    got = b.get(vh.id)
    assert got.score == 0.8 and "memcpy" in got.evidence


def test_update_hypothesis_without_scope_errors(tmp_path):
    b = _board(tmp_path)
    _, run = hypothesis_tools.build("verify", b, vh_id=None)
    out, err = run("update_hypothesis", {"score": 0.5, "evidence": "x"})
    assert err and "no VulnHypothesis in scope" in out


def test_builtin_falls_through(tmp_path, monkeypatch):
    b = _board(tmp_path)
    from fbagent import tools as T
    monkeypatch.setattr(T, "run_tool", lambda n, a: (f"ran {n}", False))
    _, run = hypothesis_tools.build("reproduce", b, vh_id="H01")
    out, err = run("read", {"path": "harness/x.c"})
    assert not err and out == "ran read"
