# SPDX-License-Identifier: Apache-2.0
"""Per-role tool sets and the LeadBoard-bound runner: the whitelist each stage
exposes, and that create_lead / update_lead land on the board while everything
else falls through to the built-in tools."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent import lead_tools  # noqa: E402
from fbagent.lead import LeadBoard  # noqa: E402


def _board(tmp_path):
    return LeadBoard(tmp_path / ".fb" / "leads.jsonl")


def test_role_whitelists():
    disc = {s["name"] for s in lead_tools.build("discovery", None)[0]}
    ver = {s["name"] for s in lead_tools.build("verify", None, lead_id="L01")[0]}
    rep = {s["name"] for s in lead_tools.build("reproduce", None, lead_id="L01")[0]}
    assert "create_lead" in disc and "trace" not in disc      # discovery: no dynamic tools
    assert "update_lead" in ver and "trace" in ver
    assert "gates" in rep and "trace" in rep
    assert "create_lead" not in rep and "update_lead" not in rep


def test_create_lead_writes_board(tmp_path):
    b = _board(tmp_path)
    schemas, run = lead_tools.build("discovery", b, origin="discovery/llm",
                                    harness="h.cc", sanitizer="address")
    out, err = run("create_lead", {"function": "foo",
                                   "description": "heap-buffer-overflow via memcpy",
                                   "important_controlflow": "foo: sink"})
    assert not err and "L01" in out and "heap-buffer-overflow" in out
    lead = b.all()[0]
    assert lead.function == "foo" and lead.origin == "discovery/llm" and lead.harness == "h.cc"


def test_update_lead_writes_board(tmp_path):
    b = _board(tmp_path)
    lead = b.create(function="foo", description="overflow")
    _, run = lead_tools.build("verify", b, lead_id=lead.id)
    out, err = run("update_lead", {"score": 0.8, "evidence": "src/x.c:9 memcpy unchecked",
                                   "pov_guidance": "seed: 8 bytes"})
    assert not err and "0.8" in out
    got = b.get(lead.id)
    assert got.score == 0.8 and "memcpy" in got.evidence


def test_update_lead_without_scope_errors(tmp_path):
    b = _board(tmp_path)
    _, run = lead_tools.build("verify", b, lead_id=None)
    out, err = run("update_lead", {"score": 0.5, "evidence": "x"})
    assert err and "no Lead in scope" in out


def test_builtin_falls_through(tmp_path, monkeypatch):
    b = _board(tmp_path)
    from fbagent import tools as T
    monkeypatch.setattr(T, "run_tool", lambda n, a: (f"ran {n}", False))
    _, run = lead_tools.build("reproduce", b, lead_id="L01")
    out, err = run("read", {"path": "harness/x.c"})
    assert not err and out == "ran read"
