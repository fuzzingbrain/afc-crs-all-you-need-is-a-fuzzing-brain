# SPDX-License-Identifier: Apache-2.0
"""The discovery role: the agent explores harness-reachable code and records
Leads via create_lead. LLM faked; pins that created Leads land on the board
with the right origin/harness and that the run reports what it made."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent import roles  # noqa: E402
from fbagent.lead import PENDING_VERIFY, LeadBoard  # noqa: E402
from fbagent.sanitizer_guidance import guidance_for  # noqa: E402
from tests.test_roles_reproduce import _FakeLLM, _done, _tool_use  # noqa: E402


def _board(tmp_path):
    return LeadBoard(tmp_path / ".fb" / "leads.jsonl")


def test_discovery_creates_leads(tmp_path, monkeypatch):
    from fbagent import tools as T
    monkeypatch.setattr(T, "run_tool", lambda n, a: ("source line", False))
    monkeypatch.setattr(roles, "harness_source", lambda ws, **k: "(harness)")
    b = _board(tmp_path)
    llm = _FakeLLM([
        _tool_use("d1", "grep", {"pattern": "memcpy"}),
        _tool_use("d2", "create_lead", {"function": "cupsUTF8ToCharset",
                  "description": "heap-buffer-overflow: reads a second UTF-8 byte past the end",
                  "important_controlflow": "cupsUTF8ToCharset: sink"}),
        _done("ASSESSMENT COMPLETE"),
    ])
    out = roles.run_discovery(llm=llm, board=b, workspace=str(tmp_path),
                              harness="harness/harness.cc", sanitizer="address")
    assert out["n"] == 1 and out["created"] == ["L01"]
    lead = b.get("L01")
    assert lead.function == "cupsUTF8ToCharset"
    assert lead.origin == "discovery/llm" and lead.harness == "harness/harness.cc"
    assert lead.status == PENDING_VERIFY


def test_discovery_dedups_within_run(tmp_path, monkeypatch):
    from fbagent import tools as T
    monkeypatch.setattr(T, "run_tool", lambda n, a: ("x", False))
    monkeypatch.setattr(roles, "harness_source", lambda ws, **k: "(harness)")
    b = _board(tmp_path)
    llm = _FakeLLM([
        _tool_use("d1", "create_lead", {"function": "foo", "description": "heap-buffer-overflow A"}),
        _tool_use("d2", "create_lead", {"function": "foo", "description": "another heap-buffer-overflow B"}),
        _done("ASSESSMENT COMPLETE"),
    ])
    out = roles.run_discovery(llm=llm, board=b, workspace=str(tmp_path),
                              harness="h.cc", sanitizer="address")
    assert out["n"] == 1                      # same (function, class) merged


def test_sanitizer_guidance_selects_asan_with_leaks():
    g = guidance_for("address")
    assert "AddressSanitizer" in g and "LeakSanitizer" in g
    assert "Undefined" not in g              # only the asan section
