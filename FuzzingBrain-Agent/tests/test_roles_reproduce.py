# SPDX-License-Identifier: Apache-2.0
"""The reproduction role: builds the Agent with the reproduce toolset, runs it,
and banks a submit-backed crash on the Lead or records the deepest point. The
LLM is faked (scripted turns), so no network — this pins the wiring and the
outcome scanner, not model behavior."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent import roles  # noqa: E402
from fbagent.lead import POV_GENERATED, LeadBoard  # noqa: E402


# ---- a fake LLM that plays scripted assistant turns ------------------------
class _Blk:
    def __init__(self, **k):
        self.__dict__.update(k)
        self.type = k.get("type")


class _Resp:
    def __init__(self, content, stop_reason):
        self.content = content
        self.stop_reason = stop_reason
        self.usage = _Blk(type=None, input_tokens=10, output_tokens=5,
                          cache_read_input_tokens=0, cache_creation_input_tokens=0)
        self.model = "fake"


class _FakeLLM:
    def __init__(self, turns):
        self._turns = iter(turns)
        self.model = "fake"; self.effort = "high"; self.reasoning = False
        self.provider = "anthropic"; self.context_window = 200_000
        self.served_model = None; self.last_prompt_tokens = 0
        self.usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
        self.max_tokens = 32000; self.cost_usd = 0.0; self.cache_hit_rate = 0.0

    def call(self, system, messages, tools):
        return next(self._turns)


def _tool_use(cid, name, inp):
    return _Resp([_Blk(type="tool_use", id=cid, name=name, input=inp)], "tool_use")


def _done(text):
    return _Resp([_Blk(type="text", text=text)], "end_turn")


CRASH_VERDICT = ("crash: the harness faulted under the sanitizer (heap-buffer-overflow).\n"
                 "stack (where it crashed):\n"
                 "  #0 cupsUTF8ToCharset  transcode.c:245\n"
                 "  #1 LLVMFuzzerTestOneInput  harness.cc:19\n")
CLEAN_VERDICT = ("clean: the harness ran to completion with no sanitizer fault. "
                 "This input reached no crash; change it to reach a different sink.")


def _board(tmp_path):
    return LeadBoard(tmp_path / ".fb" / "leads.jsonl")


def test_reproduction_banks_submit_crash(tmp_path, monkeypatch):
    # the built-in bash tool returns the crash verdict when the agent runs ./submit
    from fbagent import tools as T
    monkeypatch.setattr(T, "run_tool",
                        lambda n, a: (CRASH_VERDICT, False) if "./submit" in a.get("command", "")
                        else ("wrote candidate", False))
    monkeypatch.setattr(roles, "harness_source", lambda ws, **k: "(harness)")
    b = _board(tmp_path)
    lead = b.create(function="cupsUTF8ToCharset", description="heap-buffer-overflow",
                    harness="harness/harness.cc")
    b.set_status(lead.id, "generating_pov")
    llm = _FakeLLM([
        _tool_use("c1", "bash", {"command": "python3 -c \"open('/tmp/x','wb').write(b'\\xc3')\""}),
        _tool_use("c2", "bash", {"command": "./submit /tmp/x"}),
        _done("ASSESSMENT COMPLETE — crashed at cupsUTF8ToCharset"),
    ])
    out = roles.run_reproduction(lead, llm=llm, board=b, workspace=str(tmp_path))
    assert out["crashed"] is True
    assert "cupsUTF8ToCharset" in out["signature"]
    got = b.get(lead.id)
    assert got.status == POV_GENERATED and got.signature == out["signature"]
    assert got.best_candidate == "/tmp/x"


def test_reproduction_records_deepest_on_failure(tmp_path, monkeypatch):
    from fbagent import tools as T
    trace_out = ("outcome: no crash; the program gave up (longjmp)\n"
                 "deepest call: png_get_uint_31  (7 levels below the harness entry)\n")
    def fake(n, a):
        cmd = a.get("command", "")
        if "./submit" in cmd:
            return (CLEAN_VERDICT, False)
        return ("wrote candidate", False)
    monkeypatch.setattr(T, "run_tool", fake)
    monkeypatch.setattr(roles, "harness_source", lambda ws, **k: "(harness)")
    b = _board(tmp_path)
    lead = b.create(function="png_read_end", description="heap-buffer-overflow")
    b.set_status(lead.id, "generating_pov")
    llm = _FakeLLM([
        _tool_use("c1", "bash", {"command": "./submit /tmp/y"}),
        _tool_use("c2", "trace", {"input": "/tmp/y"}),
        _done("ASSESSMENT COMPLETE — could not crash; deepest png_get_uint_31"),
    ])
    # feed the trace verdict through the trace tool result
    def fake2(n, a):
        if n == "trace":
            return (trace_out, False)
        return fake(n, a)
    monkeypatch.setattr(T, "run_tool", fake2)
    out = roles.run_reproduction(lead, llm=llm, board=b, workspace=str(tmp_path))
    assert out["crashed"] is False
    assert "png_get_uint_31" in out["deepest_reached"]
    got = b.get(lead.id)
    assert got.attempts == 1 and "png_get_uint_31" in got.deepest_reached


def test_harness_source_reads_harness_dir(tmp_path):
    (tmp_path / "harness").mkdir()
    (tmp_path / "harness" / "h.cc").write_text("int LLVMFuzzerTestOneInput(){}")
    src = roles.harness_source(tmp_path)
    assert "harness/h.cc" in src and "LLVMFuzzerTestOneInput" in src
