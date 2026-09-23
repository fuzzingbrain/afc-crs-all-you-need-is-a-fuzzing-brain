# SPDX-License-Identifier: Apache-2.0
"""End to end through the REAL controller and REAL three role functions, with a
faked LLM and simulated tools. Unlike test_controller (which stubs the stages),
this composes discovery -> verify -> reproduce for real and proves a cups-01-
shaped challenge flows to a banked crash. No network, no containers, no model.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent import controller, tools as T  # noqa: E402
from fbagent.hypothesis import POV_GENERATED  # noqa: E402
from tests.test_roles_reproduce import CRASH_VERDICT, _Resp, _Blk  # noqa: E402


def _tool_use(cid, name, inp):
    return _Resp([_Blk(type="tool_use", id=cid, name=name, input=inp)], "tool_use")


def _done(text):
    return _Resp([_Blk(type="text", text=text)], "end_turn")


class _StageLLM:
    """One fake model that plays a different script per stage, chosen from the
    system prompt (discovery / verify / reproduce), so the real controller can
    drive the real role functions."""

    def __init__(self):
        self.model = "fake"; self.effort = "high"; self.reasoning = False
        self.provider = "anthropic"; self.context_window = 200_000
        self.served_model = None; self.last_prompt_tokens = 0
        self.usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
        self.max_tokens = 32000; self.cost_usd = 0.0; self.cache_hit_rate = 0.0
        self._iters = {}

    def call(self, system, messages, tools):
        if "record suspicious points" in system or "hypotheses" in system:
            stage = "discovery"
        elif "verifying one bug hypothesis" in system or "record your verdict" in system:
            stage = "verify"
        else:
            stage = "reproduce"
        scripts = {
            "discovery": [
                _tool_use("d1", "grep", {"pattern": "memcpy"}),
                _tool_use("d2", "create_hypothesis", {"function": "cupsUTF8ToCharset",
                          "description": "heap-buffer-overflow: reads a 2nd UTF-8 byte past the buffer",
                          "important_controlflow": "cupsUTF8ToCharset: sink"}),
                _done("ASSESSMENT COMPLETE"),
            ],
            "verify": [
                _tool_use("v1", "update_hypothesis", {"score": 0.9,
                          "evidence": "transcode.c:245 reads src[1] with no bound",
                          "pov_guidance": "seed: one 0xC3 byte"}),
                _done("ASSESSMENT COMPLETE"),
            ],
            "reproduce": [
                _tool_use("r1", "bash", {"command": "printf '\\xc3' > /tmp/pov.bin"}),
                _tool_use("r2", "bash", {"command": "./submit /tmp/pov.bin"}),
                _done("ASSESSMENT COMPLETE — crashed"),
            ],
        }
        it = self._iters.setdefault(stage, iter(scripts[stage]))
        # exhausted (e.g. a second discovery round with nothing new) -> just stop
        return next(it, _done("ASSESSMENT COMPLETE"))


def test_pipeline_reaches_a_banked_crash(tmp_path, monkeypatch):
    (tmp_path / "harness").mkdir()
    (tmp_path / "harness" / "h.cc").write_text(
        "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){"
        "cupsUTF8ToCharset(dest,(char*)d,2048,1);return 0;}")
    (tmp_path / "bench.yaml").write_text(
        "bug_id: cups-01\nlanguage: c\nharness:\n  sanitizer: asan\n"
        "  engine: libfuzzer\n  invocation: ['@@']\n")

    def fake_tool(name, args):
        if name == "bash" and "./submit" in args.get("command", ""):
            return (CRASH_VERDICT, False)
        if name == "bash":
            return ("ok", False)
        return ("source line", False)
    monkeypatch.setattr(T, "run_tool", fake_tool)

    out = controller.run_task(llm=_StageLLM(), workspace=str(tmp_path), max_usd=20.0)

    assert out["sanitizer"] == "address"
    assert out["solved"] == 1
    assert out["signatures"] == ["heap-buffer-overflow|cupsUTF8ToCharset@transcode.c:245"]
    stages = [e["stage"] for e in out["log"]]
    # discovery -> verify -> reproduce in order; after the crash the pool drains
    # and the controller re-runs discovery for a DISTINCT fault (finds none here
    # -> stops), so a trailing discovery round is expected (the diversity drive).
    assert stages[:3] == ["discovery", "verify", "reproduce"]
    assert all(s == "discovery" for s in stages[3:])
    # the VulnHypothesis carries the whole trail: verdict, PoV, solved status
    from fbagent.hypothesis import HypothesisPool
    b = HypothesisPool(tmp_path / ".fb" / "hypotheses.jsonl")
    vh = b.all()[0]
    assert vh.status == POV_GENERATED and vh.score == 0.9
    assert vh.best_candidate == "/tmp/pov.bin" and vh.signature
