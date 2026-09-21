# SPDX-License-Identifier: Apache-2.0
"""Context compaction + the progress note — the two things that let a long run
survive a small context window (Haiku 200k) instead of dying with a 400."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent.agent import Agent, _is_tool_result_turn, _is_context_overflow, _ELIDED_PREFIX
from fbagent.llm import LLM, context_window


def _agent(model="claude-haiku-4-5", n_turns=300, body_chars=4000):
    llm = LLM.__new__(LLM)
    llm.model = model
    llm.context_window = context_window(model)
    llm.last_prompt_tokens = 0
    llm.usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    a = Agent.__new__(Agent)
    a.system = "SYS " * 2000
    a.llm = llm
    a._tokens_per_char = 0.25
    a.compactions = 0
    a.max_usd = 20.0
    a.deadline = None
    a._deadline_total_s = 0
    a.steps = 0
    a.messages = [{"role": "user", "content": "OPENING pinned"}]
    big = "X" * body_chars
    for i in range(n_turns):
        a.messages.append({"role": "assistant",
                           "content": [{"type": "text", "text": f"step {i}"}]})
        a.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "content": big}]})
    return a, big


def test_context_window_lookup():
    assert context_window("claude-haiku-4-5") == 200_000
    assert context_window("claude-opus-4-8") == 1_000_000
    assert context_window("claude-opus-5") == 1_000_000
    assert context_window("something-unknown") == 200_000  # conservative default


def test_compaction_brings_estimate_under_target():
    a, _ = _agent()
    win = a.llm.context_window
    assert a._estimate_tokens() > win           # starts overflowing
    a._compact_to_fit()
    target = min(0.85 * win, win - 24_000)
    assert a._estimate_tokens() <= target
    assert a.compactions == 1


def test_recent_turns_and_opening_preserved():
    a, big = _agent()
    a._compact_to_fit()
    tool_turns = [m for m in a.messages if _is_tool_result_turn(m)]
    for m in tool_turns[-4:]:                    # newest 4 kept whole
        assert m["content"][0]["content"] == big
    assert a.messages[0]["content"] == "OPENING pinned"   # pinned string turn


def test_pairing_id_preserved_and_idempotent():
    a, _ = _agent()
    a._compact_to_fit()
    old = [m for m in a.messages if _is_tool_result_turn(m)][0]
    assert old["content"][0]["content"].startswith(_ELIDED_PREFIX)
    assert old["content"][0]["tool_use_id"] == "t0"        # id kept -> pairing valid
    assert a._compact_history(keep_recent=4, large_chars=1500) == 0   # idempotent


def test_large_window_model_does_not_compact():
    a, _ = _agent(model="claude-opus-4-8", n_turns=100)
    assert a._estimate_tokens() < a.llm.context_window
    assert a._compact_to_fit() == 0


def test_progress_note_cadence():
    a, _ = _agent()
    a.llm.usage = a.llm.usage
    a.steps = 30
    assert a._progress_note() is not None        # every 30 steps
    a.steps = 31
    assert a._progress_note() is None            # not other steps


def test_context_overflow_detection():
    assert _is_context_overflow(Exception("prompt is too long: 210000 tokens"))
    assert _is_context_overflow(Exception("context_length_exceeded"))
    assert not _is_context_overflow(Exception("rate limit"))


def _agent_asst(n_turns=300, script_chars=4000, prose_chars=4000):
    """A run whose bulk is the model's OWN output (bash scripts + prose); tool
    results are tiny, so only assistant compaction can bring it under the window."""
    llm = LLM.__new__(LLM)
    llm.model = "claude-haiku-4-5"
    llm.context_window = context_window("claude-haiku-4-5")
    llm.last_prompt_tokens = 0
    llm.usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    a = Agent.__new__(Agent)
    a.system = "S" * 500
    a.llm = llm
    a._tokens_per_char = 0.25
    a.compactions = 0
    a.max_usd = 20.0
    a.deadline = None
    a._deadline_total_s = 0
    a.steps = n_turns
    a.messages = [{"role": "user", "content": "OPENING"}]
    script = "x=1\n" * (script_chars // 4)
    prose = "I will analyze this now. " * (prose_chars // 25)
    for i in range(n_turns):
        a.messages.append({"role": "assistant", "content": [
            {"type": "text", "text": prose},
            {"type": "tool_use", "id": f"t{i}", "name": "bash",
             "input": {"command": script}}]})
        a.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "content": "ok"}]})
    return a


def test_assistant_compaction_fits_when_output_is_the_bulk():
    a = _agent_asst()
    win = a.llm.context_window
    assert a._estimate_tokens() > win          # own output overflows
    a._compact_to_fit()
    assert a._estimate_tokens() <= min(0.85 * win, win - 24_000)


def test_assistant_compaction_keeps_ids_and_recent_and_thinking():
    a = _agent_asst()
    # a thinking block in an OLD turn must survive verbatim (reasoning models)
    a.messages[1]["content"].insert(0, {"type": "thinking", "thinking": "T" * 5000, "signature": "s"})
    a._compact_to_fit()
    at = [m for m in a.messages if m["role"] == "assistant"]
    # newest 2 assistant turns kept whole
    for m in at[-2:]:
        for b in m["content"]:
            if b.get("type") == "tool_use":
                assert "__elided__" not in str(b["input"])
    # old bash args elided, id kept -> pairing valid
    old_tu = [b for b in at[0]["content"] if b.get("type") == "tool_use"][0]
    assert "__elided__" in str(old_tu["input"]) and old_tu["id"] == "t0"
    # thinking block never touched
    think = [b for m in at for b in m["content"] if b.get("type") == "thinking"]
    assert think and think[0]["thinking"] == "T" * 5000


def test_assistant_compaction_idempotent():
    a = _agent_asst()
    a._compact_assistant_history(keep_recent=2, large_chars=1500)
    assert a._compact_assistant_history(keep_recent=2, large_chars=1500) == 0


# --- truncation handling: max_tokens is a cut-off, not a voluntary stop --------

class _Resp:
    def __init__(self, reason, blocks=None):
        self.stop_reason = reason
        self.content = blocks or [type("B", (), {"type": "text", "text": "..."})()]


def _fake_llm(seq):
    llm = LLM.__new__(LLM)
    llm.model = "claude-haiku-4-5"
    llm.context_window = context_window("claude-haiku-4-5")
    llm.usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    llm.last_prompt_tokens = 100
    llm.served_model = None
    it = iter(seq)
    llm.call = lambda s, m, t: next(it)
    type(llm).cost_usd = property(lambda self: 0.5)   # always under any cap
    return llm


def _run(seq):
    a = Agent("sys", llm=_fake_llm(seq), max_usd=10, min_spend_fraction=0.0, deadline_s=3600)
    return a.run("go")


def test_max_tokens_continues_then_stops_on_end_turn():
    r = _run([_Resp("max_tokens"), _Resp("max_tokens"), _Resp("end_turn")])
    assert r["stop_reason"] == "end_turn"
    assert r["forced_continuations"] == 2   # both truncations were continued, not stopped


def test_repeated_truncation_is_capped():
    from fbagent.agent import _MAX_CONSECUTIVE_TRUNC
    r = _run([_Resp("max_tokens")] * 50)
    assert "repeated truncation" in r["stop_reason"]
    assert r["steps"] <= _MAX_CONSECUTIVE_TRUNC + 2   # bounded, not infinite


def test_tool_use_turn_resets_truncation_counter(monkeypatch):
    import fbagent.tools as T
    monkeypatch.setattr(T, "run_tool", lambda n, a: ("ok", False))
    tool = _Resp("tool_use", [type("B", (), {"type": "tool_use", "id": "t",
                                             "name": "read", "input": {"path": "x"}})()])
    # 2 truncations, a real tool turn, 2 more truncations: never 3-in-a-row, so no give-up
    r = _run([_Resp("max_tokens"), _Resp("max_tokens"), tool,
              _Resp("max_tokens"), _Resp("max_tokens"), _Resp("end_turn")])
    assert r["stop_reason"] == "end_turn"
