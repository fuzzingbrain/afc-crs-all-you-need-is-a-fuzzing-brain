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
