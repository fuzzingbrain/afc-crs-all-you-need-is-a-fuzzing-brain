"""Mechanical context compression: reversible tool-result eviction.

The one correctness-critical property is that eviction only rewrites tool-result
*content* and never removes a message, so every assistant tool_call keeps its
matching tool_result (an orphan is a hard API 400). These tests lock that down
deterministically, without running a real agent.
"""

import asyncio
import json
from pathlib import Path

from fuzzingbrain.agents.base import BaseAgent


class _StubAgent(BaseAgent):
    """Minimal concrete agent whose __init__ we bypass; we only exercise the
    compression methods, which touch a small, well-defined set of attributes."""

    @property
    def agent_name(self) -> str:
        return "stub"

    # abstract surface the ABC requires, unused by these tests
    @property
    def system_prompt(self) -> str:
        return "sys"

    def get_initial_message(self, **kwargs) -> str:
        return "init"


def _make_agent(tmp_path: Path, keep: int = 2) -> _StubAgent:
    a = object.__new__(_StubAgent)  # bypass __init__ / MCP wiring
    a.messages = []
    a._evict_seq = 0
    a._last_input_tokens = 0
    a._ledger = {}
    import uuid
    a._evict_token = uuid.uuid4().hex[:12]  # unique per instance (never id(self))
    a.enable_context_compression = True
    a.compress_keep_recent_tools = keep
    a.log_dir = tmp_path
    a._log = lambda *args, **kwargs: None  # silence
    return a


def _ledger_msg(msgs):
    for m in msgs:
        if m.get("role") == "user" and isinstance(m.get("content"), str) and m["content"].startswith("## LEDGER"):
            return m["content"]
    return None


def _asst(call_id, name, args="{}"):
    return {
        "role": "assistant",
        "content": "",
        "tool_calls": [{"id": call_id, "function": {"name": name, "arguments": args}}],
    }


def _asst_multi(calls):
    return {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {"id": cid, "function": {"name": n, "arguments": a}} for cid, n, a in calls
        ],
    }


def _tool(call_id, content):
    return {"role": "tool", "tool_call_id": call_id, "content": content}


def _pairs_valid(msgs) -> bool:
    """Every assistant tool_call id has exactly one matching tool result, and
    every tool result matches some tool_call (no orphans either way)."""
    call_ids = []
    for m in msgs:
        if m.get("role") == "assistant":
            for tc in m.get("tool_calls", []) or []:
                call_ids.append(tc["id"])
    result_ids = [m["tool_call_id"] for m in msgs if m.get("role") == "tool"]
    return sorted(call_ids) == sorted(result_ids)


def test_eviction_preserves_tool_pairs(tmp_path):
    a = _make_agent(tmp_path, keep=2)
    a.messages = [
        {"role": "system", "content": "FRAME"},
        {"role": "user", "content": "TASK"},
        _asst("c1", "get_callers", '{"f":"foo"}'),   # idempotent
        _tool("c1", "A" * 500),
        _asst("c2", "reach_probe", '{"x":1}'),        # non-idempotent
        _tool("c2", "B" * 500),
        _asst_multi([("c3", "get_callees", "{}"), ("c4", "create_pov", "{}")]),  # mixed turn
        _tool("c3", "C" * 500),
        _tool("c4", "D" * 500),
        _asst("c5", "reach_probe", "{}"),
        _tool("c5", "E" * 500),   # recent (kept)
        _asst("c6", "get_callers", "{}"),
        _tool("c6", "F" * 500),   # recent (kept)
    ]
    before = len(a.messages)
    assert _pairs_valid(a.messages)

    asyncio.run(a._compress_context())

    # No message added or removed -> pairing is structurally intact.
    assert len(a.messages) == before
    assert _pairs_valid(a.messages), "eviction orphaned a tool_call/tool_result"


def test_frame_and_recent_untouched(tmp_path):
    a = _make_agent(tmp_path, keep=2)
    a.messages = [
        {"role": "system", "content": "FRAME"},
        {"role": "user", "content": "TASK"},
        _asst("c1", "get_callers"),
        _tool("c1", "OLD1" + "x" * 500),
        _asst("c2", "reach_probe"),
        _tool("c2", "OLD2" + "y" * 500),
        _asst("c3", "get_callees"),
        _tool("c3", "RECENT_A" + "z" * 500),
        _asst("c4", "reach_probe"),
        _tool("c4", "RECENT_B" + "w" * 500),
    ]
    asyncio.run(a._compress_context())

    # Frame untouched.
    assert a.messages[0]["content"] == "FRAME"
    assert a.messages[1]["content"] == "TASK"
    # Last 2 tool results kept verbatim.
    assert a.messages[7]["content"].startswith("RECENT_A")
    assert a.messages[9]["content"].startswith("RECENT_B")
    # Older two evicted to stubs.
    assert a.messages[3]["content"].startswith("[evicted")
    assert a.messages[5]["content"].startswith("[evicted")


def test_idempotent_vs_nonidempotent(tmp_path):
    a = _make_agent(tmp_path, keep=1)  # keep only the most recent tool result
    a.messages = [
        {"role": "system", "content": "FRAME"},
        {"role": "user", "content": "TASK"},
        _asst("c1", "get_callers", '{"f":"foo"}'),   # idempotent -> no storage
        _tool("c1", "CODE" * 100),
        _asst("c2", "reach_probe", "{}"),             # non-idempotent -> stored
        _tool("c2", "PROBE_RESULT" * 100),
        _asst("c3", "get_callers", "{}"),             # recent (kept verbatim)
        _tool("c3", "RECENT" * 50),
    ]
    asyncio.run(a._compress_context())

    idem_stub = a.messages[3]["content"]
    noni_stub = a.messages[5]["content"]
    assert idem_stub.startswith("[evicted") and "re-call get_callers" in idem_stub
    assert noni_stub.startswith("[evicted #") and "recall(" in noni_stub

    # Idempotent: nothing stored. Non-idempotent: stored + recallable verbatim.
    files = list((tmp_path / "agent_ctx").rglob("*.txt"))
    assert len(files) == 1, f"expected exactly one stored result, got {files}"
    restored = a._handle_recall({"ref": 1})
    assert restored == "PROBE_RESULT" * 100


def test_two_agents_do_not_collide_in_recall_store(tmp_path):
    """Regression: the recall store dir was keyed on id(self), a memory address
    reused across GC'd agents, so sequential POV agents overwrote each other's
    <ref>.txt files and recall() returned another agent's result. Two agents
    sharing a log_dir must get distinct store dirs and independent refs."""
    a = _make_agent(tmp_path, keep=0)
    b = _make_agent(tmp_path, keep=0)
    assert a._evict_dir() != b._evict_dir(), "two agents collided on one store dir"

    a.messages = [
        {"role": "system", "content": "s"}, {"role": "user", "content": "t"},
        _asst("x1", "reach_probe"), _tool("x1", json.dumps({"sink_reached": True, "who": "A"})),
        _asst("x2", "noop"), _tool("x2", "keepA"),
    ]
    b.messages = [
        {"role": "system", "content": "s"}, {"role": "user", "content": "t"},
        _asst("y1", "create_pov"), _tool("y1", json.dumps({"pov_ids": ["B"], "who": "B"})),
        _asst("y2", "noop"), _tool("y2", "keepB"),
    ]
    asyncio.run(a._compress_context())
    asyncio.run(b._compress_context())

    # Both evicted their first tool result to ref #1, but in DIFFERENT dirs, so
    # each recall(1) returns ITS OWN content, not the other agent's.
    assert '"who": "A"' in a._handle_recall({"ref": 1})
    assert '"who": "B"' in b._handle_recall({"ref": 1})
    assert '"who": "B"' not in a._handle_recall({"ref": 1})


def test_recall_bad_ref(tmp_path):
    a = _make_agent(tmp_path, keep=2)
    a.messages = [{"role": "system", "content": "s"}]
    assert "invalid ref" in a._handle_recall({"ref": "abc"})
    assert "no evicted result" in a._handle_recall({"ref": 999})


def test_ledger_pins_reach_and_pov_facts(tmp_path):
    a = _make_agent(tmp_path, keep=1)
    reach = json.dumps(
        {"sink_reached": True, "asan_margin": 3, "first_unreached": None, "crashed": False}
    )
    pov = json.dumps({"crashed": True, "crash_matches_sp": True})
    a.messages = [
        {"role": "system", "content": "FRAME"},
        {"role": "user", "content": "TASK"},
        _asst("c1", "reach_probe"),
        _tool("c1", reach),          # evicted -> fact lifted
        _asst("c2", "create_pov"),
        _tool("c2", pov),            # evicted -> fact lifted
        _asst("c3", "reach_probe"),
        _tool("c3", "{}recent"),     # kept (recent)
    ]
    asyncio.run(a._compress_context())

    led = _ledger_msg(a.messages)
    assert led is not None, "ledger message was not pinned"
    assert "sink_reached=True" in led and "asan_margin=3" in led
    assert "pov:CRASHED" in led and "create_pov CRASHED" in led
    # Structure still valid after inserting the ledger message.
    assert _pairs_valid(a.messages)


def test_ledger_is_bounded_and_updated_in_place(tmp_path):
    a = _make_agent(tmp_path, keep=0)
    # Two shallow probes under the same key -> second overwrites first (bounded).
    a.messages = [
        {"role": "system", "content": "FRAME"},
        {"role": "user", "content": "TASK"},
        _asst("c1", "reach_probe"),
        _tool("c1", json.dumps({"sink_reached": False, "asan_margin": 10})),
        _asst("c2", "reach_probe"),
        _tool("c2", json.dumps({"sink_reached": False, "asan_margin": 4})),
    ]
    asyncio.run(a._compress_context())
    # one 'reach:last' key, holding the latter value; ledger did not grow to 2.
    assert len(a._ledger) == 1
    led = _ledger_msg(a.messages)
    assert "asan_margin=4" in led and "asan_margin=10" not in led

    # A second compression must update the SAME ledger message, not add another.
    a.messages.append(_asst("c3", "reach_probe"))
    a.messages.append(_tool("c3", json.dumps({"crashed": True, "crash_frame": "foo"})))
    asyncio.run(a._compress_context())
    ledger_msgs = [
        m for m in a.messages
        if m.get("role") == "user" and str(m.get("content", "")).startswith("## LEDGER")
    ]
    assert len(ledger_msgs) == 1, "ledger message was duplicated"
    assert "reach:CRASHED" in ledger_msgs[0]["content"]


def test_second_pass_is_idempotent(tmp_path):
    """Compressing twice must not double-evict or corrupt already-stubbed results."""
    a = _make_agent(tmp_path, keep=1)
    a.messages = [
        {"role": "system", "content": "FRAME"},
        {"role": "user", "content": "TASK"},
        _asst("c1", "reach_probe"),
        _tool("c1", "R1" * 300),
        _asst("c2", "get_callers"),
        _tool("c2", "R2" * 300),
        _asst("c3", "reach_probe"),
        _tool("c3", "R3recent" * 50),
    ]
    asyncio.run(a._compress_context())
    seq_after_first = a._evict_seq
    stub_c1 = a.messages[3]["content"]

    asyncio.run(a._compress_context())
    # Already-evicted stub unchanged; no new store for it.
    assert a.messages[3]["content"] == stub_c1
    assert a._evict_seq == seq_after_first
    assert _pairs_valid(a.messages)
