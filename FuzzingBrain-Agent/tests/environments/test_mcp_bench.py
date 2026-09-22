"""The v2 environment: the agent drives the bench's MCP server, not a shell.

Everything here runs against a fake server on a real unix socket, so the tests
exercise the actual wire handling (framing, ids, chunking) without a container,
a challenge image or an API key.
"""
import json
import os
import socket
import threading

import pytest

from minisweagent.environments.mcp_bench import McpBenchEnvironment
from minisweagent.exceptions import Submitted


class FakeServer:
    """A bench MCP server that records what it was asked."""

    def __init__(self, path, reply=None, chunk=None):
        self.path = str(path)
        self.calls = []
        self.reply = reply or (lambda name, args: {"stdout": "ok", "stderr": "", "exit_code": 0})
        self.chunk = chunk
        self.srv = socket.socket(socket.AF_UNIX)
        self.srv.bind(self.path)
        self.srv.listen(1)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        conn, _ = self.srv.accept()
        buf = b""
        while True:
            try:
                b = conn.recv(65536)
            except OSError:
                return
            if not b:
                return
            buf += b
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                msg = json.loads(line)
                if msg.get("method") == "tools/call":
                    p = msg["params"]
                    self.calls.append((p["name"], p.get("arguments", {})))
                    result = self.reply(p["name"], p.get("arguments", {}))
                else:
                    result = {"protocolVersion": "2024-11-05"}
                out = (json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                   "result": result}) + "\n").encode()
                if self.chunk:                      # dribble it out in pieces
                    for i in range(0, len(out), self.chunk):
                        conn.sendall(out[i:i + self.chunk])
                else:
                    conn.sendall(out)


@pytest.fixture
def server(tmp_path):
    return FakeServer(tmp_path / "bench.sock")


def _env(server, **kw):
    return McpBenchEnvironment(socket_path=server.path, timeout=5, **kw)


def test_a_plain_command_goes_to_exec(server):
    env = _env(server)
    out = env.execute({"command": "ls -la /challenge"})
    assert server.calls[-1][0] == "exec"
    assert server.calls[-1][1]["cmd"] == "ls -la /challenge"
    assert out["output"] == "ok" and out["returncode"] == 0


def test_the_model_names_the_tool_and_nothing_is_guessed(server):
    """v2 dispatches on the tool the model called. Inferring the grader from the
    text of a bash command is what made a model run `which run_poc_on_harness`,
    looking for a binary, and spend 30 turns never grading anything."""
    env = _env(server)
    env.execute({"tool": "run_poc_on_harness", "args": {"path": "/workspace/c1.bin"}})
    # Not calls[-1] any more: a graded candidate is followed by read-only
    # reachability probes, which are exec calls. The grading call itself is
    # what this test is about, and there must be exactly one of it.
    graded = [c for c in server.calls if c[0] == "run_poc_on_harness"]
    assert graded == [("run_poc_on_harness", {"path": "/workspace/c1.bin"})]
    env.execute({"tool": "exec", "args": {"cmd": "ls /challenge"}})
    assert server.calls[-1][0] == "exec" and server.calls[-1][1]["cmd"] == "ls /challenge"
    env.execute({"tool": "setup", "args": {}})
    assert server.calls[-1] == ("setup", {})


def test_a_bash_shaped_action_still_reaches_exec(server):
    """Anything that hands over only a command string is an exec."""
    env = _env(server)
    env.execute({"command": "echo hi"})
    assert server.calls[-1][0] == "exec" and server.calls[-1][1]["cmd"] == "echo hi"


def test_the_agent_gets_the_whole_verdict_not_one_line(tmp_path):
    """v1 handed this arm `crash: a|b|c` while the other arms got the raw
    sanitizer report. That was the real handicap, and it is gone."""
    full = {"harness_output": {"exit_code": 1, "signal": "SIGSEGV",
                               "stderr": "==1==ERROR: AddressSanitizer: heap-use-after-free\n"
                                         "    #0 0x1 in xmlIsID valid.c:2366"},
            "crash_novelty": "new", "crashed_rounds": 3, "total_rounds": 3}
    srv = FakeServer(tmp_path / "s.sock", reply=lambda n, a: full)
    env = McpBenchEnvironment(socket_path=srv.path, timeout=5)
    out = env.execute({"tool": "run_poc_on_harness", "args": {"path": "/workspace/c1.bin"}})
    assert "AddressSanitizer: heap-use-after-free" in out["output"]
    assert "valid.c:2366" in out["output"]
    assert "crash_novelty" in out["output"]


def test_a_reply_split_across_reads_is_reassembled(tmp_path):
    srv = FakeServer(tmp_path / "s.sock", chunk=7)
    env = McpBenchEnvironment(socket_path=srv.path, timeout=5)
    assert env.execute({"command": "echo hi"})["output"] == "ok"


def test_a_nonzero_exit_is_reported_not_swallowed(tmp_path):
    srv = FakeServer(tmp_path / "s.sock",
                     reply=lambda n, a: {"stdout": "", "stderr": "boom", "exit_code": 2})
    env = McpBenchEnvironment(socket_path=srv.path, timeout=5)
    out = env.execute({"command": "false"})
    assert out["returncode"] == 2 and "boom" in out["output"]


def test_a_server_error_reaches_the_model_instead_of_killing_the_run(tmp_path):
    """A tool error is information for the model, not a crash."""
    srv = FakeServer(tmp_path / "s.sock")
    env = McpBenchEnvironment(socket_path=srv.path, timeout=5)
    srv.srv.close()
    env._sock.close()
    out = env.execute({"command": "ls"})
    assert out["returncode"] == -1 and out["exception_info"]


def test_the_finish_command_still_ends_the_episode(server):
    env = _env(server)
    server.reply = lambda n, a: {"stdout": "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\ndone\n",
                                 "stderr": "", "exit_code": 0}
    with pytest.raises(Submitted):
        env.execute({"command": "echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"})


def test_no_socket_is_a_clear_failure_not_a_silent_shell(monkeypatch):
    """Falling back to a local shell would mean the agent never touched the
    challenge while the run still looked normal."""
    monkeypatch.delenv("FBBENCH_MCP_SOCKET", raising=False)
    with pytest.raises(RuntimeError, match="FBBENCH_MCP_SOCKET"):
        McpBenchEnvironment()


def test_the_socket_is_taken_from_the_environment_when_not_passed(server, monkeypatch):
    monkeypatch.setenv("FBBENCH_MCP_SOCKET", server.path)
    env = McpBenchEnvironment(timeout=5)
    env.execute({"command": "pwd"})
    assert server.calls[-1][0] == "exec"


def test_the_real_mcp_envelope_is_unwrapped(tmp_path):
    """A live smoke run caught what these tests did not: the server answers
    tools/call with {"content": [...], "structuredContent": {...}}, and reading
    the envelope instead of its payload gives an empty stdout with no error
    anywhere. The model spent its whole budget looking at nothing."""
    real = {"content": [{"type": "text", "text": '{"stdout": "total 44\\nsrc\\n", '
                                                 '"stderr": "", "exit_code": 0}'}],
            "structuredContent": {"stdout": "total 44\nsrc\n", "stderr": "",
                                  "exit_code": 0}}
    srv = FakeServer(tmp_path / "s.sock", reply=lambda n, a: real)
    env = McpBenchEnvironment(socket_path=srv.path, timeout=5)
    out = env.execute({"command": "ls -la /challenge"})
    assert "total 44" in out["output"], out
    assert out["returncode"] == 0


def test_content_blocks_alone_are_enough(tmp_path):
    """Older servers answer with content blocks and no structuredContent."""
    real = {"content": [{"type": "text", "text": '{"stdout": "hi", "exit_code": 0}'}]}
    srv = FakeServer(tmp_path / "s.sock", reply=lambda n, a: real)
    env = McpBenchEnvironment(socket_path=srv.path, timeout=5)
    assert env.execute({"command": "echo hi"})["output"] == "hi"


# ------------------------------------------------ facts, not suggestions
def test_a_verdict_carries_what_the_candidate_reached(monkeypatch):
    """The loop asks the target what the input covered and appends one line.

    Measured motivation: in five zero-scoring cells nearly every candidate was
    thrown out before the library ran -- 25 of 25 on one -- and the verdict
    said nothing about it. The agent never once asked on its own across 706
    shell commands.
    """
    from minisweagent.environments import mcp_bench as mb
    env = mb.McpBenchEnvironment.__new__(mb.McpBenchEnvironment)
    env._covered_before, env._asked_callers, env.probe_calls = None, set(), 0
    env._min_size, env._min_size_read, env._guard_waived = None, True, set()
    env.config = type("C", (), {"timeout": 60})()
    calls = []

    def fake_tool(name, arguments, timeout=None):
        calls.append((name, arguments))
        if name == "run_poc_on_harness":
            return {"harness_output": {"exit_code": 0, "stderr": "", "stdout": ""}}
        return {"stdout": "COVERED_FUNC: hits: 1 edges: 1/2 xmlParseDocument /s/p.c:1\n"
                          "COVERED_FUNC: hits: 1 edges: 1/2 LLVMFuzzerTestOneInput /s/f.c:2\n"}
    env._tool = fake_tool
    out = env.execute({"tool": "run_poc_on_harness", "args": {"path": "/workspace/a"}})
    assert "[reach] reached 2 functions" in out["output"]
    assert env.probe_calls == 1, "probe calls must be counted, not hidden"
    assert calls[0][0] == "run_poc_on_harness"
    assert all(n != "run_poc_on_harness" for n, _ in calls[1:]), \
        "a probe must never spend a grading call"


def test_an_input_that_never_entered_the_harness_is_named_as_such(monkeypatch):
    from minisweagent.environments import mcp_bench as mb
    env = mb.McpBenchEnvironment.__new__(mb.McpBenchEnvironment)
    env._covered_before, env._asked_callers, env.probe_calls = None, set(), 0
    env._min_size, env._min_size_read, env._guard_waived = None, True, set()
    env.config = type("C", (), {"timeout": 60})()
    env._tool = lambda name, arguments, timeout=None: (
        {"harness_output": {"exit_code": 0, "stderr": "", "stdout": ""}}
        if name == "run_poc_on_harness" else
        {"stdout": "UNCOVERED_FUNC: hits: 0 edges: 0/24 LLVMFuzzerTestOneInput /s/f.c:2\n"})
    out = env.execute({"tool": "run_poc_on_harness", "args": {"path": "/workspace/a"}})
    assert "never entered the harness" in out["output"]


def test_no_readable_target_means_no_note_and_no_crash():
    """An older bench mounts no target copy; the agent must still run."""
    from minisweagent.environments import mcp_bench as mb
    env = mb.McpBenchEnvironment.__new__(mb.McpBenchEnvironment)
    env._covered_before, env._asked_callers, env.probe_calls = None, set(), 0
    env._min_size, env._min_size_read, env._guard_waived = None, True, set()
    env.config = type("C", (), {"timeout": 60})()
    env._tool = lambda name, arguments, timeout=None: (
        {"harness_output": {"exit_code": 0, "stderr": "", "stdout": ""}}
        if name == "run_poc_on_harness" else {"stdout": "", "stderr": "not found"})
    out = env.execute({"tool": "run_poc_on_harness", "args": {"path": "/workspace/a"}})
    assert "[reach]" not in out["output"]


# ------------------------------------------- refusing a candidate that cannot pass
def _guard_env(harness_src, size, monkey_calls):
    from minisweagent.environments import mcp_bench as mb
    env = mb.McpBenchEnvironment.__new__(mb.McpBenchEnvironment)
    env._covered_before, env._asked_callers, env.probe_calls = None, set(), 0
    env._min_size, env._min_size_read, env._guard_waived = None, False, set()
    env.config = type("C", (), {"timeout": 60})()

    def fake_tool(name, arguments, timeout=None):
        monkey_calls.append((name, arguments))
        cmd = arguments.get("cmd", "")
        if name == "run_poc_on_harness":
            return {"harness_output": {"exit_code": 0, "stderr": "", "stdout": ""}}
        if cmd.startswith("cat /challenge/harness"):
            return {"stdout": harness_src}
        if cmd.startswith("stat"):
            return {"stdout": str(size)}
        return {"stdout": ""}
    env._tool = fake_tool
    return env


_SRC = ("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        "  if (size < 8) return 0;\n  parse(data, size);\n}\n")


def test_a_candidate_too_small_to_reach_the_library_is_not_graded():
    """An empty file cannot pass a format check, so grading it buys nothing.

    This is the move that cost us the one challenge we lost cleanly: we read
    the format header at turn 6 and graded an EMPTY file at turn 13, while the
    arm we are measured against spent four more turns and submitted the magic
    bytes. Every one of our 25 candidates there died at the gate.
    """
    calls = []
    env = _guard_env(_SRC, 0, calls)
    out = env.execute({"tool": "run_poc_on_harness", "args": {"path": "/workspace/a"}})
    assert "NOT GRADED" in out["output"] and "size < 8" in out["output"]
    assert all(n != "run_poc_on_harness" for n, _ in calls), "the call must not be spent"


def test_insisting_on_the_same_candidate_lets_it_through():
    """The guard may be wrong; refusing a good candidate twice would be worse
    than never refusing at all."""
    calls = []
    env = _guard_env(_SRC, 0, calls)
    env.execute({"tool": "run_poc_on_harness", "args": {"path": "/workspace/a"}})
    env.execute({"tool": "run_poc_on_harness", "args": {"path": "/workspace/a"}})
    assert any(n == "run_poc_on_harness" for n, _ in calls)


def test_a_big_enough_candidate_is_graded_normally():
    calls = []
    env = _guard_env(_SRC, 64, calls)
    out = env.execute({"tool": "run_poc_on_harness", "args": {"path": "/workspace/a"}})
    assert "NOT GRADED" not in out["output"]
    assert any(n == "run_poc_on_harness" for n, _ in calls)


def test_an_unreadable_guard_never_blocks():
    """`size < sizeof(hdr)` cannot be resolved without compiling the target;
    guessing a bound there would refuse candidates that were fine."""
    calls = []
    env = _guard_env("int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size) {\n"
                     "  if (size < sizeof(header_t)) return 0;\n}", 0, calls)
    out = env.execute({"tool": "run_poc_on_harness", "args": {"path": "/workspace/a"}})
    assert "NOT GRADED" not in out["output"]
