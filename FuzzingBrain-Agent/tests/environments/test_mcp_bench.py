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


def test_a_grading_call_goes_to_the_oracle_not_the_shell(server):
    """`./submit` is gone. The shared task prompt names run_poc_on_harness, so
    the environment has to honour that name."""
    env = _env(server)
    for form in ("run_poc_on_harness(/workspace/c1.bin)",
                 "run_poc_on_harness /workspace/c1.bin",
                 "  run_poc_on_harness( /workspace/c1.bin )  "):
        env.execute({"command": form})
        assert server.calls[-1][0] == "run_poc_on_harness"
        assert server.calls[-1][1]["path"] == "/workspace/c1.bin"


def test_the_agent_gets_the_whole_verdict_not_one_line(tmp_path):
    """v1 handed this arm `crash: a|b|c` while the other arms got the raw
    sanitizer report. That was the real handicap, and it is gone."""
    full = {"harness_output": {"exit_code": 1, "signal": "SIGSEGV",
                               "stderr": "==1==ERROR: AddressSanitizer: heap-use-after-free\n"
                                         "    #0 0x1 in xmlIsID valid.c:2366"},
            "crash_novelty": "new", "crashed_rounds": 3, "total_rounds": 3}
    srv = FakeServer(tmp_path / "s.sock", reply=lambda n, a: full)
    env = McpBenchEnvironment(socket_path=srv.path, timeout=5)
    out = env.execute({"command": "run_poc_on_harness(/workspace/c1.bin)"})
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
