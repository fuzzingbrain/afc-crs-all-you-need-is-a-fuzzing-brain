"""Run the agent's actions through FuzzingBrain-Bench's own MCP server.

v2 of the bench gives every agent arm one tool surface: a per-episode
mcp-server inside the sealed challenge image, reached over a unix socket.
claudecode, codex and this agent all drive the same six tools. There is no
`./submit`, no `./reach` and no staged host copy any more -- those were the
external arm's own tools, and having them was the asymmetry.

What the agent sees, identical to every other arm:
  cwd /challenge, read-only   /workspace and /tmp writable
  gdb where the image ships one          no network
  run_poc_on_harness() as the only oracle

This keeps fb-agent's single-action loop. The model still writes one command
per turn; the environment decides whether that is `exec` or the grader. How an
agent surfaces the bench's tools to its model is the agent's own design -- the
tools themselves are the bench's, and they are the same for everyone.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import socket
import threading
from typing import Any

from pydantic import BaseModel

from minisweagent.exceptions import Submitted

# The model asks for a grading run the way the shared task prompt names it:
# `run_poc_on_harness(/workspace/c1.bin)` or `run_poc_on_harness /workspace/c1.bin`.
_GRADE = re.compile(r"^\s*run_poc_on_harness\s*(?:\(\s*)?([^)\s]+)\s*\)?\s*$")


class McpBenchEnvironmentConfig(BaseModel):
    socket_path: str = ""
    """Unix socket for this episode's bench MCP server. Defaults to
    $FBBENCH_MCP_SOCKET, which the bench sets for every external agent."""
    cwd: str = ""
    timeout: int = 300
    env: dict[str, str] = {}


class McpBenchEnvironment:
    def __init__(self, *, config_class: type = McpBenchEnvironmentConfig, **kwargs):
        self.config = config_class(**kwargs)
        path = self.config.socket_path or os.environ.get("FBBENCH_MCP_SOCKET", "")
        if not path:
            raise RuntimeError(
                "no bench MCP socket: pass socket_path or set FBBENCH_MCP_SOCKET. "
                "The bench sets it for every external agent; running without it "
                "would mean the agent has no way to reach the challenge.")
        self._sock = socket.socket(socket.AF_UNIX)
        self._sock.connect(path)
        self._buf = b""
        self._id = 0
        self._lock = threading.Lock()
        self._rpc("initialize", {})

    # -- the wire ----------------------------------------------------------
    def _rpc(self, method: str, params: dict, timeout: float | None = None) -> Any:
        with self._lock:
            self._id += 1
            mid = self._id
            self._sock.sendall(
                (json.dumps({"jsonrpc": "2.0", "id": mid,
                             "method": method, "params": params}) + "\n").encode())
            self._sock.settimeout(timeout or (self.config.timeout + 60))
            while True:
                while b"\n" in self._buf:
                    line, self._buf = self._buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line)
                    except ValueError:
                        continue
                    if msg.get("id") == mid:
                        if "error" in msg:
                            raise RuntimeError(str(msg["error"])[:500])
                        return msg.get("result")
                chunk = self._sock.recv(65536)
                if not chunk:
                    raise RuntimeError("bench MCP server closed the connection")
                self._buf += chunk

    def _tool(self, name: str, arguments: dict, timeout: float | None = None) -> Any:
        return self._rpc("tools/call", {"name": name, "arguments": arguments}, timeout)

    # -- the environment interface ----------------------------------------
    def execute(self, action: dict, cwd: str = "", *, timeout: int | None = None) -> dict[str, Any]:
        command = action.get("command", "")
        t = timeout or self.config.timeout
        try:
            m = _GRADE.match(command)
            if m:
                out = self._tool("run_poc_on_harness",
                                 {"path": shlex.split(m.group(1))[0]}, t)
                # The whole result, not a one-line summary. The other arms get
                # the raw harness stdout/stderr -- the full sanitizer report --
                # and a one-line verdict was the external arm's real handicap.
                text = json.dumps(out, indent=2) if not isinstance(out, str) else out
                output = {"output": text, "returncode": 0, "exception_info": ""}
            else:
                out = self._tool("exec", {"cmd": command, "timeout_s": int(t)}, t)
                out = out if isinstance(out, dict) else {"stdout": str(out)}
                text = (out.get("stdout") or "") + (out.get("stderr") or "")
                output = {"output": text,
                          "returncode": int(out.get("exit_code") or 0),
                          "exception_info": ""}
        except Exception as e:  # noqa: BLE001 - surfaced to the model, not raised
            output = {"output": "", "returncode": -1,
                      "exception_info": f"An error occurred while executing the command: {e}",
                      "extra": {"exception_type": type(e).__name__, "exception": str(e)}}
        self._check_finished(output)
        return output

    def _check_finished(self, output: dict):
        """Raises Submitted when the model issues the finish command.

        Same rule as LocalEnvironment, restated rather than borrowed: the two
        environments agreeing by accident is how a finish command silently
        stops working on one of them."""
        lines = output.get("output", "").lstrip().splitlines(keepends=True)
        if lines and lines[0].strip() == "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT" and output["returncode"] == 0:
            submission = "".join(lines[1:])
            raise Submitted({
                "role": "exit",
                "content": submission,
                "extra": {"exit_status": "Submitted", "submission": submission},
            })

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass
