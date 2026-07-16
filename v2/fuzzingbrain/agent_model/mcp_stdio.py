# SPDX-License-Identifier: Apache-2.0
"""
Minimal line-delimited JSON-RPC 2.0 stdio client for an external MCP tool server.

The agent model talks to a target's tool server (e.g. a challenge container's
`mcp-server`, launched as `docker run -i --rm <image> mcp-server`) over the
subprocess's stdin/stdout. This is a narrow transport — initialize, tools/list,
tools/call — that lets the agent drive ANY MCP server, independent of the CRS's
own in-process FastMCP tooling.
"""
from __future__ import annotations

import json
import subprocess
import threading
from typing import Any

# Upper bound (seconds) on an exec tool call's timeout_s. A single blocking exec
# pins the whole episode (we wait on the server's read), so clamp a runaway
# request instead of stalling forever.
EXEC_TIMEOUT_CAP_S = 300


class MCPToolError(Exception):
    def __init__(self, message: str, data: Any = None):
        super().__init__(message)
        self.data = data


class StdioMCPClient:
    """JSON-RPC 2.0 over a subprocess's stdio. `cmd` is the argv that launches
    the MCP server (it must speak line-delimited JSON-RPC on stdin/stdout)."""

    def __init__(self, cmd: list[str], env: dict | None = None):
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            bufsize=0,
        )
        self._id = 0
        self._lock = threading.Lock()
        self._stderr_buf: list[bytes] = []
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _drain_stderr(self) -> None:
        assert self._proc.stderr is not None
        for line in self._proc.stderr:
            self._stderr_buf.append(line)

    def initialize(self) -> dict:
        return self._call("initialize", {})

    def list_tools(self) -> list[dict]:
        return self._call("tools/list", {})["tools"]

    def call(self, name: str, arguments: dict) -> Any:
        arguments = self._clamp_exec_timeout(name, arguments)
        resp = self._call("tools/call", {"name": name, "arguments": arguments})
        return resp.get("structuredContent", resp)

    @staticmethod
    def _clamp_exec_timeout(name: str, arguments: dict) -> dict:
        if name != "exec":
            return arguments
        ts = arguments.get("timeout_s")
        if isinstance(ts, (int, float)) and ts > EXEC_TIMEOUT_CAP_S:
            arguments = {**arguments, "timeout_s": EXEC_TIMEOUT_CAP_S}
        return arguments

    def _call(self, method: str, params: dict) -> dict:
        with self._lock:
            self._id += 1
            req = {"jsonrpc": "2.0", "id": self._id, "method": method,
                   "params": params}
            assert self._proc.stdin is not None
            self._proc.stdin.write((json.dumps(req) + "\n").encode())
            self._proc.stdin.flush()
            assert self._proc.stdout is not None
            line = self._proc.stdout.readline()
            if not line:
                tail = b"".join(self._stderr_buf[-20:]).decode("utf-8", "replace")
                raise RuntimeError("MCP server closed stdout; stderr=" + tail)
            resp = json.loads(line)
        if "error" in resp:
            err = resp["error"]
            raise MCPToolError(err.get("message", "tool error"), err.get("data"))
        return resp["result"]

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
        except Exception:
            pass
        try:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()

    def openai_tools(self) -> list[dict]:
        """The server's tools/list rendered as OpenAI function-calling schemas."""
        out = []
        for t in self.list_tools():
            out.append({
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("inputSchema") or {
                        "type": "object", "properties": {}},
                },
            })
        return out
