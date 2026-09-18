"""A stand-in for the bench's per-episode MCP server, for tests.

Runs in a thread on a real unix socket and speaks the same JSON-RPC the bench's
mcp-server does, so the agent's own wire handling is exercised. `exec` runs the
command for real in the staged directory; `run_poc_on_harness` returns a canned
verdict in the shape McpBenchEnvironment renders.
"""
from __future__ import annotations

import json
import socket
import subprocess
import threading


class FakeBenchServer:
    def __init__(self, path: str, cwd: str, verdict: dict | None = None,
                 observer=None):
        # The real episode server tees both pumps into CandidateLog; a fake
        # that skipped it would leave the observer untested.
        self.observer = observer
        self.path, self.cwd = str(path), str(cwd)
        self.verdict = verdict if verdict is not None else {
            "harness_output": {"exit_code": 0, "signal": "", "stdout": "", "stderr": ""},
            "duration_ms": 0}
        self.calls: list[tuple] = []
        self.srv = socket.socket(socket.AF_UNIX)
        self.srv.bind(self.path)
        self.srv.listen(4)
        self._stop = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        buf = b""
        while not self._stop.is_set():
            try:
                b = conn.recv(65536)
            except OSError:
                return
            if not b:
                return
            if self.observer is not None:
                self.observer.saw_request(b)
            buf += b
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                try:
                    reply = (json.dumps({"jsonrpc": "2.0", "id": msg.get("id"),
                                         "result": self._handle(msg)}) + "\n").encode()
                    if self.observer is not None:
                        self.observer.saw_response(reply)
                    conn.sendall(reply)
                except OSError:
                    return

    def _handle(self, msg):
        if msg.get("method") != "tools/call":
            return {"protocolVersion": "2024-11-05"}
        p = msg["params"]
        name, args = p["name"], p.get("arguments", {})
        self.calls.append((name, args))
        if name == "run_poc_on_harness":
            return self.verdict
        if name == "exec":
            # The bench bind-mounts the workspace at /workspace inside the
            # container; the fake maps it the same way so a path the agent
            # builds resolves to the same file the test reads back.
            cmd = (args.get("cmd", "") or "").replace("/workspace/", f"{self.cwd}/")
            r = subprocess.run(cmd, shell=True, cwd=self.cwd,
                               capture_output=True, text=True,
                               timeout=args.get("timeout_s", 60))
            return {"stdout": r.stdout, "stderr": r.stderr, "exit_code": r.returncode}
        return {}

    def stop(self):
        self._stop.set()
        try:
            self.srv.close()
        except OSError:
            pass
