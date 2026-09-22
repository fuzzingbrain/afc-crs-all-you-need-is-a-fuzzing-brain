"""Run the agent's actions through FuzzingBrain-Bench's own MCP server.

v2 of the bench gives every agent arm one tool surface: a per-episode
mcp-server inside the sealed challenge image, reached over a unix socket.
claudecode, codex and this agent all drive the same three tools:
setup(), exec() and run_poc_on_harness(). There is no
`./submit`, no `./reach` and no staged host copy any more -- those were the
external arm's own tools, and having them was the asymmetry.

What the agent sees, identical to every other arm:
  cwd /challenge, read-only   /workspace and /tmp writable
  gdb on PATH on every challenge         no network
  run_poc_on_harness() as the only oracle

This keeps fb-agent's single-action loop. The model still writes one command
per turn; the environment decides whether that is `exec` or the grader. How an
agent surfaces the bench's tools to its model is the agent's own design -- the
tools themselves are the bench's, and they are the same for everyone.
"""

from __future__ import annotations

import json
import re

from minisweagent.environments import entry_guards as eg
from minisweagent.environments import reachability as rx
import os
import socket
import threading
from typing import Any

from pydantic import BaseModel

from minisweagent.exceptions import Submitted
from minisweagent.utils.serialize import recursive_merge

_FRAME = re.compile(r"^\s*#0\s+0x\S+\s+in\s+([A-Za-z_][\w:]*)", re.M)


def _top_frame(verdict: Any) -> str | None:
    """The function that faulted, from the verdict the grader returned."""
    blob = json.dumps(verdict) if not isinstance(verdict, str) else verdict
    m = _FRAME.search(blob.replace("\\n", "\n"))
    return m.group(1) if m else None


def _render_verdict(out: Any) -> str:
    """The harness's own output first, as text, then the structured fields.

    json.dumps would escape every newline, so the sanitizer report -- the whole
    reason v2 hands this arm the raw result instead of a one-line verdict --
    would arrive as one unreadable line. The other arms read the report as the
    harness printed it; so does this one.
    """
    if not isinstance(out, dict):
        return str(out)
    ho = out.get("harness_output") or {}
    parts = []
    for stream in ("stdout", "stderr"):
        if text := (ho.get(stream) or "").strip():
            parts.append(text)
    meta = {k: v for k, v in out.items() if k != "harness_output"}
    meta |= {k: v for k, v in ho.items() if k not in ("stdout", "stderr")}
    if meta:
        parts.append("\n".join(f"{k}: {v}" for k, v in meta.items()))
    return "\n\n".join(parts) if parts else json.dumps(out, indent=2)


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
        # reachability state: what the last candidate covered, which faulting
        # functions have already been enumerated, and how many read-only
        # queries this loop has spent that the model did not ask for.
        self._covered_before: set[str] | None = None
        self._asked_callers: set[str] = set()
        self.probe_calls = 0
        self._min_size: tuple[int, str] | None = None
        self._min_size_read = False
        self._guard_waived: set[str] = set()
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
        """Unwrap the MCP envelope the way the bench's own client does.

        A tools/call result is {"content": [...blocks...], "structuredContent":
        {...}}. Reading the envelope instead of its payload is silent: every
        exec() came back with an empty stdout and the model spent its whole
        budget looking at nothing, with no error anywhere.
        """
        resp = self._rpc("tools/call", {"name": name, "arguments": arguments}, timeout)
        if isinstance(resp, dict):
            if isinstance(sc := resp.get("structuredContent"), dict):
                return sc
            if isinstance(blocks := resp.get("content"), list):
                text = "\n".join(b.get("text", "") for b in blocks
                                  if isinstance(b, dict) and b.get("type") == "text")
                if text:
                    try:
                        return json.loads(text)
                    except ValueError:
                        return {"stdout": text, "stderr": "", "exit_code": 0}
        return resp

    # -- the environment interface ----------------------------------------
    def execute(self, action: dict, cwd: str = "", *, timeout: int | None = None) -> dict[str, Any]:
        t = timeout or self.config.timeout
        # The model names the tool; nothing is inferred from the text of a
        # command any more. Guessing the grader out of a bash string is what
        # made a model run `which run_poc_on_harness`, looking for a binary.
        name = action.get("tool") or "exec"
        args = dict(action.get("args") or {})
        if not args and action.get("command"):      # a bash-shaped caller
            name, args = "exec", {"cmd": action["command"]}
        try:
            if name == "run_poc_on_harness":
                path = args.get("path", "")
                if refused := self._entry_guard(path, t):
                    return {"output": refused, "returncode": 0,
                            "exception_info": ""}
                out = self._tool(name, {"path": path}, t)
                text = _render_verdict(out)
                text += self._reachability(path, out, t)
                output = {"output": text, "returncode": 0,
                          "exception_info": ""}
            elif name == "setup":
                out = self._tool(name, {}, t)
                output = {"output": json.dumps(out, indent=2), "returncode": 0,
                          "exception_info": ""}
            else:
                args.setdefault("timeout_s", int(t))
                out = self._tool("exec", args, t)
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



    def _entry_guard(self, path: str, t: float) -> str:
        """Refuse a candidate the harness will throw out, before grading it.

        Not a judgement about the bug -- only about whether the input can reach
        the library at all. A grading call spent on a file the entry check
        rejects buys nothing, and that was the whole of two zero-scoring cells.

        Deliberately timid: it only knows numeric size guards, it refuses a
        given path once, and re-submitting the same path goes straight through.
        Blocking a candidate that was actually fine is worse than saying
        nothing, so anything it cannot read confidently it lets past.
        """
        if not path or path in self._guard_waived:
            return ""
        if not self._min_size_read:
            self._min_size_read = True
            src = self._probe("cat /challenge/harness/*.c /challenge/harness/*.cc "
                              "/challenge/harness/*.cpp 2>/dev/null", t)
            self._min_size = eg.min_size(src)
        if not self._min_size:
            return ""
        need, guard = self._min_size
        out = self._probe(f"stat -c %s {path} 2>/dev/null", t).strip()
        if not out.isdigit():
            return ""
        size = int(out)
        if size >= need:
            return ""
        self._guard_waived.add(path)      # insist once and it goes through
        return eg.refusal(size, need, guard)

    # ------------------------------------------------ facts, not suggestions
    def _probe(self, cmd: str, t: float) -> str:
        """Run a read-only query against the target copy. Never the grader.

        Counted in `probe_calls` so these are visible in the trajectory: the
        loop is spending container time the model did not ask for, and a
        benchmark result should not hide that.
        """
        try:
            out = self._tool("exec", {"cmd": cmd, "timeout_s": int(min(t, 120))}, t)
            self.probe_calls += 1
            out = out if isinstance(out, dict) else {"stdout": str(out)}
            return (out.get("stdout") or "") + (out.get("stderr") or "")
        except Exception:  # noqa: BLE001 - a probe must never break a turn
            return ""

    def _reachability(self, path: str, verdict, t: float) -> str:
        """What that candidate actually reached, appended to its verdict.

        The model is told; it does not have to think to ask. Silent when the
        bench does not mount a target copy, so an older bench still runs.
        """
        if not path:
            return ""
        notes: list[str] = []
        covered, entry = rx.parse_coverage(self._probe(rx.coverage_cmd(path), t))
        if entry is None and not covered:
            return ""                      # no readable target; say nothing
        if line := rx.coverage_note(covered, entry, self._covered_before):
            notes.append(line)
        self._covered_before = covered

        frame = _top_frame(verdict)
        if frame and frame not in self._asked_callers:
            self._asked_callers.add(frame)
            callers = rx.parse_callers(self._probe(rx.callers_cmd(frame), t), frame)
            if line := rx.callers_note(frame, callers, covered):
                notes.append(line)
        return ("\n\n" + "\n".join(notes)) if notes else ""

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

    def get_template_vars(self, **kwargs) -> dict[str, Any]:
        """The prompt renders against these. The agent is not on this host any
        more -- it acts inside the challenge image -- so reporting the host's
        uname would describe a machine the model never touches."""
        return recursive_merge(self.config.model_dump(),
                               {"system": "Linux", "machine": "x86_64",
                                "release": "", "version": "",
                                "cwd": "/challenge"},
                               kwargs)

    def serialize(self) -> dict:
        return {
            "info": {
                "config": {
                    "environment": self.config.model_dump(mode="json"),
                    "environment_type": f"{self.__class__.__module__}.{self.__class__.__name__}",
                }
            }
        }

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass
