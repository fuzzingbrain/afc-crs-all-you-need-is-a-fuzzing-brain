"""One agent session: a single ``claude -p`` or ``codex exec`` process.

A session runs one role (harness generator, reviewer, seed agent, VH finder,
...) against one workspace. It

* writes ``ctx.json`` (what the MCP tool server needs), the system prompt and
  the task prompt into its session directory;
* launches the CLI on the host, in ``work/``, with every API-key variable
  removed, so it bills the subscription the CLI is logged in with;
* gives the CLI our MCP tool server and nothing of the host's (no user
  settings, CLAUDE.md, hooks, plugins or other MCP servers);
* streams the CLI's events to ``trajectory.jsonl`` as they arrive, so a
  crashed or killed session still leaves its record;
* enforces a wall-clock limit (both CLIs) and a turn limit (Claude natively,
  Codex by counting turns and stopping the process);
* returns what happened; what the agent *submitted* is in ``out/``, written
  by the tool server, and the caller reads it from there.

The CLIs' own shells would run on the host, so they are not given one: Claude
runs ``--restricted`` with read-only navigation plus our tools, Codex runs
``--sandbox read-only``. Everything that executes goes through the MCP
``exec`` / ``run_*`` tools, which run in the workspace container.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from fbv3.runtime import auth

logger = logging.getLogger(__name__)

V3_ROOT = Path(__file__).resolve().parents[2]
SERVER_SCRIPT = V3_ROOT / "fbv3" / "tools" / "server.py"

CLAUDE_READONLY_TOOLS = ("Read", "Grep", "Glob")

RATE_LIMIT_MARKERS = (
    "rate limit", "rate_limit", "429", "usage limit", "quota", "insufficient_quota",
    "resource_exhausted", "overloaded", "too many requests", "limit reached",
)
# Named policy refusals: unambiguous, so they are recognised wherever they appear.
CONTENT_FILTER_MARKERS = (
    "flagged for possible cybersecurity", "content was flagged", "access_programs.cyber",
    "safeguards flagged", "usage policy", "[cyber]", "refusal", "content_policy",
)
# A plain refusal (the ChatGPT plan answers exploitation prompts this way) is only
# taken as one when it arrives on the error channel: in the agent's own prose the
# same words are ordinary English and must not cost a backend switch.
REFUSAL_MARKERS = (
    "unable to assist", "can't assist with", "cannot assist with", "won't assist with",
    "unable to help with", "can't help with that", "cannot help with that",
)

STATUSES = ("completed", "max_turns", "timeout", "rate_limited", "content_filtered", "auth_error",
            "error", "skipped")


@dataclass
class SessionResult:
    session_id: str
    role: str
    backend: str
    status: str
    error: str = ""
    duration_s: float = 0.0
    turns: int = 0
    auth_source: str = ""
    final_text: str = ""
    usage: dict = field(default_factory=dict)
    session_dir: str = ""

    @property
    def ok(self) -> bool:
        """The session ran to an end of its own (its submissions are usable)."""
        return self.status in ("completed", "max_turns")

    @property
    def out_dir(self) -> Path:
        return Path(self.session_dir) / "out"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ok"] = self.ok
        return d


@dataclass
class Session:
    role: str
    backend: str  # claude | codex
    session_root: Path  # sessions/ of the workspace
    system_prompt: str
    task_prompt: str
    tools: tuple[str, ...]  # MCP tool names this role may call
    ctx: dict  # handed to the tool server
    tool_python: Path
    model: str = ""
    timeout_s: int = 900
    max_turns: int = 60
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    # -- files ----------------------------------------------------------------

    @property
    def dir(self) -> Path:
        return (Path(self.session_root) / f"{self.role}-{self.session_id[:12]}").resolve()

    def _prepare(self) -> tuple[Path, Path]:
        d = self.dir
        (d / "work").mkdir(parents=True, exist_ok=True)
        (d / "out").mkdir(parents=True, exist_ok=True)
        (d / "system.md").write_text(self.system_prompt)
        (d / "prompt.md").write_text(self.task_prompt)
        ctx = {
            **self.ctx,
            "role": self.role,
            "tools": list(self.tools),
            "session_id": self.session_id,
            "session_dir": str(d),
        }
        ctx_path = d / "ctx.json"
        ctx_path.write_text(json.dumps(ctx, indent=2, default=str) + "\n")
        mcp = {"mcpServers": {"fb": {"command": str(self.tool_python),
                                     "args": [str(SERVER_SCRIPT), "--ctx", str(ctx_path)]}}}
        mcp_path = d / "mcp.json"
        mcp_path.write_text(json.dumps(mcp, indent=2) + "\n")
        return ctx_path, mcp_path

    # -- command lines ----------------------------------------------------------

    def claude_argv(self, mcp_path: Path) -> list[str]:
        allowed = list(CLAUDE_READONLY_TOOLS) + [f"mcp__fb__{t}" for t in self.tools]
        argv = [
            "claude", "-p", self.task_prompt,
            "--restricted",
            "--strict-mcp-config", "--mcp-config", str(mcp_path),
            "--setting-sources", "",
            "--append-system-prompt", self.system_prompt,
            "--allowedTools", ",".join(allowed),
            "--permission-mode", "acceptEdits",
            "--add-dir", str(self.dir / "work"),
            "--no-session-persistence",
            "--disable-slash-commands",
            "--output-format", "stream-json", "--verbose",
            "--max-turns", str(self.max_turns),
        ]
        if self.model:
            argv += ["--model", self.model]
        return argv

    def codex_argv(self, ctx_path: Path) -> list[str]:
        argv = [
            "codex", "exec",
            "--cd", str(self.dir / "work"),
            "--skip-git-repo-check", "--ephemeral", "--ignore-user-config",
            "--sandbox", "read-only",
            "--json",
            "-c", f"mcp_servers.fb.command={json.dumps(str(self.tool_python))}",
            "-c", "mcp_servers.fb.args=" + json.dumps([str(SERVER_SCRIPT), "--ctx", str(ctx_path)]),
            "-c", "mcp_servers.fb.startup_timeout_sec=60",
            "-c", "mcp_servers.fb.tool_timeout_sec=1000",
            "-c", 'mcp_servers.fb.default_tools_approval_mode="approve"',
        ]
        if self.model:
            argv += ["-c", f"model={json.dumps(self.model)}"]
        argv.append(f"{self.system_prompt}\n\n---\n\n{self.task_prompt}")
        return argv

    # -- run --------------------------------------------------------------------

    def run(self) -> SessionResult:
        ctx_path, mcp_path = self._prepare()
        if self.backend == "claude":
            argv = self.claude_argv(mcp_path)
        elif self.backend == "codex":
            argv = self.codex_argv(ctx_path)
        else:
            raise ValueError(f"unknown backend {self.backend!r}")
        (self.dir / "cmd.json").write_text(json.dumps(
            {"backend": self.backend, "argv": argv, "cwd": str(self.dir / "work"),
             "env_removed": list(auth.API_ENV_VARS)}, indent=2) + "\n")
        started = time.monotonic()
        result = self._spawn(argv)
        result.duration_s = round(time.monotonic() - started, 2)
        result.session_dir = str(self.dir)
        (self.dir / "result.json").write_text(json.dumps(result.to_dict(), indent=2) + "\n")
        return result

    def _spawn(self, argv: list[str]) -> SessionResult:
        res = SessionResult(self.session_id, self.role, self.backend, "error")
        try:
            proc = subprocess.Popen(
                argv, cwd=str(self.dir / "work"), env=auth.scrubbed_env(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                text=True, bufsize=1, start_new_session=True,
            )
        except FileNotFoundError as exc:
            res.error = f"{argv[0]} not installed: {exc}"
            return res

        stop_reason = {"why": ""}
        done = threading.Event()

        def stop(why: str) -> None:
            if not stop_reason["why"]:
                stop_reason["why"] = why
            _kill_group(proc)

        def watchdog() -> None:
            if not done.wait(self.timeout_s):
                stop("timeout")

        stderr_tail: list[str] = []

        def drain_err() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                stderr_tail.append(line)
                del stderr_tail[:-60]

        threading.Thread(target=watchdog, daemon=True).start()
        err_t = threading.Thread(target=drain_err, daemon=True)
        err_t.start()

        errors: list[str] = []
        auth_error = ""
        hit_max_turns = False
        with (self.dir / "trajectory.jsonl").open("w", encoding="utf-8") as log:
            assert proc.stdout is not None
            for line in proc.stdout:
                log.write(line)
                log.flush()
                ev = _parse(line)
                if ev is None:
                    continue
                kind = ev.get("type")
                if self.backend == "claude":
                    if kind == "system" and ev.get("subtype") == "init":
                        res.auth_source = str(ev.get("apiKeySource", ""))
                        auth_error = auth.claude_init_error(ev)
                        if auth_error:
                            stop("auth")
                    elif kind == "assistant":
                        res.turns += 1
                    elif kind == "result":
                        res.final_text = str(ev.get("result", ""))[-4000:]
                        res.usage = {k: ev.get(k) for k in ("total_cost_usd", "usage", "num_turns", "duration_ms")
                                     if ev.get(k) is not None}
                        if ev.get("subtype") == "error_max_turns":
                            hit_max_turns = True
                        elif ev.get("is_error"):
                            errors.append(str(ev.get("result") or ev.get("subtype") or "error"))
                else:
                    if kind == "turn.completed":
                        res.turns += 1
                        u = ev.get("usage") or {}
                        for k, v in u.items():
                            if isinstance(v, (int, float)):
                                res.usage[k] = res.usage.get(k, 0) + v
                        if res.turns >= self.max_turns:
                            hit_max_turns = True
                            stop("max_turns")
                    elif kind == "item.completed":
                        item = ev.get("item") or {}
                        if item.get("type", item.get("item_type")) in ("agent_message", "assistant_message"):
                            res.final_text = str(item.get("text", ""))[-4000:] or res.final_text
                        if item.get("type") == "mcp_tool_call" or item.get("item_type") == "mcp_tool_call":
                            pass
                    elif kind in ("error", "turn.failed"):
                        msg = ev.get("message") or (ev.get("error") or {}).get("message") or json.dumps(ev)[:500]
                        errors.append(str(msg))
        proc.wait()
        done.set()
        err_t.join(timeout=5)
        stderr_text = "".join(stderr_tail)
        blob = "\n".join([stderr_text, *errors, res.final_text]).lower()
        error_blob = "\n".join([stderr_text, *errors]).lower()

        if auth_error:
            res.status, res.error = "auth_error", auth_error
        elif stop_reason["why"] == "timeout":
            res.status, res.error = "timeout", f"session exceeded {self.timeout_s}s"
        elif any(m in blob for m in CONTENT_FILTER_MARKERS) or \
                any(m in error_blob for m in REFUSAL_MARKERS):
            res.status, res.error = "content_filtered", ("\n".join(errors) or stderr_text)[-800:]
        elif hit_max_turns:
            res.status = "max_turns"
        elif (proc.returncode != 0 or errors) and any(m in blob for m in RATE_LIMIT_MARKERS):
            res.status, res.error = "rate_limited", ("\n".join(errors) or stderr_text)[-800:]
        elif errors:
            res.status, res.error = "error", "\n".join(errors)[-800:]
        elif proc.returncode != 0:
            res.status, res.error = "error", stderr_text[-800:] or f"exit {proc.returncode}"
        else:
            res.status = "completed"
        return res


def _parse(line: str) -> dict | None:
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        return json.loads(line)
    except ValueError:
        return None


def _kill_group(proc: subprocess.Popen) -> None:
    import os
    import signal

    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def default_tool_python() -> Path:
    """The Python the tool server runs under: this interpreter (it has fastmcp)."""
    return Path(sys.executable)
