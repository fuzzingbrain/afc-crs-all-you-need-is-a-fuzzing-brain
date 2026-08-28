# SPDX-License-Identifier: Apache-2.0
"""The four tools, and their Claude schemas.

read / glob / grep to navigate the source, bash to build a candidate input and
run ./submit. Everything the agent does to the world goes through here, so this
is also where the sandbox is honoured: bash runs through the shell the bench
handed us in $FBAGENT_SHELL, which masks the Docker socket and blocks the
network. If that variable is unset (running the agent by hand), it falls back to
a plain shell.

Paths are confined to the working directory. The agent is given the challenge
source and nothing else; a tool that could read outside it could read the answer
the bench deliberately kept out of the workspace.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

WORKSPACE = Path.cwd()
_SANDBOX_SHELL = os.environ.get("FBAGENT_SHELL", "/bin/bash")
_READ_LIMIT = 2000


def _resolve(rel: str) -> Path:
    """A workspace-relative path, or an error if it escapes."""
    p = (WORKSPACE / rel).resolve()
    if p != WORKSPACE and WORKSPACE not in p.parents:
        raise ValueError(f"path is outside the workspace: {rel}")
    return p


# ------------------------------------------------------------------ implementations

def read_file(path: str, offset: int = 1, limit: int = _READ_LIMIT) -> str:
    p = _resolve(path)
    if not p.is_file():
        return f"error: not a file: {path}"
    try:
        lines = p.read_text(errors="replace").splitlines()
    except Exception as e:
        return f"error: {e}"
    start = max(1, offset)
    chunk = lines[start - 1: start - 1 + limit]
    if not chunk:
        return f"error: offset {offset} is past the end ({len(lines)} lines)"
    width = len(str(start + len(chunk)))
    body = "\n".join(f"{str(start + i).rjust(width)}\t{ln[:2000]}"
                     for i, ln in enumerate(chunk))
    if start - 1 + limit < len(lines):
        body += f"\n... {len(lines) - (start - 1 + limit)} more lines; read from offset {start + limit}"
    return body


def glob_files(pattern: str, limit: int = 200) -> str:
    hits = sorted(str(p.relative_to(WORKSPACE)) for p in WORKSPACE.glob(pattern)
                  if p.is_file())
    if not hits:
        return "no files match"
    out = hits[:limit]
    tail = "" if len(hits) <= limit else f"\n... {len(hits) - limit} more"
    return "\n".join(out) + tail


def grep(pattern: str, glob: str | None = None, limit: int = 100) -> str:
    rg = shutil.which("rg")
    if rg:
        cmd = [rg, "--line-number", "--no-heading", "--color=never", pattern]
        if glob:
            cmd += ["--glob", glob]
    else:
        cmd = ["grep", "-rn", pattern, "."]
    try:
        out = subprocess.run(cmd, cwd=WORKSPACE, capture_output=True, text=True,
                             timeout=60)
    except Exception as e:
        return f"error: {e}"
    lines = (out.stdout or "").splitlines()
    if not lines:
        return "no matches"
    tail = "" if len(lines) <= limit else f"\n... {len(lines) - limit} more matches"
    return "\n".join(lines[:limit]) + tail


def bash(command: str, timeout: int = 120) -> str:
    """Run a command through the sandbox shell. This is how the agent writes a
    candidate input (python3 ...) and tests it (./submit cand.bin)."""
    try:
        out = subprocess.run([_SANDBOX_SHELL, "-c", command], cwd=WORKSPACE,
                             capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"error: command exceeded {timeout}s"
    except Exception as e:
        return f"error: {e}"
    body = (out.stdout or "") + (out.stderr or "")
    if out.returncode != 0:
        body += f"\n[exit {out.returncode}]"
    return body[-8000:] or "(no output)"


# ------------------------------------------------------------------ dispatch + schemas

_IMPL = {"read": read_file, "glob": glob_files, "grep": grep, "bash": bash}


def run_tool(name: str, args: dict) -> tuple[str, bool]:
    """Run a tool. Returns (output, is_error).

    is_error is the flag the tool_result block carries back: a tool that failed
    must be reported to the model with is_error=True rather than dropped or
    passed off as an ordinary result, so it can correct course instead of
    trusting a failure as data.
    """
    fn = _IMPL.get(name)
    if not fn:
        return f"error: unknown tool {name}", True
    try:
        out = fn(**args)
    except TypeError as e:
        return f"error: bad arguments for {name}: {e}", True
    except ValueError as e:
        return f"error: {e}", True
    except Exception as e:  # noqa: BLE001 - a tool must never take the loop down
        return f"error: {name} failed: {e}", True
    # The tool impls encode their own failures as an "error:" prefix.
    return out, out.startswith("error:")


SCHEMAS = [
    {
        "name": "read",
        "description": "Read a file (or a slice), returned with line numbers. "
                       "Paths are relative to the challenge directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "offset": {"type": "integer", "description": "first line, 1-based"},
                "limit": {"type": "integer", "description": "how many lines"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "glob",
        "description": "List files matching a glob pattern, e.g. '**/*.c' or 'src/*.h'.",
        "input_schema": {
            "type": "object",
            "properties": {"pattern": {"type": "string"}},
            "required": ["pattern"],
        },
    },
    {
        "name": "grep",
        "description": "Search file contents for a pattern (ripgrep). Optionally "
                       "restrict to a glob.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "glob": {"type": "string"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "bash",
        "description": "Run a shell command in the challenge directory. Use it to "
                       "write a candidate input (e.g. with python3) and to test it "
                       "with ./submit <file>. No network.",
        "input_schema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
]
