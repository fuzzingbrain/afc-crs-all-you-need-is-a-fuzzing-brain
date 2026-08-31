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


def gates(func: str) -> str:
    """Deterministic P7: the literal input constraints on the static path from
    the harness entry to `func` -- magic bytes, minimum lengths, byte-equality
    gates -- so a seed for that target can be built to satisfy them."""
    from . import analysis
    try:
        return analysis.gates_to(WORKSPACE, func)
    except Exception as e:  # noqa: BLE001
        return f"error: gates failed: {e}"


def reached(stack: str) -> str:
    """Deterministic P4: given the sanitizer/JVM crash report you just saw, name
    the frame in the challenge's own code and its call-graph distance from the
    entry -- where the input actually went, mapped onto the static graph."""
    from . import analysis
    try:
        r = analysis.reached_report(stack, WORKSPACE)
        return r or "no stack frames found in that text."
    except Exception as e:  # noqa: BLE001
        return f"error: reached failed: {e}"


def diversify(cracked: str = "") -> str:
    """Deterministic Furthest-Point-First: given the functions where you already
    found distinct crashes (comma-separated), return the reachable sinks that are
    *furthest* from them in the call structure -- the next targets most likely to
    be a different fault. With none given, returns the nearest-first worklist."""
    from . import analysis, frontier
    try:
        ctx = analysis.build(WORKSPACE)
        if not ctx.entry:
            return "no entry point; cannot rank targets."
        names = [x.strip() for x in cracked.replace(";", ",").split(",") if x.strip()]
        far = frontier.furthest_first(ctx, names)
        if not far:
            return "no reachable sinks to suggest."
        head = ("Furthest reachable sinks from what you already cracked "
                f"({', '.join(names)}), most-different first:" if names
                else "Reachable sinks, nearest-first (no crashes recorded yet):")
        lines = [head]
        for i, s in enumerate(far, 1):
            lines.append(f"{i:2}. [{s.klass}] {s.func}  ({s.file}:{s.line}, dist {s.distance})")
            lines.append(f"      {s.why}")
        return "\n".join(lines)
    except Exception as e:  # noqa: BLE001
        return f"error: diversify failed: {e}"


# ------------------------------------------------------------------ dispatch + schemas

_IMPL = {"read": read_file, "glob": glob_files, "grep": grep, "bash": bash,
         "gates": gates, "reached": reached, "diversify": diversify}


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


# The schema *shape* (parameters, types, what's required) is logic and stays
# here; the model-facing *text* (each description) comes from prompts/tools.yaml
# via prompts.py, so every word the model reads lives under prompts/.
from .prompts import tool_description, tool_param  # noqa: E402


def _param(tool: str, name: str, spec: dict) -> dict:
    line = tool_param(tool, name)
    return {**spec, "description": line} if line else dict(spec)


def _schema(name: str, properties: dict, required: list[str]) -> dict:
    return {
        "name": name,
        "description": tool_description(name),
        "input_schema": {
            "type": "object",
            "properties": {p: _param(name, p, s) for p, s in properties.items()},
            "required": required,
        },
    }


SCHEMAS = [
    _schema("read",
            {"path": {"type": "string"},
             "offset": {"type": "integer"},
             "limit": {"type": "integer"}},
            ["path"]),
    _schema("glob", {"pattern": {"type": "string"}}, ["pattern"]),
    _schema("grep",
            {"pattern": {"type": "string"}, "glob": {"type": "string"}},
            ["pattern"]),
    _schema("bash", {"command": {"type": "string"}}, ["command"]),
    _schema("gates", {"func": {"type": "string"}}, ["func"]),
    _schema("reached", {"stack": {"type": "string"}}, ["stack"]),
    _schema("diversify", {"cracked": {"type": "string"}}, []),
]
