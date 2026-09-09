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
import re
import shutil
import subprocess
import time
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


# Coverage-guided fuzzing is a *general* capability, so it is allowed by default;
# a benchmark that wants results attributable to reasoning + the analysis tools
# (not brute force) turns it off with FBAGENT_NO_FUZZING=1. The signatures below
# are the ones that only a fuzzing campaign uses — building a libFuzzer binary
# (-fsanitize=fuzzer), running one in explore mode (-fork/-jobs/-max_total_time/
# -artifact_prefix), or AFL/honggfuzz — so a plain "run the harness on one input"
# is never caught.
_FUZZ_SIG = re.compile(
    r"-fsanitize=fuzzer|-fork=\d|-jobs=[1-9]|-max_total_time=|-artifact_prefix=|"
    r"\bafl-(fuzz|clang|cc|gcc|g\+\+|clang\+\+|showmap|cmin|tmin)\b|\bhonggfuzz\b",
    re.IGNORECASE)


def _fuzzing_disabled() -> bool:
    return os.environ.get("FBAGENT_NO_FUZZING", "").strip().lower() in ("1", "true", "yes", "on")


def bash(command: str, timeout: int = 120) -> str:
    """Run a command through the sandbox shell. This is how the agent writes a
    candidate input (python3 ...) and tests it (./submit cand.bin)."""
    if _fuzzing_disabled() and _FUZZ_SIG.search(command):
        return ("error: coverage-guided fuzzing is disabled for this benchmark. "
                "Do not build or run a fuzzer (libFuzzer -fork/-max_total_time/"
                "-fsanitize=fuzzer, AFL, honggfuzz). Find the bug by reading the "
                "code and constructing targeted inputs — use the worklist, gates, "
                "and trace tools.")
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


_FRAME_RE = re.compile(
    r"#\d+\s+(?:0x[0-9a-fA-F]+\s+in\s+)?(?P<func>[A-Za-z_][\w:~<>]*)\s*"
    r"\([^)]*\)(?:\s+at\s+(?P<loc>[^\s:]+:\d+))?")
_SIG_RE = re.compile(r"received signal (?P<sig>SIG[A-Z]+)")
# The trace bridge: the agent runs on the host with no graded binary, so `trace`
# drops a request here and the bench harness serves it by running gdb in the
# challenge container (see external.py's Judge). Same `.fbbench` channel `submit`
# uses. Absent this dir, we are not running under the harness and trace is a no-op.
_TRACE_REQ = WORKSPACE / ".fbbench" / "trace_req"
_TRACE_RES = WORKSPACE / ".fbbench" / "trace_res"


def _parse_trace(raw: str, target: str) -> str:
    """Turn the raw gdb batch output into a compact 'where it went / what it hit'
    report: whether the input reached `target` (with the live args there), and,
    if it faulted, the signal and the crash backtrace."""
    reached = f"@@REACHED {target}@@" in raw
    lines = raw.splitlines()
    out = []
    if reached:
        # `info args` sits between the marker and the first backtrace frame.
        try:
            i = next(k for k, l in enumerate(lines) if l.startswith(f"@@REACHED {target}@@"))
        except StopIteration:
            i = -1
        args = []
        for l in lines[i + 1:]:
            if l.startswith("#") or l.startswith("@@") or "received signal" in l or "Thread" in l:
                break
            if "=" in l and l.strip():
                args.append(l.strip())
        out.append(f"reached {target}: YES"
                   + (f"   args: {'; '.join(args)}" if args else ""))
    else:
        out.append(f"reached {target}: no — this input did not hit it")

    sig = _SIG_RE.search(raw)
    if sig:
        # The crash backtrace is everything after the fault signal (the reach
        # frames printed at the breakpoint come before it), so the top frame here
        # is the real fault site, not a frame the input merely passed through.
        crash_bt = raw[sig.end():]
        frames = []
        for l in crash_bt.splitlines():
            m = _FRAME_RE.search(l)
            if m:
                loc = m.group("loc") or ""
                frames.append(f"  {m.group('func')}" + (f"  ({loc})" if loc else ""))
        frames = frames[:8]
        top = frames[0].strip() if frames else "?"
        out.append(f"crashed: YES — {sig.group('sig')} in {top}")
        out += frames
    else:
        out.append("crashed: no — ran to completion without a fault")
    out.append("(LeakSanitizer is off under gdb; score memory-leak faults through ./submit.)")
    return "\n".join(out)


def trace(input: str, target: str) -> str:
    """Run one candidate input under gdb against the graded binary and report,
    from the real run, where it reached and -- if it faulted -- the crash site
    with the live values there. Unlike a static crash-stack parse it works on a
    clean run too (did the input reach `target`?). LeakSanitizer is off under the
    debugger, so a memory-leak fault will not surface here -- score those through
    ./submit, which keeps the sanitizer on.

    The gdb run happens in the challenge container (the agent's host workspace has
    no graded binary); this drops a request on the `.fbbench` bridge and reads the
    raw gdb output back, then parses it here."""
    inp = Path(input)
    if not inp.is_file():
        return f"error: no input file at {input!r}; write your candidate bytes there first."
    tgt = (target or "").strip().split("::")[-1]
    if not tgt:
        return "error: give a target function to break on (the sink you are aiming for)."
    if not _TRACE_REQ.parent.is_dir():
        return "error: trace unavailable — not running under the bench harness (no bridge)."
    _TRACE_REQ.mkdir(parents=True, exist_ok=True)
    rid = f"{time.time_ns()}-{os.getpid()}"
    try:
        shutil.copyfile(inp, _TRACE_REQ / f"{rid}.bin")
        (_TRACE_REQ / f"{rid}.tgt").write_text(tgt)     # written last = request ready
    except OSError as e:
        return f"error: could not post trace request: {e}"
    res = _TRACE_RES / rid
    for _ in range(1100):                               # ~220s; the bridge caps gdb at 180s
        if res.exists():
            raw = res.read_text()
            res.unlink(missing_ok=True)
            if raw.startswith("error:"):
                return raw.strip()
            return _parse_trace(raw, tgt)
        time.sleep(0.2)
    return "error: trace timed out waiting for the bridge."


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
         "gates": gates, "trace": trace, "diversify": diversify}


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
    _schema("trace", {"input": {"type": "string"}, "target": {"type": "string"}},
            ["input", "target"]),
    _schema("diversify", {"cracked": {"type": "string"}}, []),
]

# Controlled-experiment switch: drop the dynamic `trace` tool so a run's result
# is attributable to static reasoning + the worklist alone, with no runtime
# feedback. Read from the env at import — set it before launching python
# (e.g. `FBAGENT_NO_TRACE=1 python3 -m fbagent.run ...`).
import os as _os  # noqa: E402
def _flag(name):
    return _os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")
if _flag("FBAGENT_NO_TRACE"):
    SCHEMAS = [s for s in SCHEMAS if s["name"] != "trace"]
    _IMPL.pop("trace", None)
# Ablation: drop the deterministic static-analysis helpers (gates, diversify) so a
# "bare + worklist" run isolates the worklist alone. Leaves read/glob/grep/bash.
if _flag("FBAGENT_NO_HELPERS"):
    SCHEMAS = [s for s in SCHEMAS if s["name"] not in ("gates", "diversify")]
    _IMPL.pop("gates", None)
    _IMPL.pop("diversify", None)
