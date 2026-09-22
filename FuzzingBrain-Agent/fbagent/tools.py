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

import hashlib
import json
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
                "code and constructing targeted inputs — use the gates and trace "
                "tools.")
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
    from .worklist import analysis
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
# The gdb-side script the bridge runs for us (gdb_tracer.py, next to this file).
# It is copied into the request so the bench needs nothing from this package.
_TRACER_PY = Path(__file__).resolve().with_name("gdb_tracer.py")

# Whether anything is actually answering on the bridge. The directory existing
# proves only that `submit` is wired, not that a trace responder is listening.
# Where none is, every call used to wait the full 220 seconds before giving up:
# 18 calls across the recorded D5 runs returned 8 timeouts and zero reports, and
# each timeout cost 220s of a 1800s cell. So the first call probes briefly and,
# if nothing has even claimed the request, every later call fails immediately.
_TRACE_PROBE_S = 8.0
_trace_bridge_dead = False
_trace_seen = False   # a responder has answered at least once


def _mark_trace_alive() -> None:
    global _trace_seen
    _trace_seen = True


def _parse_trace_legacy(raw: str, target: str) -> str:
    """The pre-tracer report, for a bench that still runs the one-breakpoint
    script: whether the input reached `target`, and the crash stack if any."""
    reached = f"@@REACHED {target}@@" in raw
    lines = raw.splitlines()
    out = []
    if reached:
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


# --- the tracer's JSON events -> the report the model reads -------------------
_RUNTIME_FNS = {"longjmp", "_longjmp", "__longjmp_chk", "siglongjmp", "__libc_siglongjmp",
                "abort", "__assert_fail", "__cxa_throw", "_exit", "exit"}
_SYS_AT = ("/usr/", "/lib/", "/build/", "compiler-rt", "libFuzzer", "Fuzzer", "libcxx",
           "libc++", "glibc", "sysdeps/", "nptl/", "csu/", "stdlib/", "setjmp/", "?:0")
_ASAN_ERR = re.compile(r"==\d+==\s*ERROR:\s*(?P<msg>[^\n]+)")
_ASAN_FRAME = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?P<fn>\S+)\s+(?P<loc>/?\S+:\d+)", re.M)
_SEQ_LINES = 60


def _trace_events(raw: str) -> list[dict] | None:
    if "@@TRACE_JSON@@" not in raw:
        return None
    body = raw.split("@@TRACE_JSON@@", 1)[1].split("@@TRACE_END@@", 1)[0]
    evs = []
    for l in body.splitlines():
        l = l.strip()
        if l.startswith("{"):
            try:
                evs.append(json.loads(l))
            except json.JSONDecodeError:
                pass
    return evs


def _proj_at(at: str) -> bool:
    return bool(at) and not any(m in at for m in _SYS_AT)


def _short_at(at: str) -> str:
    return at.rsplit("/", 1)[-1] if at else "?"


_ARG_STR = re.compile(r'^(?P<name>\w+)=0x[0-9a-fA-F]+(?: <[^>]*>)? "(?P<txt>[^"]*)"(?P<rest>.*)$', re.S)
_ARG_BYTES = re.compile(r"  bytes=(?P<hex>[0-9a-f ]+)$")


def _fmt_arg(a: str) -> str:
    """One `name=value` from the tracer, made readable: a clean C string shows
    as name="text", binary data as name=bytes[..], optimized-out as ?."""
    a = a.replace("<optimized out>", "?")
    m = _ARG_STR.match(a)
    if m:
        txt, rest = m.group("txt"), m.group("rest")
        clean = txt.isprintable() and "\\" not in txt and "incomplete" not in rest
        if clean and txt:
            return f'{m.group("name")}="{txt}"'
        b = _ARG_BYTES.search(rest)
        if b:
            return f'{m.group("name")}=bytes[{b.group("hex").strip()}]'
    b = _ARG_BYTES.search(a)
    if b:
        return a[:b.start()].split(" ")[0] + f"=bytes[{b.group('hex').strip()}]"
    return a[:110]


def _fmt_args(args: list, limit: int = 5) -> str:
    out = [_fmt_arg(a) for a in args[:limit]]
    tail = "" if len(args) <= limit else f" (+{len(args) - limit} more)"
    return ", ".join(out) + tail


def _frame_line(fr: dict, indent: str = "    ") -> str:
    s = f"{indent}{fr.get('fn', '?')}  ({_short_at(fr.get('at', ''))})"
    args = fr.get("args") or []
    if args:
        s += "   " + _fmt_args(args)
    return s


def _stop_message(stack: list) -> tuple[str | None, str | None, int]:
    """(message, raised-from, index) from the stop stack: the first string
    argument found walking outward through project frames is the error message;
    the frames that carry it are the error wrappers (png_error and friends); the
    project frame just outside the last wrapper is where the error was raised.
    `index` is that frame's position in `stack` (or the first carrier's)."""
    msg = None
    last_carrier = -1
    for i, fr in enumerate(stack):
        if not _proj_at(fr.get("at", "")):
            continue
        strings = [_fmt_arg(a).split("=", 1)[1] for a in (fr.get("args") or [])
                   if '="' in _fmt_arg(a)]
        if msg is None and strings:
            msg = strings[0]
        if msg is not None and msg in strings:
            last_carrier = i
        elif msg is not None:
            break
    if msg is None:
        return None, None, 0
    raiser = next((fr for fr in stack[last_carrier + 1:] if _proj_at(fr.get("at", ""))), None)
    idx = stack.index(raiser) if raiser else last_carrier
    return msg, (f"{raiser.get('fn')} ({_short_at(raiser.get('at', ''))})" if raiser else None), idx


def _chain(frames: list, n: int = 5) -> str:
    """fn (file:line) ← fn (file:line) ← ..., innermost first."""
    return " ← ".join(f"{fr.get('fn', '?')} ({_short_at(fr.get('at', ''))})" for fr in frames[:n])


def _summarize_trace(raw: str, targets: list[str], verbose: bool = False) -> str:
    """The report the model reads.

    Brief (default): the outcome, one line on why it stopped, the deepest call,
    and each target's reached / returned / not-reached status -- about ten
    lines, enough to answer "did it get there, and if not what rejected it".
    Verbose: the same plus the live arguments of every project frame at the
    stop, every function reached with its call count, and the indented call
    sequence -- for when the brief answer is not enough to pick the next input.
    """
    evs = _trace_events(raw)
    if evs is None:
        return _parse_trace_legacy(raw, targets[0] if targets else "")
    by: dict[str, list] = {}
    for e in evs:
        by.setdefault(e.get("ev"), []).append(e)
    setup = (by.get("setup") or [{}])[0]
    exit_ev = (by.get("exit") or [{}])[-1]
    seq_ev = (by.get("seq") or [{}])[0]
    counts_ev = (by.get("counts") or [{}])[0]
    seq = seq_ev.get("seq") or []
    counts = [(n, c) for n, c in (counts_ev.get("top") or []) if n not in _RUNTIME_FNS]
    signal = (by.get("signal") or [None])[-1]
    # a stop is interesting only if the project is on the stack (libFuzzer's own
    # exit() at the end of a normal run has no project frame)
    stops = [e for e in by.get("stop", [])
             if any(_proj_at(fr.get("at", "")) for fr in e.get("stack", []))]
    hits = exit_ev.get("hits", 0)
    out = [f"trace: {hits} calls into {counts_ev.get('distinct', '?')} project functions, "
           f"{exit_ev.get('t', '?')}s under gdb"
           + (f" (breakpoints on {setup.get('breakpoints')} functions)"
              if verbose and setup.get("breakpoints") else "")]

    # ---- outcome + why it stopped
    if signal:
        m = _ASAN_ERR.search(raw)
        out.append(f"outcome: CRASHED — {signal.get('sig')}"
                   + (f"; sanitizer: {m.group('msg').strip()}" if m else ""))
        # only the fault stack: the report goes on with "allocated by" / "freed by"
        first = raw.split("ERROR:", 1)[1] if "ERROR:" in raw else raw
        first = first.split("\n\n", 1)[0]
        frames = [(fm.group("fn"), fm.group("loc")) for fm in _ASAN_FRAME.finditer(first)]
        proj = [{"fn": fn, "at": loc} for fn, loc in frames if _proj_at(loc)]
        if not proj:
            proj = [fr for fr in signal.get("stack", []) if _proj_at(fr.get("at", ""))]
        if proj and verbose:
            out.append("  fault site (project frames, innermost first):")
            out += [f"    {fr['fn']}  ({_short_at(fr['at'])})" for fr in proj[:6]]
        elif proj:
            out.append(f"  fault site: {_chain(proj, 4)}")
    elif exit_ev.get("outcome") == "timeout":
        out.append(f"outcome: KILLED after {exit_ev.get('t')}s under gdb (timeout); the trace below is partial")
    elif stops:
        st = stops[0]
        kind = st.get("fn", "")
        if "longjmp" in kind:
            label = "the program gave up (longjmp back to the harness)"
        elif kind == "__cxa_throw":
            label = "a C++ exception was thrown"
        elif kind in ("abort", "__assert_fail"):
            label = f"{kind}() was called"
        else:
            label = f"{kind}() was called from inside the harness"
        out.append(f"outcome: no crash; {label}; process exit code {exit_ev.get('code')}")
        proj_frames = [fr for fr in st.get("stack", []) if _proj_at(fr.get("at", ""))]
        if verbose:
            out.append("  why it stopped — the stack at that moment, innermost first, with live arguments:")
            out += [_frame_line(fr) for fr in proj_frames[:8]]
            if len(stops) > 1:
                out.append(f"  ({len(stops) - 1} more such stop(s) later in the run)")
        else:
            stack = st.get("stack", [])
            msg, raiser, idx = _stop_message(stack)
            line = "  why: "
            if msg and raiser:
                line += f"{msg} raised from {raiser}; "
            elif msg:
                line += f"{msg}; "
            # the chain from the raising frame outward (the error wrappers
            # inside it are plumbing, not the answer)
            chain = [fr for fr in stack[idx:] if _proj_at(fr.get("at", ""))] if msg else proj_frames
            line += "stack: " + _chain(chain, 6)
            out.append(line)
    else:
        out.append(f"outcome: no crash; ran to the end, process exit code {exit_ev.get('code')}")

    # ---- deepest project call
    base = int(seq[0].rsplit(":", 1)[1]) if seq and ":" in seq[0] else 0
    if seq:
        deepest = max(((int(x.rsplit(":", 1)[1]) - base, x.rsplit(":", 1)[0]) for x in seq
                       if x.rsplit(":", 1)[0] not in _RUNTIME_FNS), default=None)
        if deepest:
            out.append(f"deepest call: {deepest[1]}  ({deepest[0]} levels below the harness entry)")

    # ---- targets
    if targets:
        out.append("targets:")
        calls = by.get("call", [])
        rets = by.get("ret", [])
        lost = by.get("ret_lost", [])
        for t in targets:
            c = [e for e in calls if e.get("fn") == t]
            if not c:
                out.append(f"  {t}: NOT reached")
                continue
            line = f"  {t}: reached ({len(c)} call{'s' if len(c) > 1 else ''})"
            args = c[0].get("args") or []
            if verbose and args:
                line += f"; args at first call: {_fmt_args(args)}"
            t_rets = [e for e in rets if e.get("fn") == t]
            n_lost = sum(1 for e in lost if e.get("fn") == t)
            if verbose:
                out.append(line)
                for r in t_rets[:3]:
                    v = r.get("value")
                    out.append(f"      returned {v if v is not None else '(void)'} -> {_short_at(r.get('to', ''))}")
                if n_lost:
                    out.append(f"      {n_lost} call(s) never returned: the frame was dropped by longjmp / exception / abort")
            else:
                bits = []
                if t_rets:
                    vals = [r.get("value") if r.get("value") is not None else "(void)" for r in t_rets[:3]]
                    bits.append("returned " + ", ".join(str(v) for v in vals))
                if n_lost:
                    bits.append(f"{n_lost} call(s) never returned (frame dropped by longjmp / exception / abort)")
                out.append(line + ("; " + "; ".join(bits) if bits else ""))

    if not verbose:
        out.append("(verbose=true adds the live arguments at the stop, every function reached, and the call sequence)")
        return "\n".join(out)

    # ---- reached
    if counts:
        out.append("functions reached (calls): "
                   + ", ".join(f"{n}×{c}" if c > 1 else n for n, c in counts[:30])
                   + (" ..." if len(counts) > 30 else ""))
        capped = counts_ev.get("capped") or []
        if capped:
            out.append(f"  (hot functions capped at {len(capped)}: {', '.join(capped[:8])}"
                       + (" ..." if len(capped) > 8 else "") + ")")

    # ---- the sequence, compressed and indented by depth
    if seq:
        items: list = []
        for x in seq:
            fn, d = x.rsplit(":", 1)
            if fn in _RUNTIME_FNS:
                continue
            d = int(d) - base
            if items and items[-1][0] == fn and items[-1][1] == d:
                items[-1][2] += 1
            else:
                items.append([fn, d, 1])
        lines = [f"  {'  ' * max(0, d)}{fn}" + (f" ×{k}" if k > 1 else "") for fn, d, k in items]
        if len(lines) > _SEQ_LINES:
            lines = lines[:_SEQ_LINES - 15] + [f"  ... {len(lines) - _SEQ_LINES} calls omitted ..."] + lines[-15:]
        out.append("call sequence (indent = stack depth; approximate where the compiler inlined):")
        out += lines
        if seq_ev.get("truncated"):
            out.append("  (sequence capped; counts above are complete)")
    out.append("(LeakSanitizer is off under gdb; score memory-leak faults through ./submit.)")
    return "\n".join(out)


# The last few raw gdb outputs, keyed by (input bytes, targets): a brief call
# followed by a verbose one on the same input renders from the same run instead
# of paying for gdb twice.
_TRACE_CACHE: dict[tuple, str] = {}
_TRACE_CACHE_MAX = 16


def trace(input: str, target: str = "", verbose: bool = False) -> str:
    """Run one candidate input under gdb against the graded binary and report,
    from the real run, where it went and why it stopped: the stop point with
    the live values on the stack (an error message, a longjmp, an abort, a
    sanitizer fault), the deepest call, and -- for any `target` functions
    named -- whether each was reached and what it returned. `verbose` adds the
    full call sequence, every function reached, and the arguments at the stop.
    Works on a clean run as well as a crash. LeakSanitizer is off under the
    debugger, so a memory-leak fault will not surface here -- score those
    through ./submit.

    The gdb run happens in the challenge container (the agent's host workspace
    has no graded binary): this drops the input, the gdb-side script and the
    target list on the `.fbbench` bridge, reads the raw gdb output back, and
    turns the tracer's JSON events into the report here."""
    global _trace_bridge_dead
    inp = Path(input)
    if not inp.is_file():
        return f"error: no input file at {input!r}; write your candidate bytes there first."
    targets = [t.strip().split("::")[-1] for t in (target or "").replace(";", ",").split(",")
               if t.strip()]
    if isinstance(verbose, str):
        verbose = verbose.strip().lower() in ("1", "true", "yes", "on")
    try:
        key = (hashlib.sha256(inp.read_bytes()).hexdigest(), tuple(targets))
    except OSError as e:
        return f"error: could not read {input!r}: {e}"
    if key in _TRACE_CACHE:
        return _summarize_trace(_TRACE_CACHE[key], targets, verbose=bool(verbose))
    if not _TRACE_REQ.parent.is_dir():
        return "error: trace unavailable — not running under the bench harness (no bridge)."
    if _trace_bridge_dead:
        return ("error: trace is unavailable in this environment (no debugger bridge "
                "answered earlier in this run). Read the run time on ./submit's clean "
                "verdict instead: non-zero means the target did real work on your input.")
    _TRACE_REQ.mkdir(parents=True, exist_ok=True)
    rid = f"{time.time_ns()}-{os.getpid()}"
    try:
        shutil.copyfile(inp, _TRACE_REQ / f"{rid}.bin")
        shutil.copyfile(_TRACER_PY, _TRACE_REQ / f"{rid}.tracer.py")
        (_TRACE_REQ / f"{rid}.tgt").write_text(",".join(targets))   # written last = request ready
    except OSError as e:
        return f"error: could not post trace request: {e}"
    res = _TRACE_RES / rid
    waited = 0.0
    while waited < 220.0:                               # the bridge caps gdb at 180s
        if res.exists():
            raw = res.read_text()
            res.unlink(missing_ok=True)
            _mark_trace_alive()
            if raw.startswith("error:"):
                return raw.strip()
            if len(_TRACE_CACHE) >= _TRACE_CACHE_MAX:
                _TRACE_CACHE.pop(next(iter(_TRACE_CACHE)))
            _TRACE_CACHE[key] = raw
            return _summarize_trace(raw, targets, verbose=bool(verbose))
        # The responder claims a request by removing its `.tgt` the moment it
        # picks it up, so a `.tgt` still sitting here means nobody is home --
        # whereas the `.bin` stays for the whole run and proves nothing. That
        # distinction is what lets a gdb run that legitimately takes two minutes
        # avoid being mistaken for an absent bridge.
        if not _trace_seen and waited >= _TRACE_PROBE_S \
                and (_TRACE_REQ / f"{rid}.tgt").exists():
            _trace_bridge_dead = True
            (_TRACE_REQ / f"{rid}.bin").unlink(missing_ok=True)
            (_TRACE_REQ / f"{rid}.tgt").unlink(missing_ok=True)
            return ("error: trace is unavailable -- no debugger bridge is answering in "
                    "this environment, so reachability cannot be confirmed this way. "
                    "Use the run time on ./submit's clean verdict instead: a non-zero "
                    "time means the target did real work on your input.")
        time.sleep(0.2)
        waited += 0.2
    return "error: trace timed out waiting for the bridge."


def diversify(cracked: str = "") -> str:
    """Deterministic Furthest-Point-First: given the functions where you already
    found distinct crashes (comma-separated), return the reachable sinks that are
    *furthest* from them in the call structure -- the next targets most likely to
    be a different fault. Needs at least one crashed function."""
    from .worklist import analysis, frontier
    try:
        ctx = analysis.build(WORKSPACE)
        if not ctx.entry:
            return "no entry point; cannot rank targets."
        names = [x.strip() for x in cracked.replace(";", ",").split(",") if x.strip()]
        if not names:
            return ("give diversify the functions where you already found crashes "
                    "(comma-separated); it ranks the remaining reachable sinks by "
                    "call-graph distance from them.")
        far = frontier.furthest_first(ctx, names)
        if not far:
            return "no reachable sinks to suggest."
        head = ("Furthest reachable sinks from what you already cracked "
                f"({', '.join(names)}), most-different first:")
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
    _schema("trace", {"input": {"type": "string"}, "target": {"type": "string"},
                      "verbose": {"type": "boolean"}},
            ["input"]),
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
