# SPDX-License-Identifier: Apache-2.0
"""The gdb-side half of the `trace` tool. Runs INSIDE gdb's Python, never
imported by the agent:  gdb -q -batch -x gdb_tracer.py --args <harness>

Given one input, answer two questions from the real run and report them as
JSON events between @@TRACE_JSON@@ / @@TRACE_END@@:

  where did it go     a non-stopping breakpoint on every function the project's
                      own source defines -> the dynamic call sequence + counts
  why did it stop     three stop kinds, each with evidence:
                        a function returned (value + where to)   -- targets only
                        longjmp / throw / abort / exit            -- args of every
                                                                     frame on the stack
                        a signal (sanitizer crash)               -- the stack

Parameters come from the environment (the agent sets them; the model never
sees this file):
  FB_INPUT     the input file (required)
  FB_TARGETS   comma-separated functions whose args + return value are wanted
               (optional; the two questions above do not depend on it)
  FB_FILES     comma-separated source-path prefixes to break on; default: every
               file that is not under a system path (/usr, /lib, compiler-rt,
               libFuzzer, glibc)
  FB_HIT_CAP   per-function hit cap; past it the breakpoint is disabled and
               the count reads ">=cap" (default 50). Targets and stoppers are
               never capped.
  FB_MAX_SEQ   how many calls the sequence keeps (default 800)
  FB_MAX_BPS   at most this many functions get a breakpoint (default 4000)
  FB_TIMEOUT   seconds; past it the inferior is killed and what was collected
               is still printed (default 150)

Design notes, each the result of a bug:
  * Breakpoints are never created inside a stop() callback (gdb forbids it;
    doing so made one call appear three times). Target breakpoints STOP, and
    the main loop below creates the FinishBreakpoint, then continues.
  * "Why did it stop" for longjmp/abort does not rely on knowing the project's
    error function (png_error, xmlRaiseError, ...): at the stopper the args of
    every project frame on the stack are captured, so the frame that carries
    the message is there whatever it is called.
"""
import json
import os
import re
import time

import gdb

# ---------------------------------------------------------------- parameters
INPUT = os.environ.get("FB_INPUT", "")
TARGETS = [t for t in os.environ.get("FB_TARGETS", "").split(",") if t.strip()]
FILES = [f for f in os.environ.get("FB_FILES", "").split(",") if f.strip()]
HIT_CAP = int(os.environ.get("FB_HIT_CAP", "50"))
MAX_SEQ = int(os.environ.get("FB_MAX_SEQ", "800"))
MAX_BPS = int(os.environ.get("FB_MAX_BPS", "4000"))
TIMEOUT = float(os.environ.get("FB_TIMEOUT", "150"))

# Language/runtime-level "the program gave up here" functions. Project-level
# wrappers (png_error, ...) need not be listed: their args are read off the
# stack when one of these fires.
STOPPERS = ("longjmp", "_longjmp", "__longjmp_chk", "siglongjmp", "__libc_siglongjmp",
            "abort", "__assert_fail", "__cxa_throw", "_exit", "exit")
# DWARF file prefixes/fragments that are not the project under test.
SYSTEM_FILE_MARKERS = ("/usr/", "/lib/", "/build/", "compiler-rt", "libFuzzer", "Fuzzer",
                       "libcxx", "libc++", "glibc", "sysdeps/", "nptl/", "csu/", "<built-in>",
                       "setjmp/", "stdlib/", "signal/", "misc/", "io/", "malloc/", "string/")


def _is_system_path(path: str) -> bool:
    """glibc's debug sources are relative (./nptl/..., ../sysdeps/...), the
    project's are absolute (/src/...) or bare (transcode.c)."""
    return path.startswith(("./", "../")) or any(m in path for m in SYSTEM_FILE_MARKERS)

LOG: list = []
_BP_ADDRS: set = set()
_LAST_STOP = {"sig": None, "hit": -100}
SEQ: list = []
COUNTS: dict = {}
CAPPED: set = set()
T0 = time.time()
HITS = 0

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set breakpoint pending on")
gdb.execute("set print frame-arguments all")
gdb.execute("set print elements 64")
gdb.execute("set print demangle on")
gdb.execute("set width 0")


# ---------------------------------------------------------------- helpers
def _depth() -> int:
    d, f = 0, gdb.selected_frame()
    while f is not None:
        d += 1
        f = f.older()
    return d


def _loc(frame) -> str:
    try:
        sal = frame.find_sal()
        return f"{sal.symtab.filename if sal.symtab else '?'}:{sal.line}"
    except Exception:  # noqa: BLE001
        return "?"


def _is_project_at(at: str) -> bool:
    return bool(at) and at != "?:0" and not _is_system_path(at)


def _is_project(frame) -> bool:
    try:
        sal = frame.find_sal()
        fn = sal.symtab.filename if sal.symtab else ""
    except Exception:  # noqa: BLE001
        return False
    return bool(fn) and not _is_system_path(fn)


def _args_of(frame) -> list:
    """name=value for each argument of `frame`; byte/char pointers also get the
    first 16 bytes as hex, since gdb's string rendering hides binary data."""
    out = []
    try:
        blk = frame.block()
    except RuntimeError:
        return out
    for sym in blk:
        if not sym.is_argument:
            continue
        try:
            v = sym.value(frame)
            s = str(v)
            t = str(v.type.strip_typedefs())
            if t.endswith("*") and any(k in t for k in ("char", "uint8", "int8", "byte")):
                try:
                    raw = gdb.selected_inferior().read_memory(int(v), 16).tobytes()
                    s += "  bytes=" + raw.hex(" ")
                except Exception:  # noqa: BLE001
                    pass
            out.append(f"{sym.name}={s}")
        except Exception as e:  # noqa: BLE001
            out.append(f"{sym.name}=<{e}>")
    return out


def _stack(frame, n: int = 12, with_args: bool = False) -> list:
    """The stack from `frame` outward: one record per frame, args included
    for project frames when asked (that is where an error message lives)."""
    out = []
    g = frame
    for _ in range(n):
        if g is None:
            break
        rec = {"fn": g.name() or "?", "at": _loc(g)}
        if with_args and _is_project(g):
            rec["args"] = _args_of(g)
        out.append(rec)
        g = g.older()
    return out


def _timed_out() -> bool:
    return (time.time() - T0) > TIMEOUT


# ---------------------------------------------------------------- breakpoints
class FinishBP(gdb.FinishBreakpoint):
    """Fires when a target's frame returns; out_of_scope when it never does."""

    def __init__(self, frame, name):
        super().__init__(frame, internal=True)
        self.fname = name

    def stop(self):
        rv = self.return_value
        LOG.append({"ev": "ret", "fn": self.fname,
                    "value": None if rv is None else str(rv),
                    "to": _loc(gdb.selected_frame())})
        return False

    def out_of_scope(self):
        LOG.append({"ev": "ret_lost", "fn": self.fname,
                    "note": "frame left without a normal return (longjmp / exception / abort)"})


class CallBP(gdb.Breakpoint):
    """One per function. Records the call and continues, except for targets,
    which stop so the main loop can attach a FinishBP (not allowed in here)."""

    def __init__(self, name, is_target=False, is_stopper=False):
        super().__init__(name, internal=True)
        self.fname = name
        self.is_target = is_target
        self.is_stopper = is_stopper
        self.hits = 0
        # Several names can resolve to one address (longjmp / _longjmp /
        # siglongjmp are aliases): keep the first breakpoint there, drop the rest,
        # or one call would be recorded once per alias.
        try:
            addrs = {loc.address for loc in self.locations}
        except Exception:  # noqa: BLE001
            addrs = set()
        if addrs and addrs <= _BP_ADDRS:
            self.delete()
            raise ValueError(f"{name}: alias of an existing breakpoint")
        _BP_ADDRS.update(addrs)

    def stop(self):
        global HITS
        self.hits += 1
        HITS += 1
        f = gdb.selected_frame()
        name = self.fname      # not f.name(): an inlined callee's bp stops in the caller's frame
        d = _depth()
        COUNTS[name] = COUNTS.get(name, 0) + 1
        if len(SEQ) < MAX_SEQ:
            SEQ.append((name, d))
        if self.is_stopper:
            # One longjmp passes several breakpoints in a row (the sanitizer's
            # interceptor, then libc, under 4 alias names that only resolve to one
            # address once libc is loaded). Same project stack within a few hits
            # = the same event: record it once.
            stack = _stack(f, 12, with_args=True)
            sig = tuple((r["fn"], r["at"]) for r in stack if _is_project_at(r["at"]))
            if sig and sig == _LAST_STOP["sig"] and HITS - _LAST_STOP["hit"] <= 8:
                COUNTS[name] -= 1
                if SEQ and SEQ[-1] == (name, d):
                    SEQ.pop()
                return False
            _LAST_STOP["sig"], _LAST_STOP["hit"] = sig, HITS
            LOG.append({"ev": "stop", "fn": name, "depth": d, "at": _loc(f),
                        "args": _args_of(f), "stack": stack})
        if self.is_target:
            LOG.append({"ev": "call", "fn": name, "depth": d, "at": _loc(f), "args": _args_of(f)})
            return True           # the main loop attaches the FinishBP
        if not self.is_stopper and self.hits >= HIT_CAP:
            self.enabled = False  # hot function: stop paying for it
            CAPPED.add(name)
        return _timed_out()       # stop so the loop can kill on timeout


def _project_functions() -> list:
    """Every function DWARF places in a non-system file (or under FB_FILES)."""
    txt = gdb.execute("info functions -n", to_string=True)
    names, cur = [], None
    seen = set()
    for line in txt.splitlines():
        m = re.match(r"^File (.+):$", line)
        if m:
            cur = m.group(1)
            continue
        if cur is None:
            continue
        if FILES:
            ok = any(cur.startswith(p) for p in FILES)
        else:
            ok = not _is_system_path(cur)
        if not ok:
            continue
        m = re.match(r"^\d+:\s+(.*)$", line)
        if not m:
            continue
        head = m.group(1).split("(")[0].strip()
        if not head:
            continue
        nm = head.split()[-1].lstrip("*&")
        if not re.match(r"^[A-Za-z_][\w:~]*$", nm) or nm in _TYPE_WORDS:
            continue
        if nm not in seen:
            seen.add(nm)
            names.append(nm)
    return names


_TYPE_WORDS = {"int", "void", "char", "long", "unsigned", "signed", "const", "short",
               "double", "float", "bool", "static", "inline", "operator", "struct",
               "enum", "union", "class", "typename"}


def _setup() -> None:
    n_proj = 0
    want = _project_functions()[:MAX_BPS]
    tset, sset = set(TARGETS), set(STOPPERS)
    for n in want:
        if n in tset or n in sset:
            continue
        try:
            CallBP(n)
            n_proj += 1
        except Exception:  # noqa: BLE001
            pass
    for n in TARGETS:
        try:
            CallBP(n, is_target=True)
        except Exception as e:  # noqa: BLE001
            LOG.append({"ev": "bp_err", "fn": n, "err": str(e)[:80]})
    for n in STOPPERS:
        try:
            CallBP(n, is_stopper=True)
        except Exception:  # noqa: BLE001 -- alias of one already set, or absent
            pass
    LOG.append({"ev": "setup", "project_functions": len(want), "breakpoints": n_proj,
                "targets": TARGETS, "t": round(time.time() - T0, 2)})


# ---------------------------------------------------------------- the run loop
_last_stop = {"ev": None}


def _on_stop(ev):
    _last_stop["ev"] = ev


def _alive() -> bool:
    try:
        return gdb.selected_inferior().pid != 0
    except Exception:  # noqa: BLE001
        return False


def _run() -> None:
    gdb.events.stop.connect(_on_stop)
    outcome = None
    try:
        gdb.execute(f"run {INPUT}")
    except gdb.error as e:
        LOG.append({"ev": "run_err", "err": str(e)[:200]})
    while _alive():
        ev = _last_stop["ev"]
        _last_stop["ev"] = None
        if isinstance(ev, gdb.SignalEvent):
            f = gdb.selected_frame()
            LOG.append({"ev": "signal", "sig": ev.stop_signal, "stack": _stack(f, 16, with_args=True)})
            outcome = "signal"
            gdb.execute("kill")
            break
        if _timed_out():
            LOG.append({"ev": "timeout", "after_s": round(time.time() - T0, 1)})
            outcome = "timeout"
            gdb.execute("kill")
            break
        if isinstance(ev, gdb.BreakpointEvent):
            for bp in ev.breakpoints:
                if getattr(bp, "is_target", False):
                    try:
                        FinishBP(gdb.selected_frame(), bp.fname)
                    except Exception as e:  # noqa: BLE001
                        LOG.append({"ev": "finish_err", "fn": bp.fname, "err": str(e)[:80]})
        try:
            gdb.execute("continue")
        except gdb.error as e:
            LOG.append({"ev": "run_err", "err": str(e)[:200]})
            break
    LOG.append({"ev": "exit", "outcome": outcome or "exited", "code": _EXIT["code"],
                "hits": HITS, "t": round(time.time() - T0, 2)})


_EXIT = {"code": None}


def _exit_code(ev):
    _EXIT["code"] = getattr(ev, "exit_code", None)


gdb.events.exited.connect(_exit_code)

_setup()
_run()

print("@@TRACE_JSON@@")
for r in LOG:
    print(json.dumps(r))
print(json.dumps({"ev": "seq", "n": len(SEQ), "truncated": len(SEQ) >= MAX_SEQ,
                  "seq": ["%s:%d" % s for s in SEQ]}))
print(json.dumps({"ev": "counts", "distinct": len(COUNTS), "capped": sorted(CAPPED),
                  "top": sorted(COUNTS.items(), key=lambda kv: -kv[1])[:40]}))
print("@@TRACE_END@@")
