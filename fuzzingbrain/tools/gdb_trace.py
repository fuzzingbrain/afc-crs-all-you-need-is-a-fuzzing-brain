# SPDX-License-Identifier: Apache-2.0
"""
Unified FAST gdb tool: `trace` — one gdb run returns a bundle.

Reach (functions / file:line) + operand values at the sink + crash info, in a
single run. gdb is gdb-15 (ubuntu-24, reads DWARF5); the target binary's own
shared libs are staged to /projlibs and put on the INFERIOR's LD_LIBRARY_PATH
(via `set environment`), so gdb itself stays intact.

The SLOW clamp/watch tool is separate (watchpoints are expensive) — not here.

margin is arithmetic the caller does on the returned operand values; this tool
returns the raw runtime values.
"""
from __future__ import annotations
import json, os, re, shutil, subprocess, tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.fuzzer_spec import parse_fuzzer_spec, libfuzzer_oom_flags, NO_OOM_MEMORY_MB

GDB15_IMAGE = "gdbx-u24"          # ubuntu-24-04 base-runner + gdb 15 (DWARF5-capable)
_LIB_CACHE = Path("/home/ze/fb-graphs/.projlib-cache")
# glibc/runtime core the inferior should take from ubuntu-24, NOT from the project
_CORE = {"libc.so.6", "ld-linux-x86-64.so.2", "libpthread.so.0", "libm.so.6",
         "libdl.so.2", "librt.so.1", "libresolv.so.2", "libgcc_s.so.1", "linux-vdso.so.1"}
_SIG = re.compile(r"received signal SIG(SEGV|ABRT|BUS|FPE|ILL)")
_ASAN = re.compile(r"AddressSanitizer:\s*([\w-]+)")


def _sh(args, timeout=120, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, **kw)


def stage_project_libs(project: str, elf_host_path: str, image: str = None) -> Path:
    """Copy the binary's non-core shared libs from the project image into a host
    cache dir (once per project). Returns the dir to mount as /projlibs.
    `image` overrides the default aixcc-afc/<project>:latest (the run's docker image)."""
    out = _LIB_CACHE / project
    if out.is_dir() and any(out.iterdir()):
        return out
    out.mkdir(parents=True, exist_ok=True)
    img = image or f"aixcc-afc/{project}:latest"
    # ldd inside the project image, on the real binary (mounted)
    r = _sh(["docker", "run", "--rm", "-v", f"{elf_host_path}:/x:ro", img,
             "bash", "-c", "ldd /x"], timeout=120)
    libs = {}
    for m in re.finditer(r"=>\s*(/[^\s]+\.so[^\s]*)", r.stdout):
        p = m.group(1); name = Path(p).name.split(".so")[0] + ".so." + p.split(".so.")[-1] if ".so." in p else Path(p).name
        base = Path(p).name
        if base in _CORE or base.startswith("ld-linux"):
            continue
        libs[base] = p
    if not libs:
        return out
    # copy each lib out of the project image into the host cache dir
    names = " ".join(f"'{v}'" for v in libs.values())
    _sh(["docker", "run", "--rm", "-v", f"{out}:/dst", img,
         "bash", "-c", f"cp -L {names} /dst/ 2>/dev/null || true"], timeout=120)
    return out


def _gen_script(targets: List[str], sink: Optional[str], operands: Dict[str, str]) -> str:
    lines = ["set pagination off", "set confirm off", "set breakpoint pending on",
             # /projlibs = libs staged from the project image; /b/blibs = libs
             # shipped next to the binary (e.g. systemd's libsystemd-shared).
             "set environment LD_LIBRARY_PATH=/projlibs:/b/blibs:/b",
             "handle SIGSEGV SIGABRT SIGBUS SIGFPE stop nopass"]
    for t in targets or []:
        lines += [f"break {t}", "commands", "  silent", f'  printf "HIT:{t}\\n"',
                  "  continue", "end"]
    if sink:
        lines += [f"break {sink}", "commands", "  silent",
                  f'  printf "HIT-SINK:{sink}\\n"',
                  '  printf "STATE-BEGIN\\n"', "  info args", "  info locals",
                  '  printf "STATE-END\\n"', "  continue", "end"]
    lines += ["run",
              'if $_siginfo',
              '  printf "CRASHED:1\\n"',
              "  bt 8",
              "end",
              "quit", ""]
    return "\n".join(lines)


def _parse(out: str, targets: List[str], sink: Optional[str], operands: Dict[str, str]) -> Dict[str, Any]:
    reached = {t: (f"HIT:{t}" in out) for t in (targets or [])}
    sink_reached = bool(sink and f"HIT-SINK:{sink}" in out)
    # operand values from the LAST info-dump before the crash (loop -> overflow iter)
    states = re.findall(r"STATE-BEGIN(.*?)STATE-END", out, re.S)
    ops = {}
    if states and operands:
        last = states[-1]
        for label, expr in operands.items():
            # match "<name> = <value>" for the base variable name in expr
            var = re.sub(r"[^A-Za-z0-9_].*", "", expr.strip().lstrip("(").lstrip("*"))
            m = re.search(rf"\b{re.escape(var)}\s*=\s*([^\n]+)", last)
            if m:
                ops[label] = m.group(1).strip()
    # margin straight from the ASan report (reliable): "N bytes after/before M-byte region"
    asan_margin = None
    am = re.search(r"located (\d+) bytes (after|before) (?:the )?\w*\s*(\d+)-byte region", out)
    if am:
        n = int(am.group(1))
        asan_margin = -(n if am.group(2) == "after" else n)  # <=0 means overflow past the edge
    asan = _ASAN.search(out); sig = _SIG.search(out)
    # UBSan: fatal checks (e.g. signed-integer-overflow; built -fno-sanitize-
    # recover) abort via SIGABRT, which gdb catches -> CRASHED:1. Capture the
    # specific UB type from the last "runtime error:" before the abort, so
    # crash_matches_sp can match an SP whose crash_type is e.g.
    # "signed-integer-overflow" instead of a generic "ABRT". A *recoverable*
    # UB (e.g. dav1d msac.c unsigned wrap) does not raise a signal, so it never
    # sets CRASHED:1 and is not counted as a crash here.
    ubs = re.findall(r"runtime error:\s*([^\n:]+)", out)
    ub_type = re.sub(r"\s+", "-", ubs[-1].strip().lower()) if ubs else None
    # A fatal UB (‑fno‑sanitize‑recover) aborts, but on a worker thread gdb may
    # not register the abort as a caught signal, so also count a UB error whose
    # inferior did NOT exit cleanly. A *recoverable* UB runs to a clean exit.
    clean_exit = ("exited normally" in out) or ("exited with code 0]" in out)
    crashed = ("CRASHED:1" in out) or bool(asan) or bool(sig) or (bool(ub_type) and not clean_exit)
    # crashing frame: prefer the ASan report's bug frame, else the first NON-runtime gdb frame
    frame = None
    sm = re.search(r"SUMMARY: AddressSanitizer: [\w-]+ ([^\s]+:\d+)(?::\d+)? in (\w+)", out)
    if sm:
        frame = f"{sm.group(2)} @ {sm.group(1)}"
    if not frame:
        a0 = re.search(r"#0 0x[0-9a-f]+ in (\w+) ([^\s]+:\d+)", out)
        if a0:
            frame = f"{a0.group(1)} @ {a0.group(2)}"
    if not frame:
        for fm in re.finditer(r"in (\w+) \(.*?\) at ([^\s:]+):(\d+)", out):
            fpath = fm.group(2)
            if not any(x in fpath for x in ("sysdeps", "asan", "compiler-rt", "/libc")):
                frame = f"{fm.group(1)} @ {fm.group(2)}:{fm.group(3)}"; break
    # first target (in the given order) NOT reached
    first_unreached = next((t for t in (targets or []) if not reached[t]), None)
    return {"reached": reached, "sink_reached": sink_reached, "first_unreached": first_unreached,
            "operands": ops, "asan_margin": asan_margin, "crashed": crashed,
            # Attribution precedence: ASan report type > UBSan type (when a
            # SIGABRT-triggering fatal UB fired) > the raw signal name (SEGV/
            # ABRT/BUS/FPE/ILL, since gdb catches the inferior's signal before
            # ASan prints its own report) > a UBSan type with no signal.
            "sanitizer_type": (
                asan.group(1) if asan
                else ub_type if (sig and sig.group(1) == "ABRT" and ub_type)
                else sig.group(1) if sig
                else ub_type
            ),
            "crash_frame": frame}


def trace(elf_host_path: str, run_argv_tmpl, input_bytes: bytes, project: str,
          targets: List[str] = None, sink: str = None, operands: Dict[str, str] = None,
          sp_function: str = None, sp_crash_type: str = None,
          timeout: int = 150, image: str = None, memory_mb: int = 2048) -> Dict[str, Any]:
    """One gdb-15 run. `run_argv_tmpl(input_in_container)->[argv]` builds the run
    command (fuzztest vs libFuzzer). `memory_mb` caps the container -- raise it
    for memory-heavy decoders (@NO_OOM targets) or a valid input SIGKILLs before
    reaching the sink. Returns the bundle."""
    libdir = stage_project_libs(project, elf_host_path, image=image)
    work = Path(tempfile.mkdtemp(prefix="trace_"))
    try:
        shutil.copy(elf_host_path, work / "elf")
        # Some prebuilt fuzzers ship non-executable (OSS-Fuzz build.sh chmod -x's
        # the raw binary when a wrapper is the entry point); gdb then dies with
        # "exec: Permission denied" and the run looks like a clean no-crash.
        os.chmod(work / "elf", 0o755)
        # Stage shared libs shipped next to the binary (e.g. systemd's
        # libsystemd-shared-258.so under bin/address/src/shared/), which its
        # RUNPATH resolves relative to $ORIGIN -- lost when we copy just the elf.
        blibs = work / "blibs"; blibs.mkdir(exist_ok=True)
        try:
            for so in Path(elf_host_path).parent.rglob("*.so*"):
                if so.is_file():
                    dst = blibs / so.name
                    if not dst.exists():
                        shutil.copy(so, dst)
            # Vendored fallback libs for a NEEDED that is in neither the binary
            # tree nor the project image (systemd's libsystemd-shared -> libcap.so.2).
            # Without it the inferior aborts at load and the trace looks like a
            # clean no-crash -- the same gap that made the audit's agent path fail
            # on systemd while native reproduced fine.
            vendored = Path(__file__).resolve().parent.parent / "analyzer" / "runtime_libs"
            if vendored.is_dir():
                for lib in vendored.glob("*.so*"):
                    dst = blibs / lib.name
                    if not dst.exists():
                        shutil.copy(lib, dst)
        except Exception:
            pass
        (work / "input").write_bytes(input_bytes)
        (work / "t.gdb").write_text(_gen_script(targets, sink, operands))
        argv = run_argv_tmpl("/b/input")
        argv[0] = "/b/elf"
        cmd = ["docker", "run", "--rm", "--cap-add=SYS_PTRACE",
               "--security-opt", "seccomp=unconfined",
               f"--memory={memory_mb}m", f"--memory-swap={memory_mb}m",
               "--cpus=1", "--pids-limit=512",
               "-v", f"{work}:/b", "-v", f"{libdir}:/projlibs:ro",
               "-e", "ASAN_OPTIONS=abort_on_error=1:detect_leaks=0",
               GDB15_IMAGE, "bash", "-c",
               "gdb -batch -x /b/t.gdb --args " + " ".join(argv)]
        r = _sh(cmd, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        res = _parse(out, targets, sink, operands)
        res["crash_matches_sp"] = _crash_matches(res, sp_function, sp_crash_type)
        res["raw_tail"] = out[-800:]
        return res
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _crash_matches(res: dict, sp_function: str, sp_crash_type: str) -> Optional[bool]:
    """Only meaningful on a crash. True iff the crash frame's function matches the
    SP's claimed function AND the sanitizer type matches the SP's crash_type.
    None when there was no crash (field unused)."""
    if not res.get("crashed"):
        return None
    frame = res.get("crash_frame") or ""
    st = (res.get("sanitizer_type") or "").lower()
    fn_ok = bool(sp_function) and sp_function in frame
    ty_ok = (not sp_crash_type) or (sp_crash_type.lower() in st) or (st in sp_crash_type.lower())
    return bool(fn_ok and ty_ok)


# ============================================================================
# SLOW tool: check_clamp — watch a tainted variable, report its value-change
# trace (old->new @ location). A value bounded/reduced at a guard before the
# sink is a DYNAMICALLY OBSERVED clamp = the only read-independent disconfirm.
# Separate from `trace` because watchpoints can be expensive.
# ============================================================================
def check_clamp(elf_host_path: str, run_argv_tmpl, input_bytes: bytes, project: str,
                var: str, at_function: str, max_hits: int = 40,
                timeout: int = 180) -> Dict[str, Any]:
    libdir = stage_project_libs(project, elf_host_path)
    work = Path(tempfile.mkdtemp(prefix="clamp_"))
    try:
        shutil.copy(elf_host_path, work / "elf")
        os.chmod(work / "elf", 0o755)
        (work / "input").write_bytes(input_bytes)
        script = "\n".join([
            "set pagination off", "set confirm off",
            "set environment LD_LIBRARY_PATH=/projlibs",
            "handle SIGSEGV SIGABRT SIGBUS SIGFPE stop nopass",
            f"break {at_function}", "run",
            f"watch {var}",
            "set $i = 0",
            f"while $i < {max_hits}",
            f'  printf "CLAMP:new=%ld @ ", (long)({var})',
            "  frame",
            "  continue",
            "  set $i = $i + 1",
            "end",
            "quit", ""])
        (work / "c.gdb").write_text(script)
        argv = run_argv_tmpl("/b/input"); argv[0] = "/b/elf"
        cmd = ["docker", "run", "--rm", "--cap-add=SYS_PTRACE",
               "--security-opt", "seccomp=unconfined",
               "--memory=2048m", "--memory-swap=2048m", "--cpus=1", "--pids-limit=512",
               "-v", f"{work}:/b", "-v", f"{libdir}:/projlibs:ro",
               "-e", "ASAN_OPTIONS=abort_on_error=1:detect_leaks=0",
               GDB15_IMAGE, "bash", "-c",
               f"timeout {timeout-10} gdb -batch -x /b/c.gdb --args " + " ".join(argv)]
        r = _sh(cmd, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        # each hit: "CLAMP:new=<val> @ #0 ... at <file>:<line>"
        hits = []
        for m in re.finditer(r"CLAMP:new=(-?\d+) @ .*?(?:at ([^\s:]+):(\d+)| in (\w+))", out):
            where = f"{m.group(2)}:{m.group(3)}" if m.group(2) else (m.group(4) or "?")
            hits.append({"value": int(m.group(1)), "where": where})
        # a clamp = a change that REDUCES the value (bounded) at a guard before sink
        clamped = any(hits[i]["value"] < hits[i-1]["value"] for i in range(1, len(hits)))
        return {"var": var, "hits": hits, "n_changes": len(hits),
                "final_value": hits[-1]["value"] if hits else None,
                "clamp_observed": clamped,
                "crashed": bool(_SIG.search(out) or _ASAN.search(out)),
                "raw_tail": out[-600:]}
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ============================================================================
# Production adapter: reach_probe
# ----------------------------------------------------------------------------
# Verify-stage dynamic evidence WITHOUT a pre-existing PoV. The verifier LLM
# writes a `generate(variant)->bytes` candidate input (its code-reading is a
# first-class prior for what should reach the site); we run that input through
# the ASan fuzzer under gdb-15 and return execution facts the LLM cannot fake:
# which targets were reached, whether it crashed (+type/frame), and the exact
# overflow margin from the ASan report. Reads the run context set by the
# strategy (set_reach_context / set_coverage_context) so the tool is stateless.
# ============================================================================

def _argv_tmpl_for(fuzzer_name: Optional[str]):
    """Build the run argv for a logical fuzzer name.

    libFuzzer:          [elf, <oom flags>, input]
    fuzztest (name@Test): [elf, --fuzz=Test, --, input]
    @NO_OOM adds -rss_limit_mb=0 -malloc_limit_mb=0 so the allocator guard does
    not abort a memory-heavy decode before it reaches the sink.
    """
    _, no_oom, fuzztest = parse_fuzzer_spec(fuzzer_name or "")
    oom = libfuzzer_oom_flags(no_oom)
    if fuzztest:
        return lambda inp: ["/b/elf", f"--fuzz={fuzztest}", "--", inp]
    return lambda inp: ["/b/elf", *oom, inp]


def reach_probe(generator_code: str,
                targets: List[str] = None,
                sink: str = None,
                operands: Dict[str, str] = None,
                sp_function: str = None,
                sp_crash_type: str = None,
                timeout: int = 150) -> Dict[str, Any]:
    """Run one LLM-authored candidate input through the ASan fuzzer under gdb-15
    and return dynamic reach/crash/margin evidence. Context (ASan ELF, fuzzer
    name, project, docker image) comes from the run's coverage/reach context."""
    from .coverage import (get_reach_context, get_coverage_context,
                           get_asan_fuzzer_dir, get_docker_image)
    from .pov import _execute_generator_code

    elf, fuzzer_name, project, image = get_reach_context()
    cov_dir, cov_project, _ = get_coverage_context()
    # Fallbacks (coverage build present): project/image/elf from coverage context.
    if not project:
        project = cov_project
    if not image:
        image = get_docker_image()  # aixcc-afc/<project> in AFC runs; None -> default
    if elf is None:
        adir = get_asan_fuzzer_dir()
        if adir is None and cov_dir is not None:
            adir = Path(str(cov_dir).replace("_coverage", "_address"))
        if adir is not None and fuzzer_name:
            cand = adir / fuzzer_name.split("@")[0]
            if cand.exists():
                elf = cand
    if elf is None or not Path(elf).exists():
        return {"error": f"ASan fuzzer binary not found (reach context unset): elf={elf}"}
    if not project:
        return {"error": "project name not set (reach/coverage context)"}

    blobs, err = _execute_generator_code(generator_code or "", num_variants=1)
    if err or not blobs:
        return {"error": f"generator failed: {err or 'no bytes produced'}"}

    _, no_oom, _ = parse_fuzzer_spec(fuzzer_name or "")
    mem = NO_OOM_MEMORY_MB if no_oom else 2048
    try:
        res = trace(str(elf), _argv_tmpl_for(fuzzer_name), blobs[0], project,
                    targets=targets, sink=sink, operands=operands,
                    sp_function=sp_function, sp_crash_type=sp_crash_type,
                    timeout=timeout, image=image, memory_mb=mem)
    except subprocess.TimeoutExpired:
        return {"error": f"gdb trace timed out after {timeout}s", "crashed": False}
    except Exception as e:  # never let a probe failure kill verification
        return {"error": f"trace error: {type(e).__name__}: {e}"}
    res["input_len"] = len(blobs[0])
    return res
