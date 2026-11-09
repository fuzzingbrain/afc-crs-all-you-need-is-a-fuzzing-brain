"""MCP tool server for one agent session (stdio; the agent CLI launches it).

    <python> fbv3/tools/server.py --ctx <session_dir>/ctx.json

It runs on the host next to the CLI. Every command it runs for the agent --
``exec``, input generators, the fuzz target, gdb -- runs in the workspace
container, which sees only ``/ws`` and ``/src``. Builds run in the project's
builder image. Which tools a session gets is ``ctx["tools"]`` (set from its
role). Every call is appended to ``<session>/mcp_calls.jsonl`` before its
result is returned; what a session submits lands in ``<session>/out/`` and the
orchestrator reads it from there once the session ends.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import re
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fbv3.fuzz import signature as sigmod  # noqa: E402
from fbv3.sandbox import docker  # noqa: E402

OUTPUT_CAP = 20000
SAN_MARKERS = ("ERROR: AddressSanitizer", "ERROR: MemorySanitizer", "WARNING: MemorySanitizer",
               "ERROR: LeakSanitizer", "runtime error:", "ERROR: libFuzzer: deadly signal",
               "SUMMARY: UndefinedBehaviorSanitizer", "ERROR: libFuzzer: out-of-memory")
RUN_ASAN = "detect_leaks=0:symbolize=1:abort_on_error=0:handle_abort=1:allocator_may_return_null=1"
GDB_ASAN = "abort_on_error=1:detect_leaks=0:symbolize=1"

CTX: dict[str, Any] = {}


# -- plumbing -------------------------------------------------------------------------


def _sdir() -> Path:
    return Path(CTX["session_dir"])


def _out() -> Path:
    p = _sdir() / "out"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _append(path: Path, rec: dict) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, default=str) + "\n")


def recorded(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        started = time.monotonic()
        rec = {"ts": _now(), "tool": fn.__name__, "args": kwargs or list(args)}
        try:
            result = fn(*args, **kwargs)
            rec["result"] = result
            return result
        except Exception as exc:  # noqa: BLE001 -- reported to the agent and logged
            rec["error"] = f"{type(exc).__name__}: {exc}"
            return {"ok": False, "error": rec["error"]}
        finally:
            rec["duration_s"] = round(time.monotonic() - started, 3)
            _append(_sdir() / "mcp_calls.jsonl", rec)

    return wrapper


def _workdir() -> str:
    return "/ws/sessions/" + _sdir().name + "/work"


def _env_run() -> dict:
    env = {"ASAN_OPTIONS": RUN_ASAN, "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
           "MSAN_OPTIONS": "halt_on_error=1:print_stats=0"}
    if (_ws_root() / "out" / "llvm" / "llvm-symbolizer").is_file():
        env["ASAN_SYMBOLIZER_PATH"] = env["MSAN_SYMBOLIZER_PATH"] = "/ws/out/llvm/llvm-symbolizer"
    return env


def _dexec(argv: list[str], *, timeout: int, env: dict | None = None, workdir: str = "") -> dict:
    cmd = ["docker", "exec", "-u", docker.uid_gid(), "-w", workdir or _workdir()]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [CTX["container"], *argv]
    t = time.monotonic()
    proc = docker.run(cmd, timeout=timeout)
    return {"exit_code": proc.returncode, "timed_out": proc.returncode == 124 and b"[timeout]" in proc.stderr,
            "stdout": proc.stdout.decode("utf-8", "replace"), "stderr": proc.stderr.decode("utf-8", "replace"),
            "duration_s": round(time.monotonic() - t, 2)}


def _tail(text: str, cap: int = OUTPUT_CAP) -> str:
    return text if len(text) <= cap else f"[... {len(text) - cap} chars cut ...]\n" + text[-cap:]


def _ws_root() -> Path:
    return Path(CTX["ws_root"])


def _to_host(cpath: str) -> Path:
    p = str(cpath)
    if p.startswith("/ws/"):
        return _ws_root() / p[4:]
    if p.startswith("/src/"):
        return _ws_root() / "src" / p[5:]
    raise ValueError(f"{cpath!r} is not under /ws or /src")


def _to_container(host: Path) -> str:
    return "/ws/" + str(Path(host).resolve().relative_to(_ws_root().resolve()))


def _materialize(code: str, count: int, label: str) -> tuple[list[Path], str]:
    work = _sdir() / "work" / "generated" / f"{label}-{uuid.uuid4().hex[:8]}"
    work.mkdir(parents=True, exist_ok=True)
    (work / "generator.py").write_text(code, encoding="utf-8")
    res = _dexec(["python3", "/opt/fbv3/gen_runner.py", _to_container(work / "generator.py"), str(count),
                  _to_container(work)], timeout=120)
    try:
        report = json.loads(res["stdout"].strip().splitlines()[-1])
    except (ValueError, IndexError):
        return [], f"generator runner failed (exit {res['exit_code']}): {_tail(res['stderr'] + res['stdout'], 3000)}"
    files = [work / Path(i["path"]).name for i in report.get("inputs", [])]
    msg = "\n".join(x for x in (report.get("error", ""), report.get("warning", "")) if x)
    return files, msg


def _target_bin() -> str:
    """The fuzz target this session runs inputs on (container path)."""
    if CTX.get("target_bin"):
        return CTX["target_bin"]
    last = _last_build()
    if last and last.get("ok"):
        return last["binary_container"]
    raise RuntimeError("there is no built fuzz target yet: call build_harness first")


def _run_input(cinput: str, binary: str | None = None, timeout: int = 0) -> dict:
    timeout = timeout or int(CTX.get("run_timeout_s", 60))
    res = _dexec([binary or _target_bin(), "-runs=1", f"-timeout={max(5, timeout - 10)}", cinput],
                 timeout=timeout, env=_env_run())
    output = res["stderr"] + res["stdout"]
    crashed = res["exit_code"] != 0 and any(m in output for m in SAN_MARKERS)
    out = {"crashed": crashed, "exit_code": res["exit_code"], "timed_out": res["timed_out"],
           "output_tail": _tail(output, 6000)}
    if crashed:
        sig = sigmod.compute_signature(output, harness_names=CTX.get("harness_names") or [])
        out.update(crash_class=sig.crash_class, signature=sig.short, where=sig.describe(),
                   top_frames=[list(f) for f in sig.frames[:5]])
        _keep_crashing_input(cinput, sig.short)
    return out


def _keep_crashing_input(cinput: str, signature: str) -> None:
    """Keep an input that made the target report, wherever it was found.

    Any role can stumble on a crash while reading or probing. The session's
    scratch space is thrown away, so the input is copied where the
    orchestrator looks for it and can reproduce it itself.
    """
    try:
        src = _to_host(cinput)
        if not src.is_file():
            return
        keep = _out() / "crashing"
        keep.mkdir(parents=True, exist_ok=True)
        dst = keep / f"{signature or 'unknown'}-{hashlib.sha1(src.read_bytes()).hexdigest()[:12]}.bin"
        if not dst.exists():
            shutil.copyfile(src, dst)
    except (OSError, ValueError):
        pass


def _resolve_input(input_path: str, generator_code: str, label: str) -> tuple[str, str]:
    if generator_code:
        files, err = _materialize(generator_code, 1, label)
        if not files:
            return "", err or "the generator produced no input"
        return _to_container(files[0]), ""
    if not input_path:
        return "", "give input_path (a file under /ws) or generator_code (def generate(n) -> bytes)"
    if not _to_host(input_path).is_file():
        return "", f"{input_path} does not exist"
    return input_path, ""


# -- every role ------------------------------------------------------------------------


@recorded
def exec(command: str, timeout_s: int = 120) -> dict:  # noqa: A001 -- the tool is called exec
    """Run a shell command (bash -lc) in the workspace container; cwd is your session work dir.

    The container sees /ws (this workspace) and /src (the project source, read-only). Use it to read
    code (rg, sed -n, grep), inspect binaries, run python3, gdb, llvm-cov. No network. Output is capped
    at 20k characters.
    """
    timeout_s = max(1, min(int(timeout_s), 900))
    res = _dexec(["bash", "-lc", command], timeout=timeout_s + 5)
    return {"exit_code": res["exit_code"], "timed_out": res["timed_out"],
            "stdout": _tail(res["stdout"]), "stderr": _tail(res["stderr"], 6000)}


@recorded
def run_target(input_path: str = "", generator_code: str = "") -> dict:
    """Run the fuzz target once on one input and report whether a sanitizer fired.

    Give input_path (a file under /ws, e.g. one you wrote in your work dir) or generator_code
    defining `def generate(n: int) -> bytes` (called with n=1).
    """
    path, err = _resolve_input(input_path, generator_code, "run")
    if err:
        return {"ok": False, "error": err}
    return {"ok": True, "input": path, **_run_input(path)}


@recorded
def reach_probe(target: str, input_path: str = "", generator_code: str = "") -> dict:
    """Does this input reach `target` (a function name or file:line)? Runs the fuzz target under gdb with a
    breakpoint there and returns whether it was hit, the backtrace and arguments at the hit; then runs it
    normally and reports whether a sanitizer fired. Give input_path or generator_code (`generate(n)`)."""
    path, err = _resolve_input(input_path, generator_code, "probe")
    if err:
        return {"ok": False, "error": err}
    binary = _target_bin()
    # A large C++ target with full debug info takes a while just to load in gdb.
    probe_timeout = int(CTX.get("probe_timeout_s", 240))
    gdb = _dexec(["gdb", "-q", "-batch", "-nx", "-ex", "set pagination off", "-ex", "set breakpoint pending on",
                  "-ex", f"break {target}", "-ex", "run", "-ex", "bt 25", "-ex", "info args",
                  "--args", binary, "-runs=1", path], timeout=probe_timeout, env={"ASAN_OPTIONS": GDB_ASAN})
    text = gdb["stdout"] + gdb["stderr"]
    reached = "Breakpoint 1, " in text
    out = {"ok": True, "input": path, "target": target, "reached": reached,
           "breakpoint_set": "No symbol" not in text and "not defined" not in text,
           "hit": text[text.index("Breakpoint 1, "):][:5000] if reached else "",
           "gdb_tail": "" if reached else _tail(text, 2500)}
    if gdb["timed_out"] and not reached:
        # Do not let a slow probe read as "the input does not get there".
        out["timed_out"] = True
        out["note"] = (f"gdb did not finish within {probe_timeout}s, so this says nothing about whether the "
                       "input reaches the target; try a smaller input or a breakpoint closer to the entry")
    run = _run_input(path)
    out.update({f"run_{k}": v for k, v in run.items()})
    return out


# -- seeds -------------------------------------------------------------------------------


@recorded
def create_seed(generator_code: str, num_seeds: int = 5) -> dict:
    """Add inputs to the fuzzer's corpus from `def generate(seed_num: int) -> bytes`.

    generate is called with seed_num = 1..num_seeds (at most 20); return DIFFERENT bytes for each. Every
    input is copied into the live corpus of the fuzzer this session feeds.
    """
    n = max(1, min(int(num_seeds), 20))
    files, err = _materialize(generator_code, n, "seed")
    corpus = Path(CTX["seed_corpus"])
    corpus.mkdir(parents=True, exist_ok=True)
    added = []
    for f in files:
        data = f.read_bytes()
        digest = hashlib.sha1(data).hexdigest()
        name = f"{CTX['role']}-{CTX['session_id'][:8]}-{digest[:16]}"
        shutil.copyfile(f, corpus / name)
        _append(_out() / "seeds.jsonl", {"ts": _now(), "sha1": digest, "size": len(data), "corpus": name})
        added.append({"sha1": digest[:16], "size": len(data)})
    if not added:
        return {"ok": False, "error": err or "no inputs produced"}
    return {"ok": True, "added": added, "warning": err}


@recorded
def coverage_frontier(max_targets: int = 25) -> dict:
    """The coverage frontier: functions that are linked into the target but not yet executed, called from
    functions that are. Re-measures coverage over the current corpus first. Ranked with callees that do
    parsing / copying / length arithmetic first. Each item: {target, file, lines, called_from, hint}."""
    from fbv3.fuzz import coverage

    class _WS:
        def exec(self, argv, timeout=900):
            r = _dexec(argv, timeout=timeout, workdir="/ws")
            import subprocess
            return subprocess.CompletedProcess(argv, r["exit_code"], r["stdout"].encode(), r["stderr"].encode())

    rows, err = coverage.collect_functions(_WS(), coverage_binary=CTX["coverage_bin"],
                                           corpus_dir=CTX["union_corpus"], timeout_s=600)
    if err:
        return {"ok": False, "error": err}
    covered = {r.name: r for r in rows if r.execution_count > 0}
    linked = {r.name: r for r in rows}
    uncovered = {n for n, r in linked.items() if r.execution_count == 0}
    call_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")
    risky = re.compile(r"\b(memcpy|memmove|strcpy|strcat|sprintf|alloca|malloc|realloc|len|size|count|idx|offset)\b",
                       re.I)
    frontier, seen = [], set()
    for caller in sorted(covered.values(), key=lambda r: -r.execution_count):
        body = _read_lines(caller.file, caller.start_line, caller.end_line)
        for m in call_re.finditer(body):
            callee = m.group(1)
            if callee not in uncovered or callee in seen or callee == caller.name:
                continue
            seen.add(callee)
            tgt = linked[callee]
            interesting = bool(risky.search(_read_lines(tgt.file, tgt.start_line, tgt.end_line)))
            frontier.append({"target": callee, "file": tgt.file, "lines": [tgt.start_line, tgt.end_line],
                             "called_from": caller.name, "hint": "parsing/copy/length ops" if interesting else "",
                             "_rank": (int(interesting), caller.execution_count)})
    frontier.sort(key=lambda d: d.pop("_rank"), reverse=True)
    return {"ok": True, "covered_functions": len(covered), "uncovered_linked": len(uncovered),
            "frontier": frontier[: max(1, int(max_targets))]}


def _read_lines(cfile: str, start: int, end: int) -> str:
    try:
        lines = _to_host(cfile).read_text(errors="replace").splitlines()
    except (OSError, ValueError):
        return ""
    return "\n".join(lines[max(0, start - 1): max(start, end)])


# -- directed: mapper / finder / verifier / PoC ---------------------------------------------


def _index() -> dict[str, list[dict]]:
    try:
        rows = json.loads(Path(CTX["function_index"]).read_text())
    except (OSError, ValueError, KeyError):
        return {}
    by: dict[str, list[dict]] = {}
    for r in rows:
        by.setdefault(r["name"], []).append(r)
    return by


@recorded
def submit_functions(functions: list[dict]) -> dict:
    """Submit the functions worth analysing, most important first.

    Each item: {"name": str, "file": str (optional), "risk": "high"|"medium"|"low",
    "call_path": "entry -> ... -> name", "reason": str}. Names are checked against the functions linked
    into the fuzz target; the reply lists what was accepted and what was not found (with close matches).
    You may call this more than once.
    """
    index = _index()
    accepted, rejected = [], []
    if not index:  # no function index for this target: take the names as given
        for item in functions or []:
            if str(item.get("name", "")).strip():
                _append(_out() / "functions.jsonl", {
                    "name": item["name"], "file": item.get("file", ""), "start_line": 0, "end_line": 0,
                    "risk": item.get("risk", "medium"), "call_path": item.get("call_path", ""),
                    "reason": item.get("reason", "")})
                accepted.append({"name": item["name"], "where": item.get("file", "")})
        return {"ok": True, "accepted": accepted, "rejected": [],
                "note": "no function index was available for this fuzz target, so names were not checked"}
    for item in functions or []:
        name = str(item.get("name", "")).strip()
        rows = index.get(name, [])
        if item.get("file") and len(rows) > 1:
            want = str(item["file"]).rsplit("/", 1)[-1]
            rows = [r for r in rows if r["file"].endswith(want)] or rows
        if not rows:
            close = sorted(n for n in index if name and (name.lower() in n.lower() or n.lower() in name.lower()))[:5]
            rejected.append({"name": name, "reason": "not linked into the fuzz target", "close_matches": close})
            continue
        r = rows[0]
        _append(_out() / "functions.jsonl", {"name": name, "file": r["file"], "start_line": r["start_line"],
                                             "end_line": r["end_line"], "risk": item.get("risk", "medium"),
                                             "call_path": item.get("call_path", ""), "reason": item.get("reason", "")})
        accepted.append({"name": name, "where": f"{r['file']}:{r['start_line']}-{r['end_line']}"})
    return {"ok": True, "accepted": accepted, "rejected": rejected}


@recorded
def submit_vh(function_name: str, description: str, score: float, important_controlflow: str = "",
              sink_code: str = "", sink_line: int = 0) -> dict:
    """Report one vulnerability hypothesis (VH) in the function you are analysing.

    description: the bug class and the root-cause reasoning (the control flow, not just a line).
    score: 0.75 if you think it can crash under the sanitizer, 0.5 or 0.25 if unsure.
    important_controlflow: the functions/variables on the path, one per line, "<name>: <role>".
    sink_code: the faulting statement verbatim; sink_line: its line. Call again for each further VH.
    """
    local = uuid.uuid4().hex[:12]
    _append(_out() / "vhs.jsonl", {
        "local_id": local, "ts": _now(), "function_name": function_name,
        "function_file": (CTX.get("function") or {}).get("file", ""), "description": description,
        "finder_score": max(0.0, min(1.0, float(score))), "important_controlflow": important_controlflow,
        "sink_code": sink_code, "sink_line": int(sink_line or 0)})
    return {"ok": True, "vh_local_id": local}


@recorded
def submit_verdict(score: float, evidence: str, verification_notes: str, poc_guidance: str,
                   description: str = "", important_controlflow: str = "") -> dict:
    """Finish verifying the VH with ONE call.

    score: 1.0 a sanitizer report was produced; 0.75-1 real, no report yet; 0.5-0.75 probably real;
    0.25-0.5 probably not; 0-0.25 not real (with evidence); 0 if the sanitizer cannot detect it.
    evidence: facts for and against, each with file:line or a reach_probe result. poc_guidance: how to
    trigger it, with ONE generator (`def generate(variant) -> bytes`) and how far it got.
    description / important_controlflow: only to correct the VH's.
    """
    (_out() / "verdict.json").write_text(json.dumps({
        "ts": _now(), "vh_id": CTX.get("vh_id", ""), "score": max(0.0, min(1.0, float(score))),
        "evidence": evidence, "verification_notes": verification_notes, "poc_guidance": poc_guidance,
        "description": description, "important_controlflow": important_controlflow}, indent=2) + "\n")
    return {"ok": True, "recorded": True}


@recorded
def create_poc(generator_code: str) -> dict:
    """Try a PoC: `def generate(variant: int) -> bytes` is called with variant 1, 2, 3.

    Each variant runs on the ASan fuzz target; the reply says which made a sanitizer fire, with the
    report tail and crash signature. Every variant is kept with the VH and also handed to the shared
    PoC fuzzer, which mutates around all candidates.
    """
    files, err = _materialize(generator_code, 3, "poc")
    if not files:
        return {"ok": False, "error": err or "the generator produced no variants"}
    pocs = Path(CTX["pocs_dir"])
    pocs.mkdir(parents=True, exist_ok=True)
    poc_corpus = Path(CTX["poc_corpus"]) if CTX.get("poc_corpus") else None
    attempt = uuid.uuid4().hex[:8]
    results = []
    for i, f in enumerate(files, start=1):
        blob = pocs / f"{attempt}-v{i}.bin"
        shutil.copyfile(f, blob)
        if poc_corpus is not None:
            poc_corpus.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, poc_corpus / f"poc-{CTX.get('vh_id', 'x')}-{attempt}-v{i}")
        run = _run_input(_to_container(blob))
        _append(_out() / "pocs.jsonl", {"ts": _now(), "attempt": attempt, "variant": i, "blob": str(blob),
                                        "size": blob.stat().st_size, **run})
        results.append({"variant": i, "blob": _to_container(blob),
                        **{k: v for k, v in run.items() if k != "output_tail"}, "output_tail": run["output_tail"][-3000:]})
    return {"ok": True, "attempt": attempt, "variants": results,
            "any_crashed": any(r["crashed"] for r in results), "warning": err}


@recorded
def submit_poc(status: str, summary: str, blob: str = "") -> dict:
    """Finish the PoC session. status: "crashed" (give the crashing blob path) or "failed"."""
    (_out() / "poc_result.json").write_text(json.dumps({
        "ts": _now(), "vh_id": CTX.get("vh_id", ""), "status": status, "summary": summary, "blob": blob},
        indent=2) + "\n")
    return {"ok": True, "recorded": True}


# -- harness generation ------------------------------------------------------------------------


def _last_build() -> dict:
    p = _out() / "last_build.json"
    return json.loads(p.read_text()) if p.is_file() else {}


@recorded
def list_build_targets() -> dict:
    """The fuzz-target sources the project's build.sh compiles, and build.sh itself.

    A new harness REPLACES one of these sources (its "overlay" path): build.sh then compiles your code
    into that fuzz target. Pick the source whose build line links the library the target logic lives in.
    """
    res = _dexec(["bash", "-lc",
                  "grep -rlE 'LLVMFuzzerTestOneInput' /src --include=*.c --include=*.cc --include=*.cpp "
                  "--include=*.cxx 2>/dev/null | head -100"], timeout=120, workdir="/ws")
    sources = [s for s in res["stdout"].split() if s]
    build_sh = _ws_root() / "src" / "build.sh"
    return {"ok": True, "fuzzer_sources": sources,
            "suggested_overlay": CTX.get("overlay_hint", ""), "expected_binary": CTX.get("expected_binary", ""),
            "build_sh": _tail(build_sh.read_text(errors="replace"), 12000) if build_sh.is_file() else "(none)"}


@recorded
def build_harness(code: str, overlay: str) -> dict:
    """Compile `code` as the fuzz-target source at `overlay` (an existing /src/... path build.sh compiles).

    Runs the project's own build (ASan, libFuzzer) with your file in place of the original. The reply has
    the compiler errors when it fails, or the built fuzz target and the deterministic principle checks
    when it succeeds. Fix and call again until it builds; then call smoke_test.
    """
    from fbv3.build.builder import build_harness as _build
    from fbv3.harness.principles import static_findings

    n = len(list(Path(CTX["builds_dir"]).glob("b*"))) + 1
    bdir = Path(CTX["builds_dir"]) / f"b{n:02d}-{CTX['session_id'][:6]}"
    res = _build(builder_image=CTX["builder_image"], overlay=overlay, source=code, build_dir=bdir,
                 sanitizer="address", engine="libfuzzer", language=CTX.get("language", "c"),
                 run_id=CTX.get("run_id", ""), timeout_s=int(CTX.get("build_timeout_s", 1800)),
                 memory_mb=int(CTX.get("build_memory_mb", 8192)), cpus=float(CTX.get("build_cpus", 4.0)),
                 expected_binary=CTX.get("expected_binary", ""))
    findings = [f.to_dict() for f in static_findings(code, CTX.get("sanitizers", ["address"]), CTX.get("language", "c"))]
    rec = {"ts": _now(), "n": n, "overlay": overlay, "ok": res.ok, "binary": res.binary, "error": res.error,
           "infra": res.infra, "build_dir": str(bdir), "code_sha1": hashlib.sha1(code.encode()).hexdigest(),
           "findings": findings}
    if res.ok:
        rec["binary_container"] = _to_container(Path(res.out_dir) / res.binary)
        (bdir / "source").write_text(code)
        (_out() / "last_build.json").write_text(json.dumps({**rec, "code": code}, indent=2) + "\n")
    _append(_out() / "builds.jsonl", rec)
    reply = {"ok": res.ok, "binary": res.binary, "error": res.error, "principle_checks": findings}
    if not res.ok:
        reply["build_log_excerpt"] = res.log_excerpt
        if res.infra:
            reply["note"] = "this failure is infrastructure, not your code; retrying once is reasonable"
    return reply


@recorded
def smoke_test(seconds: int = 0) -> dict:
    """Fuzz the last successful build briefly and judge reachability (P4): edges covered, exec/s, and
    whether it crashed at once (a harness bug, or a real bug the reviewer must look at)."""
    from fbv3.harness.smoke import smoke

    last = _last_build()
    if not last.get("ok"):
        return {"ok": False, "error": "no successful build yet: call build_harness first"}

    def run(script: str, timeout: int) -> tuple[int, str]:
        r = _dexec(["bash", "-lc", script], timeout=timeout, env=_env_run())
        return r["exit_code"], r["stdout"] + r["stderr"]

    out = {"ok": True, **smoke(run, binary=last["binary_container"], work_dir=_workdir(),
                               seconds=int(seconds or CTX.get("smoke_seconds", 30)),
                               min_edges=int(CTX.get("min_edges", 20)), min_exec_s=int(CTX.get("min_exec_s", 10)),
                               harness_names=CTX.get("harness_names") or [])}
    (_out() / "last_smoke.json").write_text(json.dumps({**out, "build": last["n"]}, indent=2) + "\n")
    return out


@recorded
def run_harness(input_path: str = "", generator_code: str = "") -> dict:
    """Run the last successful build once on one input (input_path or generator_code)."""
    last = _last_build()
    if not last.get("ok"):
        return {"ok": False, "error": "no successful build yet: call build_harness first"}
    path, err = _resolve_input(input_path, generator_code, "hrun")
    if err:
        return {"ok": False, "error": err}
    return {"ok": True, "input": path, **_run_input(path, last["binary_container"])}


@recorded
def submit_harness(notes: str = "") -> dict:
    """Submit the last successful build as your harness. Call it once, at the end, after smoke_test.
    notes: what the harness exercises and any setup choices a reviewer should know about."""
    last = _last_build()
    if not last.get("ok"):
        return {"ok": False, "error": "nothing to submit: no successful build (call build_harness)"}
    smoke = json.loads((_out() / "last_smoke.json").read_text()) if (_out() / "last_smoke.json").is_file() else {}
    (_out() / "harness.json").write_text(json.dumps({
        "ts": _now(), "overlay": last["overlay"], "binary": last["binary"], "build_dir": last["build_dir"],
        "code": last["code"], "findings": last["findings"], "smoke": smoke if smoke.get("build") == last["n"] else {},
        "notes": notes}, indent=2) + "\n")
    return {"ok": True, "submitted": last["binary"], "overlay": last["overlay"]}


@recorded
def build_project(build_sh: str, harness_path: str, harness_code: str, target_name: str = "") -> dict:
    """Run your build.sh over the source tree and report what happened.

    build_sh: the whole script. It runs through the fuzzing toolchain's `compile`, so $CC, $CXX,
    $CFLAGS, $CXXFLAGS, $LIB_FUZZING_ENGINE and $OUT are set; the working directory is a writable
    copy of the tree. harness_path: where to put your harness, relative to the tree root (e.g.
    "fuzz/parse_fuzzer.c"). target_name: the file name to produce in $OUT (default: the harness's
    stem). The reply carries the compiler errors when it fails; fix and call again.
    """
    from fbv3.build.workspace_build import build_workspace

    n = len(list(Path(CTX["builds_dir"]).glob("i*"))) + 1
    bdir = Path(CTX["builds_dir"]) / f"i{n:02d}-{CTX['session_id'][:6]}"
    res = build_workspace(
        base_image=CTX["base_image"], source_dir=Path(CTX["source_dir"]), build_sh=build_sh,
        harness_files={harness_path: harness_code}, build_dir=bdir, sanitizer="address",
        engine="libfuzzer", language=CTX.get("language", "c"), run_id=CTX.get("run_id", ""),
        timeout_s=int(CTX.get("build_timeout_s", 3600)), memory_mb=int(CTX.get("build_memory_mb", 8192)),
        cpus=float(CTX.get("build_cpus", 4.0)), allow_network=bool(CTX.get("allow_network", False)),
        expected_binary=target_name or Path(harness_path).stem)
    rec = {"ts": _now(), "n": n, "ok": res.ok, "binary": res.binary, "binaries": res.binaries,
           "error": res.error, "infra": res.infra, "build_dir": str(bdir),
           "harness_path": harness_path, "target_name": target_name}
    if res.ok:
        (_out() / "last_build.json").write_text(json.dumps(
            {**rec, "build_sh": build_sh, "harness_code": harness_code}, indent=2) + "\n")
    _append(_out() / "builds.jsonl", rec)
    reply = {"ok": res.ok, "binary": res.binary, "fuzz_targets_found": res.binaries, "error": res.error}
    if not res.ok:
        reply["build_log_excerpt"] = res.log_excerpt
        if res.infra:
            reply["note"] = "this failure is infrastructure, not your build; retrying once is reasonable"
    else:
        reply["note"] = ("it builds. Before you submit, make sure the LIBRARY was compiled with $CFLAGS "
                         "-- a build that only instruments the harness passes this step and then finds "
                         "nothing, and the gate after you submit will reject it.")
    return reply


@recorded
def submit_build(notes: str = "") -> dict:
    """Submit your last successful build. notes: how the library is built, where the flags go in,
    and anything a later harness author needs to know."""
    last = _last_integrate_build()
    if not last.get("ok"):
        return {"ok": False, "error": "nothing to submit: no successful build yet (call build_project)"}
    (_out() / "build.json").write_text(json.dumps({**last, "notes": notes}, indent=2) + "\n")
    return {"ok": True, "submitted": last["binary"], "harness_path": last["harness_path"]}


def _last_integrate_build() -> dict:
    p = _out() / "last_build.json"
    return json.loads(p.read_text()) if p.is_file() else {}


@recorded
def submit_review(verdict: str, violations: list[dict], feedback: str, probes: str = "") -> dict:
    """Finish the review with ONE call.

    verdict: "accept" (no blocking violation) or "request_fix".
    violations: [{"principle": "P1".."P5", "lines": "12-15", "description": str, "consequence": str,
    "blocking": bool}] -- every violation you found, blocking or not.
    feedback: for the generator, concrete and actionable (what to change and why), empty on accept.
    probes: the inputs you ran and what they showed.
    """
    if verdict not in ("accept", "request_fix"):
        return {"ok": False, "error": 'verdict must be "accept" or "request_fix"'}
    (_out() / "review.json").write_text(json.dumps({
        "ts": _now(), "verdict": verdict, "violations": violations or [], "feedback": feedback,
        "probes": probes}, indent=2) + "\n")
    return {"ok": True, "recorded": True}


@recorded
def submit_report(report: str) -> dict:
    """Submit the API research report (markdown) for the harness generator."""
    if len(report.strip()) < 200:
        return {"ok": False, "error": "the report is too short to be useful; cover every section asked for"}
    (_out() / "report.md").write_text(report)
    return {"ok": True, "recorded": True, "chars": len(report)}


@recorded
def submit_targets(targets: list[dict]) -> dict:
    """Submit the target functions to build harnesses for, most valuable first.

    Each item: {"function": str, "description": str (what to fuzz and why it is security relevant),
    "entries": [other entry points of the same logic, optional], "overlay": "/src/... (optional)"}.
    """
    good, bad = [], []
    for t in targets or []:
        fn = str(t.get("function", "")).strip()
        if not fn or not t.get("description"):
            bad.append({"target": t, "reason": "function and description are required"})
            continue
        _append(_out() / "targets.jsonl", {"function": fn, "description": t["description"],
                                           "entries": list(t.get("entries") or []), "overlay": t.get("overlay", "")})
        good.append(fn)
    return {"ok": True, "accepted": good, "rejected": bad}


TOOLS = {f.__name__: f for f in (
    exec, run_target, reach_probe, create_seed, coverage_frontier, submit_functions, submit_vh,
    submit_verdict, create_poc, submit_poc, list_build_targets, build_harness, smoke_test, run_harness,
    submit_harness, submit_review, submit_report, submit_targets, build_project, submit_build)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ctx", required=True)
    args = ap.parse_args()
    CTX.update(json.loads(Path(args.ctx).read_text()))
    from fastmcp import FastMCP

    server = FastMCP("fb")
    for name in CTX["tools"]:
        server.tool(TOOLS[name])
    server.run()


if __name__ == "__main__":
    main()
