"""A short fuzz run of a built harness, judged for reachability (P4).

Used by the generator's ``smoke_test`` tool and, independently, by the
orchestrator's gate: the gate never trusts a result an agent could have
written into its own session directory.
"""

from __future__ import annotations

import re
import uuid
from typing import Callable

from fbv3.fuzz import signature as sigmod
from fbv3.harness.principles import classify_reachability

# Both spellings: a deep stack trace can be tens of thousands of characters, so
# the ERROR line scrolls out of any bounded tail and only the SUMMARY survives.
# toml11's 256-frame recursion did exactly that, and the crash went unnoticed.
SAN_MARKERS = ("ERROR: AddressSanitizer", "SUMMARY: AddressSanitizer",
               "ERROR: MemorySanitizer", "WARNING: MemorySanitizer", "SUMMARY: MemorySanitizer",
               "ERROR: LeakSanitizer", "SUMMARY: LeakSanitizer",
               "runtime error:", "SUMMARY: UndefinedBehaviorSanitizer",
               "ERROR: libFuzzer: deadly signal", "SUMMARY: libFuzzer: deadly signal",
               "ERROR: libFuzzer: out-of-memory")
# Fork mode prints "exec/s 14244" (no colon) and some lines carry no rate at all,
# so edges/features and the rate are read separately.
COV = re.compile(r"\bcov:\s*(\d+)\s+ft:\s*(\d+)")
RATE = re.compile(r"\bexec/s:?\s*(\d+)")
RUN_ENV = {"ASAN_OPTIONS": "detect_leaks=0:symbolize=1:abort_on_error=0:handle_abort=1:allocator_may_return_null=1",
           "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1", "MSAN_OPTIONS": "halt_on_error=1"}
SYMBOLIZER = "/ws/out/llvm/llvm-symbolizer"
# docker itself failing is not a verdict on the harness. A workspace container
# can be gone -- OOM-killed by the host, removed by a cleanup -- and blaming the
# agent for it sends it to fix code that was never the problem.
INFRA_MARKERS = ("No such container", "Cannot connect to the Docker daemon",
                 "is not running", "No space left on device", "OCI runtime")


def run_env(have_symbolizer: bool = True) -> dict:
    env = dict(RUN_ENV)
    if have_symbolizer:
        env["ASAN_SYMBOLIZER_PATH"] = env["MSAN_SYMBOLIZER_PATH"] = SYMBOLIZER
    return env


def parse_stats(text: str, seconds: int) -> dict:
    """The last edge/feature counts and the last execution rate libFuzzer printed."""
    stats: dict = {}
    for m in COV.finditer(text):
        stats["edges"], stats["features"] = int(m.group(1)), int(m.group(2))
    for m in RATE.finditer(text):
        if int(m.group(1)) > 0:
            stats["exec_s"] = int(m.group(1))
    m = re.search(r"stat::number_of_executed_units:\s*(\d+)", text)
    if m:
        stats["executions"] = int(m.group(1))
        if not stats.get("exec_s"):
            stats["exec_s"] = int(m.group(1)) // max(1, seconds)
    return stats


def judge(text: str, *, seconds: int, min_edges: int, min_exec_s: int, harness_names: list[str]) -> dict:
    stats = parse_stats(text, seconds)
    crashed = any(mk in text for mk in SAN_MARKERS)
    ran = bool(stats) or crashed or "INITED" in text
    detail, sig_short = "", ""
    if crashed:
        sig = sigmod.compute_signature(text, harness_names=harness_names)
        if sig:
            detail, sig_short = f"crashed: {sig.describe()}", sig.short
        else:
            detail = "crashed"
    verdict = classify_reachability(stats, min_edges=min_edges, min_exec_s=min_exec_s, crashed=crashed,
                                    ran=ran, detail=detail)
    return {**verdict.to_dict(), "stats": stats, "signature": sig_short}


TAIL_MARK = "==FBV3-SMOKE-TAIL=="


def script(binary: str, corpus: str, seconds: int) -> str:
    """Fuzz briefly, and make sure the coverage lines survive the trace.

    A bounded tail of the raw output is not enough: one deep stack trace fills
    it and the "cov: N ft: M" lines are gone, which reads as a harness that
    covered nothing. The counters are grepped out separately first.
    """
    log = f"{corpus}.log"
    return (f"mkdir -p {corpus}; timeout {seconds + 30} {binary} {corpus} -max_total_time={seconds} "
            f"-timeout=10 -rss_limit_mb=2048 -detect_leaks=0 -print_final_stats=1 "
            f"-artifact_prefix={corpus}/ > {log} 2>&1; "
            f"grep -aE '\\bcov: [0-9]+' {log} | tail -3; "
            f"grep -aE 'ERROR: |SUMMARY: ' {log} | head -4; "
            f"echo '{TAIL_MARK}'; tail -c 30000 {log}")


def infra_failure(text: str) -> str:
    """The infrastructure error in this output, if that is what went wrong."""
    for m in INFRA_MARKERS:
        if m in text:
            return m
    return ""


def smoke(run: Callable[[str, int], tuple[int, str]], *, binary: str, work_dir: str, seconds: int,
          min_edges: int, min_exec_s: int, harness_names: list[str]) -> dict:
    """``run(shell_script, timeout_s) -> (exit_code, output)`` runs in the workspace container."""
    seconds = max(5, min(int(seconds), 300))
    corpus = f"{work_dir}/smoke-{uuid.uuid4().hex[:6]}"
    _, text = run(script(binary, corpus, seconds), seconds + 60)
    infra = infra_failure(text)
    if infra:
        return {"verdict": "infra", "edges": 0, "exec_s": 0, "detail": f"the smoke run could not start: {infra}",
                "stats": {}, "signature": "", "seconds": seconds, "infra": infra,
                "output_tail": text[-2000:]}
    out = judge(text, seconds=seconds, min_edges=min_edges, min_exec_s=min_exec_s, harness_names=harness_names)
    out["seconds"] = seconds
    out["output_tail"] = text[-(5000 if out["verdict"] in ("crash", "no_run") else 1500):]
    return out
