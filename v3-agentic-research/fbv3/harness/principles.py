"""The harness quality principles, in one place.

The generator's prompt, the reviewer's prompt and the deterministic gate all
read them from here, so they cannot drift apart (in AGF the checker required
an MSan include the generator prompt forbade, and P3/P4 were never enforced).

    P1  The harness's own logic is correct.
    P2  The target's API is used the way its protocol requires.
    P3  Only the public API is exercised.
    P4  The right entry point is driven, with the setup it needs, and the
        input actually reaches the target logic.
    P5  Under MemorySanitizer, the target's outputs are checked for
        initialisation (only when the task builds with ``memory``).

``static_findings`` checks what can be checked without an agent; the
reviewer agent checks the rest, dynamically where it can (it runs inputs).
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

PRINCIPLES = {
    "P1": (
        "Harness logic is correct",
        "The harness itself has no bugs: no undefined behaviour or memory errors of its own (unaligned or "
        "out-of-bounds reads of the input, missing NUL termination before string APIs, integer truncation of "
        "sizes), no leaks of what it allocates, no state that leaks across iterations (static buffers, "
        "globals not reset), no exit()/abort() on ordinary inputs, and it does not collapse the input space "
        "(e.g. ignoring most of the input, or rejecting almost everything).",
    ),
    "P2": (
        "Target API protocol is followed",
        "Calls follow the library's documented protocol: initialisation before use and in the right order, "
        "objects created are actually used (no create-and-discard), cleanup in the right order, parameter "
        "constraints respected (sizes, flags, ownership, NUL-terminated vs length-delimited), return values "
        "checked before outputs are used. A harness that calls nothing that consumes the input is a no-op.",
    ),
    "P3": (
        "Only the public API is used",
        "The harness includes public headers and calls public functions. No internal or private headers "
        "(internal/, private/, *_int.h, *_internal.h, *_priv.h), no #include of .c files, no static or "
        "file-local functions, no poking at struct internals the API does not expose.",
    ),
    "P4": (
        "The right entry point, with essential setup, reaching the target",
        "The harness drives the API entry point that owns the target logic, at the right level of "
        "abstraction, with the setup without which the code path is dead (e.g. a TLS server with no "
        "certificate, a decoder never given a stream header). For code that only runs when the library "
        "talks to a peer or reads a file, that setup is a peer or a stream the FUZZ INPUT controls: an "
        "in-process transport (a BIO pair, a memory stream, the library's own read/seek callbacks) or a "
        "socket on 127.0.0.1 whose bytes come from the input. Never an outside host: there is no outward "
        "network, and a crash that depended on one could not be reproduced. Inputs must actually reach "
        "the target: a harness whose fuzzing covers almost no edges, or runs too slowly to explore, "
        "fails this.",
    ),
    "P5": (
        "Outputs are checked under MemorySanitizer",
        "Only for MSan builds: after each call that produces output (buffers, out-parameters, return values "
        "read from memory), call __msan_check_mem_is_initialized(ptr, len) on it, so uninitialised output is "
        "reported where it is produced. Include <sanitizer/msan_interface.h> and the calls ONLY inside "
        "`#if defined(__has_feature)` / `#if __has_feature(memory_sanitizer)` so other builds still compile.",
    ),
}


def principles_text(sanitizers: tuple[str, ...] | list[str]) -> str:
    """The principles that apply to this task, as prompt text."""
    keys = ["P1", "P2", "P3", "P4"] + (["P5"] if "memory" in sanitizers else [])
    return "\n".join(f"- {k} — {PRINCIPLES[k][0]}: {PRINCIPLES[k][1]}" for k in keys)


@dataclass
class Finding:
    principle: str
    severity: str  # error (gate fails) | warning (reviewer decides)
    message: str
    line: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


_INCLUDE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.M)
_INTERNAL_HEADER = re.compile(r"(^|/)(internal|private|priv)(/|$)|_(int|internal|priv|private)\.h$|\.c$", re.I)


def _line_of(source: str, pos: int) -> int:
    return source.count("\n", 0, pos) + 1


def static_findings(source: str, sanitizers: tuple[str, ...] | list[str] = ("address",),
                    language: str = "c") -> list[Finding]:
    out: list[Finding] = []
    if not re.search(r"\bLLVMFuzzerTestOneInput\s*\(", source):
        out.append(Finding("P1", "error", "the harness does not define LLVMFuzzerTestOneInput"))
    m = re.search(r"^\s*int\s+main\s*\(", source, re.M)
    if m:
        out.append(Finding("P1", "error", "the harness defines main(); the fuzzing engine provides it",
                           _line_of(source, m.start())))
    for m in re.finditer(r"(?<![\w.>])(exit|_exit|abort)\s*\(", source):
        out.append(Finding("P1", "warning", f"{m.group(1)}() stops the fuzzer on an ordinary input unless it "
                           "only guards a harness-internal invariant", _line_of(source, m.start())))
    for m in _INCLUDE.finditer(source):
        hdr = m.group(1)
        if hdr.startswith("sanitizer/") or hdr.startswith("fuzzer/"):
            continue
        if _INTERNAL_HEADER.search(hdr) or hdr.startswith("../"):
            out.append(Finding("P3", "warning", f"#include of a non-public header {hdr!r}",
                               _line_of(source, m.start())))
    msan_include = re.search(r"#\s*include\s*<sanitizer/msan_interface\.h>", source)
    if "memory" in sanitizers:
        if "__msan_check_mem_is_initialized" not in source:
            out.append(Finding("P5", "error", "an MSan build is requested but no output is checked with "
                               "__msan_check_mem_is_initialized"))
    if msan_include and not _guarded(source, msan_include.start()):
        out.append(Finding("P5", "error", "<sanitizer/msan_interface.h> is included without a "
                           "__has_feature(memory_sanitizer) guard; non-MSan builds may break",
                           _line_of(source, msan_include.start())))
    return out


def _guarded(source: str, pos: int) -> bool:
    before = source[:pos]
    opened = len(re.findall(r"__has_feature\s*\(\s*memory_sanitizer\s*\)", before))
    return opened > 0


@dataclass
class Reachability:
    verdict: str  # ok | dead | slow | crash | no_run
    edges: int = 0
    exec_s: int = 0
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def classify_reachability(stats: dict, *, min_edges: int, min_exec_s: int, crashed: bool,
                          ran: bool, detail: str = "") -> Reachability:
    """The P4 gate on a smoke fuzz run."""
    edges, exec_s = int(stats.get("edges", 0)), int(stats.get("exec_s", 0))
    if not ran:
        return Reachability("no_run", edges, exec_s, detail or "the fuzz target did not run")
    if crashed:
        return Reachability("crash", edges, exec_s, detail)
    if edges < min_edges:
        return Reachability("dead", edges, exec_s, f"only {edges} edges covered (< {min_edges}): "
                            "the input barely reaches the target")
    if exec_s and exec_s <= min_exec_s:
        return Reachability("slow", edges, exec_s, f"{exec_s} exec/s (<= {min_exec_s})")
    return Reachability("ok", edges, exec_s, detail)
