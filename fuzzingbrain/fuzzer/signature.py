"""What makes two crashes the same crash.

Deduplicating on the input's bytes counts distinct inputs, not distinct bugs: a
fuzzer that finds one overflow ten ways files ten crashes, and a POV count built
on that says ten when the answer is one.

A signature is the sanitizer's class plus the innermost project frames -- the
place the program broke and how it broke. Two things it deliberately leaves out:

  * harness frames, which every crash on a given target shares and which
    therefore carry no information about which bug this is;
  * the outer call chain, which varies with the input that got there. Two inputs
    reaching the same overflow through different callers are the same bug.

The frame count is the whole tradeoff. Too few and separate bugs in one function
collapse together; too many and one bug splits, because -O1 inlining moves the
boundary between frames -- in wireshark's json dissector the faulting frame and
its caller share a program counter outright. It is configurable for that reason,
and the default was chosen by running every bug in the corpus through it.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

# ASan/UBSan/LSan report the class in different places and spellings.
_ASAN_ERROR = re.compile(r"ERROR: \w*Sanitizer: ([a-zA-Z0-9_-]+)")
_UBSAN_LINE = re.compile(r"runtime error: (.+?)(?:\s*\(|$)", re.MULTILINE)
_LSAN_LEAK = re.compile(r"(?:ERROR: LeakSanitizer|SUMMARY: .*LeakSanitizer)")
_LIBFUZZER_DEADLY = re.compile(r"(?:DEADLYSIGNAL|SEGV on unknown address)")

# "#3 0x55f0 in mg_vxprintf /src/mongoose/mongoose.c:1234:9"
# The function is everything between "in " and the path, because a demangled
# C++ frame contains spaces: "operator new(unsigned long)" truncated at the
# first word becomes "operator", which then slips past the runtime-frame filter
# and lands in the signature.
_FRAME = re.compile(
    r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+(/[^\s:]+|[^\s:/]+\.[a-zA-Z]+)"
    r"(?::(\d+))?(?=[\s:]|$)"
)

# ASan spells the same fault differently on the ERROR line and the SUMMARY line.
_CLASS_ALIASES = {
    "requested": "allocation-size-too-big",
    "detected": "memory-leak",
    "SEGV": "segv",
    "DEADLYSIGNAL": "segv",
}

# Frames belonging to the fuzzing machinery rather than the program under test.
_RUNTIME_FRAME = re.compile(
    r"^(?:__|_Z|fuzzer::|LLVMFuzzerTestOneInput$|main$|__libc_start_main$"
    r"|start_thread$|clone$|__asan|__lsan|__ubsan|__sanitizer|operator new"
    r"|operator delete|std::)"
)
_RUNTIME_PATH = ("/llvm-project/", "/compiler-rt/", "/usr/lib/", "/lib/x86_64")


@dataclass(frozen=True)
class CrashSignature:
    """The identity of a crash: how it broke, and where."""

    crash_class: str
    frames: tuple = field(default_factory=tuple)  # (func, file, line) innermost first

    @property
    def key(self) -> str:
        """A stable string two crashes share exactly when they are the same.

        The faulting frame carries its line; the frames behind it do not. One
        function often holds several distinct bugs -- shadowsocks has five
        separate overflows inside json_parse_ex -- and without the line they
        collapse into one, which is exactly the undercount this class exists to
        prevent. Deduplication happens within a run, against one binary, so the
        line is stable; the callers' lines are dropped because they move with
        whatever input reached them.
        """
        parts = [self.crash_class or "unknown"]
        for i, (fn, fl, ln) in enumerate(self.frames):
            parts.append(f"{fn}@{fl}:{ln}" if i == 0 and ln > 0 else f"{fn}@{fl}")
        return "|".join(parts)

    @property
    def short(self) -> str:
        """A hash for storage and comparison, and for logging without noise."""
        return hashlib.sha1(self.key.encode()).hexdigest()[:16]

    def describe(self) -> str:
        if not self.frames:
            return self.crash_class or "unknown"
        top = self.frames[0]
        return f"{self.crash_class or 'unknown'} in {top[0]}"

    def __bool__(self) -> bool:
        return bool(self.crash_class or self.frames)


def _canonical_class(raw: str) -> str:
    raw = (raw or "").strip()
    return _CLASS_ALIASES.get(raw, raw)


def _is_runtime_frame(func: str, path: str, harness_names: Sequence[str]) -> bool:
    """Whether this frame belongs to the fuzzing machinery, not the program.

    The harness names are passed in rather than pattern-matched: AIxCC harnesses
    are called handler_telnet, TestFuzzCoreServer, customfuzz3 and
    avif_fuzztest_yuvrgb@YuvRgbFuzzTest.Convert, and no pattern covers that set.
    Knowing the name is both cheaper and correct.
    """
    if _RUNTIME_FRAME.match(func):
        return True
    if any(seg in path for seg in _RUNTIME_PATH):
        return True
    base = path.rsplit("/", 1)[-1]
    for h in harness_names:
        if not h:
            continue
        stem = h.split("@")[0]
        if stem and (stem in base or stem == func):
            return True
    return bool(re.search(r"(?:_fuzzer|_fuzz|fuzz_target)\.(?:c|cc|cpp)$", base))


def extract_class(output: str) -> str:
    """The sanitizer's name for what went wrong."""
    m = _ASAN_ERROR.search(output)
    if m:
        return _canonical_class(m.group(1))
    if _LSAN_LEAK.search(output):
        return "memory-leak"
    m = _UBSAN_LINE.search(output)
    if m:
        return f"undefined-behavior: {m.group(1).strip()[:60]}"
    if _LIBFUZZER_DEADLY.search(output):
        return "segv"
    return ""


def compute_signature(
    output: str,
    harness_names: Optional[Sequence[str]] = None,
    frame_depth: int = 3,
) -> CrashSignature:
    """The signature of the crash described by `output`.

    Args:
        output: the sanitizer's report, as printed.
        harness_names: harnesses whose frames are not part of the identity.
        frame_depth: how many project frames make up the identity.
    """
    harness_names = list(harness_names or [])
    frames: List[tuple] = []
    for m in _FRAME.finditer(output):
        func, path, line = m.group(1), m.group(2) or "", m.group(3)
        if _is_runtime_frame(func, path, harness_names):
            continue
        frames.append((func, path.rsplit("/", 1)[-1], int(line) if line else -1))
        if len(frames) >= max(1, frame_depth):
            break
    return CrashSignature(crash_class=extract_class(output), frames=tuple(frames))
