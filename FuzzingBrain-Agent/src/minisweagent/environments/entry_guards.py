"""The size conditions a candidate must satisfy to reach the library at all.

Measured cause of the worst cells: on one challenge all 25 graded candidates
were thrown out before the library ran, on another 17 of 18. Every one of those
turns bought nothing.

Watching the arm we are measured against on the challenge we lost, the
difference was not information. We read the format header at turn 6 and its own
test fixture at turn 8, five turns EARLIER than it did. Then we graded an empty
file at turn 13, while it spent four more turns and submitted the format's
magic bytes. An empty file cannot pass a format check, so that grading call was
spent before it was made.

`LLVMFuzzerTestOneInput` states its entry conditions in its first lines. They
are readable, they are per-target, and a candidate that violates one is not a
hypothesis -- it is a wasted turn. This reads them so the loop can say so
before the call rather than after.
"""
from __future__ import annotations

import re

_ENTRY = re.compile(r"LLVMFuzzerTestOneInput\s*\([^)]*\)\s*\{", re.S)
# `if (size < 8) return 0;` and the shapes around it
_LT = re.compile(r"\bsize\s*<\s*(\d+|\w+\s*\+\s*\d+|sizeof\([^)]*\))")
_LE = re.compile(r"\bsize\s*<=\s*(\d+)")
_GT = re.compile(r"\bsize\s*>\s*(\d+)")
_RANGE = re.compile(r"outside_size_range\s*\(\s*size\s*,\s*(\d+)\s*,\s*([\dA-Za-z_*\s]+?)\)")
_NUM = re.compile(r"^\d+$")


def entry_window(source: str, lines: int = 40) -> str:
    """The first `lines` of the harness entry function, where the guards live."""
    m = _ENTRY.search(source or "")
    if not m:
        return ""
    return "\n".join((source[m.end():]).splitlines()[:lines])


def min_size(source: str) -> tuple[int, str] | None:
    """(smallest size that can get past the guards, the guard's own text).

    Only guards whose bound is a plain number are used. `size < sizeof(hdr)`
    is a real guard but resolving it would mean compiling the target, and a
    wrong bound here would refuse a candidate that was fine -- worse than
    saying nothing.
    """
    win = entry_window(source)
    if not win:
        return None
    best: tuple[int, str] | None = None
    for m in _RANGE.finditer(win):
        if _NUM.match(m.group(1).strip()):
            lo = int(m.group(1))
            if lo and (best is None or lo > best[0]):
                best = (lo, m.group(0).strip())
    for rx, adjust in ((_LT, 0), (_LE, 1)):
        for m in rx.finditer(win):
            g = m.group(1).strip()
            if _NUM.match(g):
                need = int(g) + adjust
                if need and (best is None or need > best[0]):
                    best = (need, m.group(0).strip())
    return best


def refusal(size: int, need: int, guard: str) -> str:
    """What the model is told instead of a verdict it was going to waste."""
    return (f"NOT GRADED. That candidate is {size} bytes and the harness "
            f"rejects it before the library sees it: `{guard}`.\n"
            f"The grading call was not spent. Build a candidate of at least "
            f"{need} bytes that satisfies the entry checks -- the format's "
            f"magic or header from the source you have already read is the "
            f"cheapest way there -- and grade that instead. If you believe the "
            f"guard does not apply, submit the same path again and it will go "
            f"through.")
