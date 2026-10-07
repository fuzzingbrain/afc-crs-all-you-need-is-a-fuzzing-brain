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
_DEFINE = re.compile(r"^\s*#\s*define\s+(\w+)\s+(\d+)\s*$", re.M)
_CONST = re.compile(r"\b(?:const\s+)?(?:size_t|int|unsigned|uint\d+_t)\s+(\w+)\s*=\s*(\d+)\s*;")
_LT = re.compile(r"\bsize\s*<\s*([\w\s+*]+?)\s*(?:\)|\|\||&&|;)")
_LE = re.compile(r"\bsize\s*<=\s*([\w\s+*]+?)\s*(?:\)|\|\||&&|;)")
_NE = re.compile(r"\bsize\s*!=\s*(\d+)")
_RANGE = re.compile(r"outside_size_range\s*\(\s*size\s*,\s*([\w\s+*]+?)\s*,")


def _resolve(expr: str, names: dict[str, int]) -> int | None:
    """A size bound as a number, or None when it cannot be known for sure.

    Plain integers, simple sums and products of them, and identifiers defined
    as integers in the same file. Never sizeof(), never an expression with an
    unknown name -- a wrong bound refuses a candidate that was fine, which is
    worse than refusing nothing.
    """
    expr = (expr or "").strip()
    if not expr or "sizeof" in expr:
        return None
    parts = re.split(r"([+*])", expr)
    total, op = None, "+"
    for tok in parts:
        tok = tok.strip()
        if tok in ("+", "*"):
            op = tok
            continue
        if not tok:
            continue
        val = int(tok) if tok.isdigit() else names.get(tok)
        if val is None:
            return None
        total = val if total is None else (total + val if op == "+" else total * val)
    return total


def _names(source: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for rx in (_DEFINE, _CONST):
        for m in rx.finditer(source or ""):
            out[m.group(1)] = int(m.group(2))
    return out


def entry_window(source: str, lines: int = 40) -> str:
    """The first `lines` of the harness entry function, where the guards live."""
    m = _ENTRY.search(source or "")
    if not m:
        return ""
    return "\n".join((source[m.end():]).splitlines()[:lines])


def min_size(source: str) -> tuple[int, str] | None:
    """(smallest size that can reach the library, the guard's own text).

    Widened after the first version fired on none of five challenges: only one
    of six harnesses states a bare `size < 8`. The rest use a named constant, a
    sum, an exact length, or a lower bound inside outside_size_range -- and
    several state no minimum at all, which this must keep reporting as None.
    """
    win = entry_window(source)
    if not win:
        return None
    names = _names(source)
    best: tuple[int, str] | None = None

    def offer(need: int | None, text: str) -> None:
        nonlocal best
        if need and need > 0 and (best is None or need > best[0]):
            best = (need, text.strip())

    for m in _NE.finditer(win):
        offer(int(m.group(1)), m.group(0))
    for m in _RANGE.finditer(win):
        offer(_resolve(m.group(1), names), m.group(0) + "...)")
    for m in _LT.finditer(win):
        offer(_resolve(m.group(1), names), "size < " + m.group(1).strip())
    for m in _LE.finditer(win):
        v = _resolve(m.group(1), names)
        offer(None if v is None else v + 1, "size <= " + m.group(1).strip())
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
