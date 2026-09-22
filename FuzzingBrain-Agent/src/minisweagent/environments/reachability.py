"""Reachability facts, computed by the harness rather than asked of the model.

The agent and every arm it is measured against share a model, a tool set and a
budget, so nothing the MODEL does can be an advantage. What can is work this
loop performs without spending a turn on it.

Two facts are worth that treatment, both chosen from measured failures:

  coverage   Of the candidates graded in five zero-scoring cells, almost every
             one was thrown out before the library ran -- 25 of 25 on one
             challenge, 17 of 18 on another. Nothing in the verdict says so.
             The target prints it, and the agent ran the command exactly zero
             times across 706 shell commands until it was handed one; even
             then it parsed 12248 lines to find the one that mattered.

  callers    A signature is the fault type plus the top frames, so the same
             function reached through another caller scores again. That is a
             `objdump` query away and it is how both avro cells were lost.

Nothing here touches the grader. The oracle is called once per turn by the
model, exactly as before; these read the readable copy of the target that the
bench mounts, which costs no grading call and banks no crash.
"""
from __future__ import annotations

import re

TARGET = "/usr/local/share/target/asan/harness"
TARGET_LIBS = "/usr/local/share/target/sharedlibs"
ENTRY = "LLVMFuzzerTestOneInput"

_COV = re.compile(r"^(UN)?COVERED_FUNC:.*?\s(\S+)\s+\S+:\d+", re.M)
_FN = re.compile(r"^[0-9a-f]+ <([^>]+)>:")


def coverage_cmd(path: str) -> str:
    """Ask the target which functions this input reached."""
    return (f"LD_LIBRARY_PATH={TARGET_LIBS} {TARGET} -runs=1 -print_coverage=1 "
            f"{path} 2>&1 | grep -E '^(UN)?COVERED_FUNC:'")


def parse_coverage(text: str) -> tuple[set[str], bool | None]:
    """(functions reached, whether the harness entry itself was reached).

    The entry flag is the one that matters most: if it is False the input never
    got into the harness at all, and nothing about its contents is worth
    discussing yet.
    """
    covered: set[str] = set()
    entry: bool | None = None
    for un, name in _COV.findall(text or ""):
        if not un:
            covered.add(name)
        if name == ENTRY:
            entry = not un
    return covered, entry


def coverage_note(covered: set[str], entry: bool | None,
                  previous: set[str] | None) -> str:
    """One line of reachability, or "" when there is nothing to say."""
    if entry is False:
        return ("[reach] that input never entered the harness -- "
                f"{ENTRY} was not reached. Its contents do not matter yet; "
                "only the entry guards do.")
    if not covered:
        return ""
    new = covered - previous if previous else set()
    line = f"[reach] reached {len(covered)} functions"
    if previous is not None:
        if new:
            shown = ", ".join(sorted(new)[:6])
            line += f", {len(new)} of them new: {shown}"
        else:
            line += ", none of them new -- that candidate went no further than the last"
    return line + "."


def callers_cmd(func: str) -> str:
    """Every call site of `func`, read from the target binary itself."""
    safe = re.sub(r"[^\w:]", "", func)
    return (f"objdump -d --no-show-raw-insn {TARGET} 2>/dev/null | "
            "awk '/^[0-9a-f]+ <.*>:/{fn=$2} /call/ && /" + safe +
            "/{print fn}' | sort -u")


def parse_callers(text: str, func: str) -> list[str]:
    out = []
    for line in (text or "").splitlines():
        name = line.strip().strip("<>:")
        if name and name != func:
            out.append(name)
    return out


def callers_note(func: str, callers: list[str], covered: set[str]) -> str:
    """Which call sites of the faulting function are still untried."""
    if not callers:
        return ""
    untried = [c for c in callers if c not in covered]
    line = f"[callers] {func} is called from {len(callers)} place(s)"
    if untried:
        line += (f"; {len(untried)} your input did not go through: "
                 + ", ".join(untried[:8]))
        line += ". Each is a different signature and scores separately."
    else:
        line += "; your input already went through all of them."
    return line
