"""The function index from a binary's symbols, when there is no coverage build.

The coverage build is the better source (it also says which functions ran), but
a prebuilt fuzz target -- a CyberGym / ARVO case, or any binary handed to us --
often comes alone. ``nm`` lists what is linked into it and ``llvm-symbolizer``
maps each symbol to file:line from the debug info, which is enough for the
mapper's name check and for the finder to read the right lines.

``execution_count`` is 0 for every row: linked is not executed. Without a
coverage build the directed loop has no A set, so the mapper's ranked list
drives the queue.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from fbv3.fuzz.coverage import NON_PROJECT, FunctionRow

logger = logging.getLogger(__name__)

SCRIPT = """
set -e
export PATH=/ws/out/llvm:$PATH
nm --defined-only -t x "{binary}" 2>/dev/null | awk '$2 ~ /^[TtWw]$/ && NF >= 3 {{print "0x"$1"\\t"$3}}' \
  | sort -u -k2,2 > /tmp/fbv3_syms
cut -f1 /tmp/fbv3_syms | llvm-symbolizer --obj="{binary}" --functions=linkage --output-style=LLVM \
  --demangle 2>/dev/null > /tmp/fbv3_locs || true
cat /tmp/fbv3_syms
echo '==FBV3-SPLIT=='
cat /tmp/fbv3_locs
"""

# Only absolute paths: a relative one in the debug info comes from a stdlib or
# toolchain build, not from the project tree the agents read.
_LOC = re.compile(r"^(/[^\s:]+):(\d+):(\d+)$")
# Compiler-generated entry points, not code anyone wrote.
_GENERATED = re.compile(r"^(_GLOBAL__|__cxx_global_var_init|_sub_I_|GCC_except|\.)")


def _end_line(path: Path, start: int, limit: int = 2000) -> int:
    """Where the function body ends, by the first closing brace in column 0."""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return start
    for i in range(start, min(len(lines), start + limit)):
        if lines[i].startswith("}"):
            return i + 1
    return min(len(lines), start + 80)


def linked_functions(ws, *, binary: str, timeout_s: int = 600) -> tuple[list[FunctionRow], str]:
    """(rows, error) for the functions linked into ``binary`` (a container path)."""
    res = ws.exec(["bash", "-lc", SCRIPT.format(binary=binary)], timeout=timeout_s)
    text = res.stdout.decode("utf-8", "replace")
    if "==FBV3-SPLIT==" not in text:
        return [], (f"symbol listing failed (exit {res.returncode}): "
                    f"{res.stderr.decode('utf-8', 'replace')[-800:]}")
    syms_part, locs_part = text.split("==FBV3-SPLIT==", 1)
    names = [line.split("\t")[1] for line in syms_part.splitlines() if "\t" in line]
    # llvm-symbolizer prints one record per address: a function line, a location
    # line, then a blank line.
    records: list[tuple[str, str, int]] = []
    block: list[str] = []
    for line in locs_part.splitlines():
        if line.strip():
            block.append(line.strip())
            continue
        if len(block) >= 2:
            m = _LOC.match(block[-1])
            if m:
                records.append((block[0], m.group(1), int(m.group(2))))
        block = []
    if len(block) >= 2:
        m = _LOC.match(block[-1])
        if m:
            records.append((block[0], m.group(1), int(m.group(2))))
    rows: dict[tuple[str, str], FunctionRow] = {}
    for i, (fname, file, line) in enumerate(records):
        name = fname if fname and fname != "??" else (names[i] if i < len(names) else "")
        if not name or name == "??" or not file or file == "??":
            continue
        if _GENERATED.match(name):
            continue
        if any(m in file for m in NON_PROJECT):
            continue
        key = (name, file)
        if key in rows:
            rows[key].start_line = min(rows[key].start_line, line)
            continue
        host = None
        try:
            host = ws.to_host(file) if file.startswith(("/ws/", "/src/")) else None
        except ValueError:
            host = None
        end = _end_line(host, line) if host is not None and host.is_file() else line + 80
        rows[key] = FunctionRow(name, file, line, end, 0)
    if not rows:
        return [], "no project functions with debug info were found in the binary"
    return list(rows.values()), ""
