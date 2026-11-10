"""Function index and coverage from the coverage-instrumented build.

The coverage build is run over a corpus and ``llvm-cov export`` turns the
profile into per-function rows (name, file, line range, execution count). One
export gives both halves of the directed queue with no static analysis:

* A: functions with ``execution_count > 0`` -- proven reachable from the harness;
* B: project functions linked into the target but not yet executed.

Runs in the workspace container (anything with an ``exec(argv, timeout=)``
returning a CompletedProcess with bytes output).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

NON_PROJECT = ("/usr/", "/src/llvm-project/", "compiler-rt/", "/root/.cache/", "libfuzzer/",
               "/src/aflplusplus/", "/src/libfuzzer/", "/src/honggfuzz/")


@dataclass
class FunctionRow:
    name: str
    file: str
    start_line: int
    end_line: int
    execution_count: int

    def to_dict(self) -> dict:
        return asdict(self)


def export_script(coverage_binary: str, corpus_dir: str, prof_dir: str, max_inputs: int = 4000) -> str:
    return f"""
set -e
export PATH=/ws/out/llvm:$PATH
rm -rf {prof_dir} && mkdir -p {prof_dir}
trap 'rm -rf {prof_dir}' EXIT
: > {prof_dir}/empty_input
i=0
if [ -d "{corpus_dir}" ]; then
  for f in "{corpus_dir}"/*; do
    [ -f "$f" ] || continue
    LLVM_PROFILE_FILE="{prof_dir}/$i.profraw" timeout 30 "{coverage_binary}" "$f" >/dev/null 2>&1 || true
    i=$((i+1))
    [ $i -ge {max_inputs} ] && break
  done
fi
LLVM_PROFILE_FILE="{prof_dir}/empty.profraw" timeout 30 "{coverage_binary}" {prof_dir}/empty_input >/dev/null 2>&1 || true
llvm-profdata merge -sparse {prof_dir}/*.profraw -o {prof_dir}/merged.profdata
llvm-cov export -instr-profile={prof_dir}/merged.profdata -skip-expansions -Xdemangler=c++filt \\
  "{coverage_binary}" 2>{prof_dir}/export.err \\
  || {{ echo "demangling export failed:" >&2; cat {prof_dir}/export.err >&2; \\
       llvm-cov export -instr-profile={prof_dir}/merged.profdata "{coverage_binary}"; }}
"""

DEMANGLE = "export PATH=/ws/out/llvm:$PATH; c++filt 2>/dev/null || llvm-cxxfilt 2>/dev/null || cat"


# llvm-cov region: [line_start, col_start, line_end, col_end, count, file_id,
# expanded_file_id, kind], kind 0 = Code, 1 = Expansion, 2 = Skipped, 3 = Gap.
REGION_KIND, REGION_FILE_ID = 7, 5


def _code_regions(regions: list) -> list:
    """Only the function's own code regions bound its body.

    A macro expanded inside a function contributes a region at the macro's
    own line, so zlib's deflate() came out spanning lines 58-1290 -- nearly
    the whole file -- instead of 981-1290. A finder then reads 1200 lines
    instead of the function, and the coverage frontier reports every name in
    the file as something that function calls.
    """
    code = [r for r in regions
            if len(r) > REGION_KIND and r[REGION_KIND] == 0 and r[REGION_FILE_ID] == 0]
    return code or regions


def _plain_name(name: str, file: str) -> str:
    """``trees.c:pqdownheap`` -> ``pqdownheap``.

    llvm-cov qualifies a function with internal linkage by its file, because
    two translation units may each define one. The agents read the source and
    the mapper submits what they see there, so the index keeps the bare name.
    """
    prefix = file.rsplit("/", 1)[-1] + ":"
    return name[len(prefix):] if name.startswith(prefix) else name


def parse_export(data: dict) -> list[FunctionRow]:
    rows: list[FunctionRow] = []
    for export in data.get("data", []):
        for fn in export.get("functions", []):
            filenames = fn.get("filenames") or []
            if not filenames or any(m in filenames[0] for m in NON_PROJECT):
                continue
            regions = _code_regions(fn.get("regions") or [])
            start = min((r[0] for r in regions), default=0)
            end = max((r[2] for r in regions), default=start)
            rows.append(FunctionRow(_plain_name(fn.get("name", ""), filenames[0]), filenames[0],
                                    int(start), int(end), int(fn.get("count", 0))))
    merged: dict[tuple, FunctionRow] = {}
    for row in rows:  # one row per instantiation: keep the max count, widest span
        cur = merged.get((row.name, row.file))
        if cur is None:
            merged[(row.name, row.file)] = row
        else:
            cur.execution_count = max(cur.execution_count, row.execution_count)
            cur.start_line = min(cur.start_line, row.start_line) or cur.start_line
            cur.end_line = max(cur.end_line, row.end_line)
    return list(merged.values())


def collect_functions(ws, *, coverage_binary: str, corpus_dir: str, timeout_s: int = 900) -> tuple[list[FunctionRow], str]:
    """(rows, error). Each call uses its own profile dir, so concurrent exports never clash."""
    prof_dir = f"/ws/coverage/prof-{uuid.uuid4().hex[:12]}"
    res = ws.exec(["bash", "-lc", export_script(coverage_binary, corpus_dir, prof_dir)], timeout=timeout_s)
    if res.returncode != 0:
        return [], f"coverage export failed (exit {res.returncode}): {res.stderr.decode('utf-8', 'replace')[-1500:]}"
    try:
        data = json.loads(res.stdout.decode("utf-8", "replace"))
    except ValueError as exc:
        return [], f"llvm-cov export did not produce JSON: {exc}"
    rows = parse_export(data)
    return demangle(ws, rows), ""


def demangle(ws, rows: list[FunctionRow], timeout_s: int = 120) -> list[FunctionRow]:
    """Turn any mangled C++ names into the ones that appear in the source.

    llvm-cov only demangles when its -Xdemangler run succeeds; when that falls
    back, every C++ name comes out as _ZNK6json11... The agents read the source
    and the mapper submits what they see there, so a mangled index disagrees
    with them -- json11's came out 141 names of 142 mangled.
    """
    mangled = sorted({r.name for r in rows if r.name.startswith("_Z")})
    if not mangled:
        return rows
    res = ws.exec(["bash", "-lc", DEMANGLE], timeout=timeout_s,
                  stdin=("\n".join(mangled) + "\n").encode())
    out = res.stdout.decode("utf-8", "replace").splitlines()
    if len(out) != len(mangled):
        logger.warning("demangling returned %d names for %d symbols; keeping the mangled ones",
                       len(out), len(mangled))
        return rows
    table = {m: d.strip() for m, d in zip(mangled, out) if d.strip() and d.strip() != m}
    for r in rows:
        if r.name in table:
            r.name = table[r.name]
    return rows


def write_index(rows: list[FunctionRow], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([r.to_dict() for r in rows], indent=1) + "\n")


def load_index(path: Path) -> list[FunctionRow]:
    try:
        return [FunctionRow(**r) for r in json.loads(Path(path).read_text())]
    except (OSError, ValueError, TypeError):
        return []


def snapshot(rows: list[FunctionRow], path: Path) -> dict:
    covered = [r for r in rows if r.execution_count > 0]
    summary = {"functions_total": len(rows), "functions_covered": len(covered),
               "covered_names": sorted(r.name for r in covered)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=1) + "\n")
    return summary
