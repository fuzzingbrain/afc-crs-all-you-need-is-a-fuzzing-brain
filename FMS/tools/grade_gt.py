#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Grade an F(MS) run directory against the official AIxCC ground truth.

For every completed task it reads the PoV sanitizer reports saved under
<task>/successful_povs/fuzzer_output_*.txt, extracts the crash type and the top
in-project crash frame, and matches each report against every official bug of
the task's challenge (examples/aixcc-challenges/final-competition/<mode>/<chal>/
bugs/<bug>/bug.json + crash.txt).

A report matches a bug when BOTH hold:
  - type:  the report's sanitizer class is in the bug's expected_types
           (when the bug lists none, the type gate is skipped), and
  - site:  the report's top in-project crash FUNCTION equals the bug's official
           top frame (from expected_crash.top_frames[0] / crash.txt), or, when
           no official function is known, the crash file:line matches crash_file.

This is the pf_baseline/verdict.py rule (function-level site match, type gate),
which the memory notes settled on over ASan-top-frame or hand-authored WANT
tables.  Output: per-task HIT/MISS with which bug, by strategy vs background
fuzzer, and any crash that matched no official bug (side-channel / other bug).

  python3 FMS/tools/grade_gt.py FMS/runs/fms_all_run1
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
GT = ROOT / "examples/aixcc-challenges/final-competition"
IDX = {e["cpv"]: e for e in json.load(open(ROOT / "artifact/aixcc/index.json"))}

NOISE = ("__asan", "__interceptor", "MemcmpInterceptor", "__sanitizer",
         "compiler-rt", "FuzzerDriver", "FuzzerLoop", "FuzzerMain",
         "sanitizer_common_interceptors", "/libc", "libc_start")


def _fnbase(fn: str) -> str:
    """Strip C++ argument list / template params so names compare cleanly."""
    fn = fn.strip()
    for cut in ("(", "<"):
        i = fn.find(cut)
        if i > 0:
            fn = fn[:i]
    return fn.strip()


def site_frames(text: str, n: int = 5):
    """First n in-project frames as (function, file:line); runtime frames skipped.

    Handles frame functions that carry a (possibly space-containing) C++ argument
    list by taking the last whitespace token on the line as the location.  Falls
    back to a UBSan 'file:line:col: runtime error' location when there are no
    ASan-style numbered frames (UBSan reports have none).
    """
    out = []
    for m in re.finditer(r"#\d+ 0x[0-9a-f]+ in (.+?)\s+(\S+)\s*$", text, re.M):
        fn, loc = _fnbase(m.group(1)), m.group(2)
        if any(k in fn or k in loc for k in NOISE) or any(k in m.group(1) for k in NOISE):
            continue
        out.append((fn, loc.split("/")[-1]))
        if len(out) >= n:
            break
    if not out:
        # UBSan / minimal reports have no numbered frames: take the SUMMARY line's
        # 'file:line' (or a 'path:line: runtime error') as a function-less site.
        u = (re.search(r"SUMMARY: \w*Sanitizer: \S+ (\S+?):(\d+)", text)
             or re.search(r"(\S+?):(\d+)(?::\d+)?: runtime error", text))
        if u:
            out.append(("", f"{u.group(1).split('/')[-1]}:{u.group(2)}"))
    return out


def report_type(text: str) -> str:
    """Normalised crash class from a sanitizer report."""
    m = re.search(r"(?:ERROR|WARNING): \w*Sanitizer: ([A-Za-z0-9_-]+)", text)
    if m:
        return m.group(1)
    if "runtime error: signed integer overflow" in text:
        return "signed-integer-overflow"
    if "runtime error:" in text and "overflow" in text:
        return "integer-overflow"
    if "deadly signal" in text:
        return "deadly-signal"
    return "?"


def type_ok(rtype: str, expected: list | None, crash_type: str | None) -> bool:
    if not expected:
        return True  # no type gate for this bug
    exp = set(expected)
    if crash_type:
        exp.add(crash_type)
    if rtype in exp:
        return True
    # SEGV / null-deref equivalence
    if rtype == "SEGV" and ({"null-deref", "SEGV"} & exp):
        return True
    return False


def load_bugs(mode: str, chal: str) -> list[dict]:
    d = GT / mode / chal / "bugs"
    bugs = []
    if not d.exists():
        return bugs
    for b in sorted(d.iterdir()):
        bj = b / "bug.json"
        if not bj.exists():
            continue
        j = json.load(open(bj))
        c = j.get("consistency", {})
        top = (j.get("expected_crash") or {}).get("top_frames") or []
        # official in-project top frame: prefer crash.txt's first in-project frame
        off_fn = None
        ct = c.get("crash_file") or ""
        cx = b / "crash.txt"
        if cx.exists():
            sf = site_frames(cx.read_text(errors="replace"))
            if sf:
                off_fn = sf[0][0]
        if not off_fn and top:
            off_fn = top[0]
        patch_files = {Path(p).name for p in (c.get("patch_files") or [])}
        patch_fns = set(c.get("patch_functions") or [])
        bugs.append({
            "bug": j.get("bug") or b.name,
            "expected_types": c.get("expected_types"),
            "crash_type": c.get("crash_type"),
            "crash_file": ct.split("/")[-1],          # file:line (may be "" )
            "crash_fileonly": ct.split("/")[-1].split(":")[0],
            "patch_files": patch_files,
            "patch_fns": patch_fns,
            "off_fn": off_fn,
        })
    return bugs


def bug_files(bug: dict) -> set:
    files = set(bug["patch_files"])
    if bug["crash_fileonly"]:
        files.add(bug["crash_fileonly"])
    return files


def match(rtype: str, rfn: str, rfileline: str, bug: dict, file_unique: bool) -> bool:
    """file_unique: within this challenge, the report's file maps to only this bug."""
    if not type_ok(rtype, bug["expected_types"], bug["crash_type"]):
        return False
    # Function-level match (strongest). For delta the gold is the patched
    # function (patch_functions); crash.txt's top frame can be a downstream
    # manifestation (e.g. curl-001: patch dict_do, crash.txt shows formatf).
    if rfn and (rfn in bug["patch_fns"] or rfn == bug["off_fn"]):
        return True
    # If the function clearly identifies a DIFFERENT sibling in this file, reject.
    if rfn and bug["off_fn"] and rfn != bug["off_fn"] and not bug["patch_fns"] \
            and not file_unique:
        return False
    # File-level fallback ('type in expected_types + file in patch'), only when
    # the file is unambiguous for this challenge (no sibling bug shares it) or
    # the report carries no function (UBSan).
    rfile = rfileline.split(":")[0]
    if (not rfn or file_unique) and rfile and rfile != "?" and rfile in bug_files(bug):
        return True
    return False


def grade_task(tdir: Path, mode: str, chal: str) -> dict:
    bugs = load_bugs(mode, chal)
    # count how many bugs of this challenge reference each file (for disambiguation)
    fcount: dict[str, int] = {}
    for bug in bugs:
        for f in bug_files(bug):
            fcount[f] = fcount.get(f, 0) + 1
    pov_dir = tdir / "successful_povs"
    reports = sorted(pov_dir.glob("fuzzer_output_*.txt")) if pov_dir.exists() else []
    hits: dict[str, set] = {}       # bug -> {"strategy","fuzzer"}
    unmatched = []                  # (source, type, fn@fileline)
    for rp in reports:
        src = "fuzzer" if rp.name.endswith("_fuzzer.txt") else "strategy"
        text = rp.read_text(errors="replace")
        rtype = report_type(text)
        sf = site_frames(text)
        rfn, rfileline = (sf[0] if sf else ("?", "?"))
        rfile = rfileline.split(":")[0]
        matched = None
        for bug in bugs:
            if match(rtype, rfn, rfileline, bug, file_unique=(fcount.get(rfile, 0) == 1)):
                matched = bug["bug"]
                break
        if matched:
            hits.setdefault(matched, set()).add(src)
        else:
            unmatched.append((src, rtype, f"{rfn}@{rfileline}"))
    return {"bugs": bugs, "hits": hits, "unmatched": unmatched, "n_reports": len(reports)}


def main() -> int:
    run = Path(sys.argv[1])
    rows = [l.split("\t") for l in (run / "results.tsv").read_text().splitlines()[1:]]
    # group CPVs by challenge (CPVs sharing a task share a run dir = first CPV)
    print(f"{'task-dir':<14} {'chal':<20} {'mode':<6} hit?  bugs-hit (by)            unmatched")
    print("-" * 110)
    n_hit = 0
    for row in rows:
        cpv = row[0]
        e = IDX[cpv]
        chal, mode = e["challenge"], e["mode"]
        tdir = run / cpv
        if not tdir.exists():
            continue
        g = grade_task(tdir, mode, chal)
        hit = bool(g["hits"])
        n_hit += 1 if hit else 0
        bugs_str = ", ".join(f"{b}({'+'.join(sorted(s))})" for b, s in g["hits"].items()) or "-"
        um = "; ".join(f"{s}:{t}:{loc}" for s, t, loc in g["unmatched"][:3])
        print(f"{cpv:<14} {chal:<20} {mode:<6} {'HIT ' if hit else 'MISS'}  {bugs_str:<24} {um}")
    print("-" * 110)
    print(f"tasks with >=1 official bug hit: {n_hit}/{len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
