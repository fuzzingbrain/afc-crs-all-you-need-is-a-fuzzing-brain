#!/usr/bin/env python3
"""Does this sanitizer report show *this* bug?  Criteria come from the bug's own
repro.sh (EXPECT type + stack frames) plus the crash line when several bugs
share a harness.  Exit 0 = target hit; prints one verdict line.
  ./verdict.py <id> <report.txt>
"""
import json, re, sys
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).resolve().parent


@lru_cache(maxsize=None)
def criteria(tid):
    e = {x["id"]: x for x in json.loads((HERE / "manifest.json").read_text())}[tid]
    t = open(e["repro_sh"]).read()
    exp = re.search(r'EXPECT="([^"]*)"', t).group(1)
    frames = re.findall(r"grep -q '([^']+)' \|\| \{ echo \"FAIL: frame", t)
    m = re.search(r"for f in ([^;]+); do", t)
    if m:
        frames += [f for f in m.group(1).split() if f != "_none_"]
    line = ""
    if e["shared_harness"] and e["crash_file"] and e["crash_line"] and ":" not in e["crash_file"].split("/")[-1]:
        line = e["crash_file"].split("/")[-1] + ":" + str(e["crash_line"])
    return exp, frames, line


def verdict(tid, text):
    exp, frames, line = criteria(tid)
    if exp not in text:
        return 1, f"FAIL: expected {exp}, not seen"
    for f in frames:
        if f not in text:
            return 1, f"FAIL: frame {f} missing -- different crash"
    if line and line not in text:
        return 1, f"FAIL: crash line {line} not in report -- sibling bug on the same harness"
    # The two repro.sh frames can sit deep in the stack and match a different bug on the same
    # harness (libexif: exif-001's exif_get_slong overflow also passes through
    # exif_data_load_data_entry). Require the crash-site FUNCTION to match the official PoV;
    # a line-only difference stays a hit flagged for review.
    o = official_frames(tid)
    if o:
        a = site_frames(text)
        if not a or a[0][0] != o[0][0]:
            return 1, f"FAIL: crash site {a[0][0] if a else '?'} != official {o[0][0]} -- different bug on this harness"
    return 0, f"OK: {tid} reproduced ({exp}{' at ' + line if line else ''})"


NOISE = ("__asan", "__interceptor", "MemcmpInterceptor", "__sanitizer", "compiler-rt", "FuzzerDriver", "FuzzerLoop")


def site_frames(text, n=4):
    """First n in-project frames as (function, file:line), interceptor/runtime frames skipped."""
    out = []
    for m in re.finditer(r"#\d+ 0x[0-9a-f]+ in (\S+) (\S+)", text):
        fn, loc = m.group(1), m.group(2)
        if any(k in fn or k in loc for k in NOISE):
            continue
        out.append((fn, loc.split("/")[-1]))
        if len(out) >= n:
            break
    return out


@lru_cache(maxsize=None)
def official_frames(tid):
    e = {x["id"]: x for x in json.loads((HERE / "manifest.json").read_text())}[tid]
    p = Path(e["repro_sh"]).with_name("crash.txt")
    return tuple(site_frames(p.read_text(errors="replace"))) if p.exists() else ()


def site_compare(tid, text):
    """Compare the artifact's crash site with the official PoV's: same function? same file:line? same top-3 functions?"""
    a, o = site_frames(text), list(official_frames(tid))
    if not a or not o:
        return {"site_fn_match": None, "site_line_match": None, "top3_fn_match": None,
                "artifact_site": a[:1], "official_site": o[:1]}
    return {"site_fn_match": a[0][0] == o[0][0], "site_line_match": a[0] == o[0],
            "top3_fn_match": [f for f, _ in a[:3]] == [f for f, _ in o[:3]],
            "artifact_site": [f"{f}@{l}" for f, l in a[:3]], "official_site": [f"{f}@{l}" for f, l in o[:3]]}


if __name__ == "__main__":
    txt = open(sys.argv[2], errors="replace").read()
    rc, msg = verdict(sys.argv[1], txt)
    if rc == 0:
        sc = site_compare(sys.argv[1], txt)
        msg += " | site " + ("same fn+line" if sc["site_line_match"] else "same fn, line differs -- REVIEW" if sc["site_fn_match"] else "DIFFERENT function -- REVIEW")
        msg += f" ({sc['artifact_site'][:1]} vs official {sc['official_site'][:1]})"
    print(msg)
    sys.exit(rc)
