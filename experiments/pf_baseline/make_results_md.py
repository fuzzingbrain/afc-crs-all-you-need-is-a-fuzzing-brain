#!/usr/bin/env python3
"""Complete statistics: empty-corpus arm (FBv2 parity) as the primary column, shipped-seed arm second,
FBv2 RQ1 third; repeats (pf-empty-n2-r2/r3) folded in as a median when present."""
import json, re, statistics
from pathlib import Path
HERE = Path(__file__).resolve().parent
man = {e["id"]: e for e in json.load(open(HERE / "manifest.json"))}
skip = {l.strip() for l in open(HERE / "skip_sok_nonpf.txt") if l.strip() and not l.startswith("#")}
notes = json.load(open(HERE / "review_notes.json")) if (HERE / "review_notes.json").exists() else {}
rq1 = {}
for line in open("/home/ze/fbv2/paper/fbv2_new_paper/docs/RQ1_RESULTS_DATA.md"):
    m = re.match(r"\| (\S+-(?:del|fu)-\d+) \|.*?\| (\d/3) \| ([^|]+) \| ([\d.]+) \[.*?\| ([\d,\.]+) \| \$([\d.]+) ", line)
    if m: rq1[m.group(1)] = dict(actual=m.group(2), src=m.group(3).strip(), tmin=float(m.group(4)), cost=float(m.group(6)))
def res(tag, tid):
    p = HERE / "runs" / tag / tid / "result.json"
    return json.load(open(p)) if p.exists() else None
def cell(r, tid):
    if r is None: return None
    if r["target_hit"]:
        s = f"hit {r['time_to_target_s']:.0f}s"
        if r.get("seed_hits_target"): s += " (seed=PoV)"
        if r.get("review_needed"): s += " [line differs, reviewed same bug]"
        return s
    return f"miss {round(r['elapsed_s']/3600)}h"
SEEDED = {"cu5-del-01", "ex2-del-01", "ex3-del-02", "lx3-del-04", "sd1-fu-03", "sd1-fu-04", "sd1-fu-05"}
rows, stats = [], {"hit": 0, "miss": 0, "skipped": 0}
for tid, e in man.items():
    tag = "pf-delta-n2-r1" if e["mode"] == "delta" else "pf-full-n2-r1"
    r1 = res(tag, tid)
    if tid in skip:
        empty, seeded = "not run: SoK PF annotation = unsolvable (16 cores x 6 h x 3)", "-"; stats["skipped"] += 1
    elif tid == "da1-fu-01":
        empty = "miss 2h (guard-on 4GB) / miss 2h (guard-off fork=1); guard-off fork=2 OOM-killed at 10 and 24 GB"; seeded = "-"; stats["miss"] += 1
    elif tid in SEEDED:
        empty = cell(res("pf-empty-n2-r1", tid), tid) or "running"; seeded = cell(r1, tid)
        stats["hit" if empty.startswith("hit") else "miss"] += 1
    else:
        empty = cell(r1, tid); seeded = "(no shipped seeds: same run)"
        stats["hit" if empty and empty.startswith("hit") else "miss"] += 1
    reps = [res(f"pf-empty-n2-r{k}", tid) for k in (2, 3)]
    reps = [x for x in reps if x]
    base = res("pf-empty-n2-r1", tid) if tid in SEEDED else r1
    if reps and base:
        ts = [x["time_to_target_s"] if x["target_hit"] else None for x in [base] + reps]
        hits = sum(t is not None for t in ts)
        med = statistics.median([t for t in ts if t is not None]) if hits else None
        rep = f"{hits}/{len(ts)} hit" + (f", median {med:.0f}s" if med is not None else "") + " [" + ", ".join(f"{t:.0f}" if t is not None else "miss" for t in ts) + "]"
    else: rep = "-"
    q = rq1.get(tid, {})
    fb = f"{q['actual']} {q['src']} {q['tmin']:.1f} min ${q['cost']:.1f}" if q else "?"
    rows.append((tid, e["mode"], empty, seeded, rep, fb))
out = ["# Pure fuzzing vs FBv2 on the 40 AIxCC C targets -- complete statistics", "",
 "Primary column = **empty corpus, no dictionary**, the exact start FBv2's Global Fuzzer gets (manager.py creates an empty global/corpus; instance.py passes no -dict). libFuzzer -fork=2, same image/env/cgroup caps/flags as fuzzingbrain/fuzzer/instance.py, delta 1 h / full 2 h, stop on first target hit (all bugs for a shared harness). Judged per bug: sanitizer type + repro.sh frames + crash line for shared harnesses + crash-site function must match the official crash.txt.",
 "", f"Counts over the 40 targets: hit {stats['hit']}, miss {stats['miss']}, not run {stats['skipped']} (SoK annotates them as unsolvable by parallel fuzzing at 16 cores x 6 h).", "",
 "| target | mode | pure fuzzing, empty corpus | with the shipped seed corpus (competition build) | repeats (empty, r1-r3) | FBv2 RQ1 (k/3, source, mean time, mean $) |", "|---|---|---|---|---|---|"]
for r in rows: out.append("| " + " | ".join(str(x) for x in r) + " |")
out += ["", "## What the table says", "",
 "- Fuzzing-trivial from an empty corpus (< 2 min): 12 wireshark handlers, lx3-del-04, ex3-del-02, sd1-fu-01, sd1-fu-05, ss1-fu-00/01. FBv2 also solves these in minutes for < $3, except sd1-fu-05.",
 "- FBv2 solves, empty-corpus fuzzer does not: cu5-del-01, mg2-del-02, mg1-fu-00, ws1-fu-05, da1-fu-01, ss1-fu-02 (117 min vs 6 min), sd1-fu-04 (only via the shipped seed). FBv2's first-success source is G or S with agent seeds: the seeds, not the fuzzer, make the difference.",
 "- Empty-corpus fuzzer solves, FBv2 0/3: sd1-fu-05 (139 s). The bug fires on the second execution of the same input; FBv2's single-execution verification discards it (SoK KF4). A pipeline gap, not a capability gap.",
 "- Neither: av2-del-02, ex2-del-01, ss1-fu-04.",
 "- Shipped seeds are not neutral: they gave cu5-del-01 a 4 s hit (1 h miss without) and sd1-fu-04 a 0.9 s hit (the seed is the PoV), but slowed lx3-del-04 (22 min vs 3 s) and sd1-fu-05 (43 min vs 2 min). FBv2 never loads them.",
 "- Shared harness (shadowsocks json_fuzz, 5 bugs): 35,711 crashes in 2 h, 94% at the shallowest site (json.c:310); bug 02 seen once at 117 min, bug 04 never. Shallow bugs starve deep ones; FBv2 targets each site and gets 00-03 in 2-6 min.",
 "- xz1-fu-01: empty-corpus fuzzer 6 min vs FBv2 35 min -- the one target where bare fuzzing is clearly faster than FBv2.",
 "- dav1d @NO_OOM: with the allocation guard off, fork=2 exceeds 10 GB and 24 GB cgroup caps in minutes; guard-on (4 GB) and fork=1 variants ran 2 h without finding the CWE-190 SEGV.",
 "", "Crash-site audit: every counted hit's first in-project frame is the official PoV's function; line-only differences (lx3-del-04, sd1-fu-05 seeded run) were reviewed as the same bug. One false hit was caught and discarded (ex3-del-02 empty run #1: exif-001's exif_get_slong overflow passed the frame-only criteria), which is why the rule now requires the function to match. See review_notes.json."]
(HERE / "RESULTS_2026-09-18.md").write_text("\n".join(out) + "\n")
print("\n".join(out[3:5]))
