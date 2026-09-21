#!/usr/bin/env python3
"""Table of one run directory: id, mode, seeds, hit, time-to-target, artifacts."""
import json, sys
from pathlib import Path

run = Path(sys.argv[1] if len(sys.argv) > 1 else "runs")
man = {e["id"]: e for e in json.load(open(Path(__file__).with_name("manifest.json")))}
import json as _j
notes = _j.load(open(Path(__file__).with_name("review_notes.json"))) if Path(__file__).with_name("review_notes.json").exists() else {}
skip = {l.strip() for l in open(Path(__file__).with_name("skip_sok_nonpf.txt")) if l.strip() and not l.startswith("#")}
rows = []
for e in man.values():
    p = run / e["id"] / "result.json"
    r = json.load(open(p)) if p.exists() else None
    rows.append((e["id"], e["mode"], e["seeds"], r))
hits = sum(1 for *_, r in rows if r and r["target_hit"])
done = sum(1 for *_, r in rows if r)
print(f"{run}: {done}/40 run, {hits} target hits")
print(f"{'id':11s} {'mode':5s} {'seeds':>5s} {'hit':>4s} {'t_hit_s':>8s} {'arts':>4s} {'elapsed':>7s}  seed_hit  site")
for tid, mode, seeds, r in rows:
    if r is None:
        tag = "SoK: non-PF (skipped)" if tid in skip else "-"
        print(f"{tid:11s} {mode:5s} {seeds:5d}    -        -    -       -   {tag}"); continue
    print(f"{tid:11s} {mode:5s} {seeds:5d} {'yes' if r['target_hit'] else 'no':>4s} "
          f"{(r['time_to_target_s'] if r['time_to_target_s'] is not None else '-')!s:>8s} {r['artifacts']:4d} {r['elapsed_s']:7d}  "
          f"{'SEED' if r.get('seed_hits_target') else '-':>8s}  {((('reviewed:' + notes[tid]['decision']) if tid in notes else 'REVIEW') if r.get('review_needed') else ('same' if r.get('site_line_match') else '-')) if r['target_hit'] else '-'}")
