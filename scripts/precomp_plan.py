#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check the pre-competition task files and write per-run copies.

    precomp_plan.py <out_dir> <budget_usd> <timeout_minutes|-> <task.json> ...

Refuses to plan anything that would misfire hours later: a task file without
model_profile (it would silently run on the "current" profile, i.e. Sonnet),
or one whose prebuilt binary, graph or harness source is not on disk.

For every input it writes <out_dir>/tasks/<tag>__<task_id>.json with the
budget and (optionally) the timeout replaced, concurrency forced to 1, and a
fresh task_id so the result can be read back from MongoDB. Prints one line
per task and the worst-case total, and the plan as TSV to <out_dir>/plan.tsv.
"""
import json
import os
import sys
from pathlib import Path

from bson import ObjectId


def main() -> int:
    out = Path(sys.argv[1])
    budget = float(sys.argv[2])
    timeout = None if sys.argv[3] == "-" else int(sys.argv[3])
    files = [Path(p) for p in sys.argv[4:]]
    (out / "tasks").mkdir(parents=True, exist_ok=True)

    problems, rows = [], []
    for f in files:
        t = json.loads(f.read_text())
        tag = f.stem
        why = []
        if not t.get("model_profile"):
            why.append("no model_profile")
        for k in ("repo_url", "fuzz_tooling_url", "prebuild_dir"):
            if t.get(k) and not os.path.isdir(t[k]):
                why.append(f"{k} missing: {t[k]}")
        for h, b in (t.get("prebuilt_fuzzers") or {}).items():
            if not os.path.isfile(b):
                why.append(f"binary for {h} missing: {b}")
        for h, srcs in (t.get("fuzzer_sources") or {}).items():
            for s in srcs:
                if not os.path.isfile(s):
                    why.append(f"harness source for {h} missing: {s}")
        if t.get("scan_mode") == "delta" and not (t.get("base_commit") and t.get("delta_commit")):
            why.append("delta task without base/delta commits")
        if why:
            problems.append((tag, why))
            continue

        t["budget_limit"] = budget
        t["concurrency"] = 1
        if timeout is not None:
            t["timeout_minutes"] = timeout
        t["task_id"] = str(ObjectId())
        dst = out / "tasks" / f"{tag}__{t['task_id']}.json"
        dst.write_text(json.dumps(t, indent=2))
        rows.append((tag, t["task_id"], t["scan_mode"], t["model_profile"],
                     t.get("pov_count", 1), t["timeout_minutes"], str(dst)))

    if problems:
        print("REFUSING TO PLAN -- fix these first:", file=sys.stderr)
        for tag, why in problems:
            for w in why:
                print(f"  {tag}: {w}", file=sys.stderr)
        return 2

    with open(out / "plan.tsv", "w") as fh:
        fh.write("tag\ttask_id\tscan_mode\tprofile\tpov_target\ttimeout_min\tconfig\n")
        for r in rows:
            fh.write("\t".join(str(x) for x in r) + "\n")

    total = sum(r[5] for r in rows)
    print(f"{'tag':48} {'mode':6} {'profile':15} {'pov':>3} {'min':>5}")
    for tag, tid, mode, prof, pov, mins, _ in rows:
        print(f"{tag:48} {mode:6} {prof:15} {pov:>3} {mins:>5}")
    print(f"\n{len(rows)} tasks, budget ${budget:g} each (max ${budget * len(rows):g}), "
          f"worst case {total} min = {total / 60:.1f} h if every run times out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
