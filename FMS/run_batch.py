#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the F(MS) baseline over a CPV list, N tasks in parallel.

  python3 FMS/run_batch.py artifact/batches/fms_all.txt --parallel 2 --out FMS/runs/fms_all_run1

Each unique task JSON (CPVs sharing a harness run once) is launched with the
paper budgets: delta 60 min / $30, full 120 min / $100. Results land in
<out>/<cpv>/result.json; a running results.tsv is appended as tasks finish.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = str(ROOT / "venv" / "bin" / "python3")
IDX = {e["cpv"]: e for e in json.load(open(ROOT / "artifact/aixcc/index.json"))}
EXCLUDE = {"av2-del-02", "sd1-fu-05", "cm1-fu-01", "cm1-fu-02"}
DELTA = (60, 30.0)   # minutes, dollars
FULL = (120, 100.0)
MARGIN_MIN = 20      # hard-kill this long after the task's own timeout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("list")
    ap.add_argument("--parallel", type=int, default=2)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    tsv = out / "results.tsv"
    if not tsv.exists():
        tsv.write_text("cpv\ttask\tmode\tsuccess\tdistinct\tstrategy\tfuzzer\t"
                       "cost\tminutes\tsites\n")
    blog = out / "batch.log"

    def log(msg: str) -> None:
        line = f"[{time.strftime('%F %T')}] {msg}"
        print(line, flush=True)
        with open(blog, "a") as f:
            f.write(line + "\n")

    cpvs = [l.strip() for l in open(args.list)
            if l.strip() and not l.startswith("#") and l.strip() not in EXCLUDE]
    # One job per unique task JSON (ss's 5 CPVs share json_fuzz -> one run).
    jobs, seen = [], set()
    for cpv in cpvs:
        e = IDX[cpv]
        if e["task"] in seen:
            continue
        seen.add(e["task"])
        jobs.append((cpv, e))

    done = {l.split("\t")[0] for l in tsv.read_text().splitlines()[1:]}
    jobs = [(c, e) for c, e in jobs if c not in done]
    log(f"F(MS) batch: {len(jobs)} tasks, parallel={args.parallel}, out={out}")

    def run_one(cpv: str, e: dict) -> str:
        mins, budget = FULL if e["mode"] == "full" else DELTA
        rdir = out / cpv
        cmd = [PY, str(ROOT / "FMS/run.py"), str(ROOT / e["task"]),
               "--budget", str(budget), "--timeout", str(mins), "--out", str(rdir)]
        hard = int((mins + MARGIN_MIN) * 60)
        log(f"start {cpv} ({e['mode']}, {mins}min/${budget})")
        t0 = time.time()
        rc = subprocess.run(["timeout", "-k", "60", str(hard), *cmd],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        r = {}
        try:
            r = json.load(open(rdir / "result.json"))
        except Exception:  # noqa: BLE001
            pass
        row = "\t".join(str(x) for x in [
            cpv, e["task"].split("/")[1], e["mode"], r.get("success", False),
            r.get("distinct", 0), r.get("strategy_povs", 0), r.get("fuzzer_povs", 0),
            f"{r.get('cost', 0):.4f}", r.get("minutes", round((time.time()-t0)/60, 1)),
            ";".join(r.get("fuzzer_pov_sites", []) or [])])
        with open(tsv, "a") as f:
            f.write(row + "\n")
        log(f"done  {cpv}  rc={rc}  success={r.get('success')} "
            f"distinct={r.get('distinct', 0)} cost=${r.get('cost', 0):.2f} "
            f"{r.get('minutes', '?')}min")
        return cpv

    with ThreadPoolExecutor(max_workers=args.parallel) as ex:
        futs = {ex.submit(run_one, c, e): c for c, e in jobs}
        for fut in as_completed(futs):
            fut.result()
    log("batch finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
