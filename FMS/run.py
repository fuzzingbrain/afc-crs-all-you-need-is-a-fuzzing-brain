#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run one F(MS) baseline strategy against one artifact task.

  python3 FMS/run.py artifact/aixcc/cu-delta-02/tasks/curl_fuzzer_ws.json \
      --budget 30 --timeout 60 --out FMS/runs/<name>

Picks xs0_delta or xs1_c_full from the task's scan_mode. Budget in dollars,
timeout in minutes (the legacy 45-min wall clock is replaced by this deadline).
Writes successful_povs/ and result.json under --out.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from FMS.substrate import Budget, LLM, Task, bind_legacy  # noqa: E402
from FMS.strategies import run_delta, run_full            # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("task_json")
    ap.add_argument("--budget", type=float, default=30.0, help="dollars")
    ap.add_argument("--timeout", type=float, default=60.0, help="minutes")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    task = Task.load(args.task_json)
    out = Path(args.out) if args.out else (
        Path(__file__).resolve().parent / "runs" /
        f"{task.tid}_{task.fuzzer}_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    logf = open(out / "run.log", "a")

    def log(msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        print(line, flush=True)
        logf.write(line + "\n")
        logf.flush()

    budget = Budget(dollars=args.budget, deadline=time.time() + args.timeout * 60)
    llm = LLM(budget, log)
    bind_legacy(llm, log)

    log(f"F(MS) {task.mode} {task.tid} fuzzer={task.fuzzer} "
        f"budget=${args.budget} timeout={args.timeout}min")
    started = time.time()
    try:
        result = run_delta(task, llm, out, log) if task.mode == "delta" \
            else run_full(task, llm, out, log)
    except Exception as e:  # noqa: BLE001
        import traceback
        log(f"ERROR: {e}\n{traceback.format_exc()}")
        result = {"error": str(e)}

    result.update({
        "task": task.tid, "fuzzer": task.fuzzer, "mode": task.mode,
        "minutes": round((time.time() - started) / 60, 1),
        "cost": round(budget.spent, 4), "llm_calls": budget.calls,
        "n_povs": len(result.get("povs", [])),
        "success": bool(result.get("povs")),
    })
    (out / "result.json").write_text(json.dumps(result, indent=2))
    log(f"DONE success={result['success']} povs={result['n_povs']} "
        f"cost=${result['cost']} {result['minutes']}min")
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
