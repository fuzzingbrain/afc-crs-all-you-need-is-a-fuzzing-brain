#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run one F(MS) baseline strategy against one artifact task.

  python3 FMS/run.py artifact/aixcc/cu-delta-02/tasks/curl_fuzzer_ws.json \
      --budget 30 --timeout 60 --out FMS/runs/<name>

Picks xs0_delta or xs1_c_full from the task's scan_mode. A background libFuzzer
(the legacy parallel path) fuzzes the prebuilt binary alongside the strategy,
consuming the seeds the strategy drops. The run stops when the task's pov_count
distinct bugs are found, or on budget / timeout -- the same stop rule ZBH used.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from FMS.substrate import BackgroundFuzzer, Budget, LLM, Task, bind_legacy  # noqa: E402
from FMS.strategies import run_delta, run_full, Run                         # noqa: E402


def _distinct(strategy_povs: list, fuzzer_povs: list) -> int:
    """Distinct bugs = union of crash sites from the strategy and the fuzzer."""
    sites = {p.get("site") for p in strategy_povs} | {p.get("site") for p in fuzzer_povs}
    sites.discard(None)
    return len(sites)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("task_json")
    ap.add_argument("--budget", type=float, default=30.0, help="dollars")
    ap.add_argument("--timeout", type=float, default=60.0, help="minutes")
    ap.add_argument("--out", default=None)
    ap.add_argument("--no-fuzzer", action="store_true", help="strategy only")
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

    deadline = time.time() + args.timeout * 60
    budget = Budget(dollars=args.budget, deadline=deadline)
    llm = LLM(budget, log)
    bind_legacy(llm, log)

    log(f"F(MS) {task.mode} {task.tid} fuzzer={task.fuzzer} "
        f"pov_target={task.pov_count} budget=${args.budget} timeout={args.timeout}min "
        f"bg_fuzzer={not args.no_fuzzer}")
    started = time.time()

    # Background fuzzer shares the strategy's corpus dir (out/corpus).
    bg = None
    if not args.no_fuzzer:
        bg = BackgroundFuzzer(task, out / "corpus", out, log)
        try:
            bg.start()
        except Exception as e:  # noqa: BLE001
            log(f"background fuzzer failed to start: {e}")
            bg = None

    strat_povs = []
    try:
        result = run_delta(task, llm, out, log) if task.mode == "delta" \
            else run_full(task, llm, out, log)
        strat_povs = result.get("povs", [])
    except Exception as e:  # noqa: BLE001
        import traceback
        log(f"ERROR: {e}\n{traceback.format_exc()}")
        result = {"error": str(e), "povs": []}

    # Keep the fuzzer running until the target is met or the clock/budget ends,
    # so F(MS) gets the same fuzzing time ZBH did.
    if bg is not None:
        target = task.pov_count + 1
        while (_distinct(strat_povs, bg.povs) < target
               and time.time() < deadline):
            time.sleep(15)
        bg.stop()

    fuzzer_povs = bg.povs if bg else []
    result.update({
        "task": task.tid, "fuzzer": task.fuzzer, "mode": task.mode,
        "minutes": round((time.time() - started) / 60, 1),
        "cost": round(budget.spent, 4), "llm_calls": budget.calls,
        "pov_target": task.pov_count + 1,
        "strategy_povs": len(strat_povs),
        "fuzzer_povs": len(fuzzer_povs),
        "distinct": _distinct(strat_povs, fuzzer_povs),
        "success": _distinct(strat_povs, fuzzer_povs) > 0,
        "fuzzer_pov_sites": [p.get("site") for p in fuzzer_povs],
    })
    (out / "result.json").write_text(json.dumps(result, indent=2))
    log(f"DONE distinct={result['distinct']}/{task.pov_count} "
        f"(strategy={result['strategy_povs']} fuzzer={result['fuzzer_povs']}) "
        f"cost=${result['cost']} {result['minutes']}min")
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
