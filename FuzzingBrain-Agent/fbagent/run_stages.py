# SPDX-License-Identifier: Apache-2.0
"""Entry point for the three-stage pipeline: discovery -> verification ->
reproduction, over a HypothesisPool, driven by the code controller.

    python3 -m fbagent.run_stages --timeout 900 --model claude-opus-5 --max-usd 20

Started by the bench (or a person) in the staged challenge directory, where
`./submit`, the trace bridge, and bench.yaml already exist. Unlike run.py (the
single-loop agent), this runs the multi-stage controller. It writes the same
records run.py does so the bench can read them: .fbbench/usage.json for cost,
and .fb/ holds the VulnHypothesis board, candidates, and per-stage sessions.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from fbagent import controller
from fbagent.llm import LLM
from fbagent.plan import RunPlan, default_plan


def _write_usage(ws: Path, llm: LLM, summary: dict) -> None:
    """.fbbench/usage.json — the bench's external arm reads this to cost a
    black-box agent (same field names as run.py's summary)."""
    try:
        d = ws / ".fbbench"
        d.mkdir(parents=True, exist_ok=True)
        (d / "usage.json").write_text(json.dumps({
            "usage": dict(llm.usage), "cost_usd": round(llm.cost_usd, 4),
            "model": llm.model, "served_model": llm.served_model,
            "solved": summary.get("solved"), "signatures": summary.get("signatures"),
        }))
    except Exception as e:  # never fail the run over bookkeeping
        print(f"[run_stages] usage write skipped: {e}", file=sys.stderr)


def _read_bench_bug(ws: Path) -> str:
    """The bug id from bench.yaml, for naming the run; '' if unknown."""
    f = ws / "bench.yaml"
    if not f.is_file():
        return ""
    try:
        import yaml
        return str((yaml.safe_load(f.read_text()) or {}).get("bug_id", "") or "")
    except Exception:  # noqa: BLE001
        return ""


def _load_or_default_plan(args, ws: Path, llm: LLM) -> RunPlan:
    if args.plan:
        import json as _json
        plan = RunPlan.from_dict(_json.loads(Path(args.plan).read_text()))
        # a plan without a model uses the CLI/default model
        if not plan.model:
            plan.model = llm.model
        return plan
    harness, sanitizer = controller._read_bench(ws)
    return default_plan(bug=_read_bench_bug(ws), harness=harness, sanitizer=sanitizer,
                        model=llm.model, total_usd=args.max_usd, timeout_s=args.timeout)


def _save_plan(ws: Path, plan: RunPlan) -> None:
    """The plan that actually ran, beside the pool -- part of the run's record."""
    try:
        d = ws / ".fb"
        d.mkdir(parents=True, exist_ok=True)
        (d / "plan.json").write_text(plan.to_json())
    except Exception as e:  # noqa: BLE001 — bookkeeping never fails a run
        print(f"[run_stages] plan write skipped: {e}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=int, default=900, help="wall clock, seconds")
    ap.add_argument("--max-usd", type=float,
                    default=float(os.environ.get("FBAGENT_MAX_USD", "0") or 0),
                    help="global spend cap in USD across all stages (env: FBAGENT_MAX_USD)")
    ap.add_argument("--model", default=None)
    ap.add_argument("--discovery-frac", type=float, default=None,
                    help="override the plan's discovery budget fraction")
    ap.add_argument("--plan", default=None,
                    help="path to a run plan JSON; default: a heuristic plan from bench.yaml")
    args = ap.parse_args()

    llm = LLM(model=args.model) if args.model else LLM()
    ws = Path.cwd()

    # The run plan is the declarative interface (docs/ORCHESTRATION_plan_json.md):
    # who writes it (a heuristic today, an orchestration agent later) is separate
    # from executing it. Load --plan if given, else author a default from
    # bench.yaml; then let CLI flags override the top-level budget knobs.
    plan = _load_or_default_plan(args, ws, llm)
    if args.discovery_frac is not None:
        plan.budget.split["discovery"] = args.discovery_frac
    _save_plan(ws, plan)
    print(f"[run_stages] model={llm.model} provider={llm.provider} "
          f"max_usd={plan.budget.total_usd} timeout_s={plan.budget.timeout_s} "
          f"run_id={plan.run_id} split={plan.budget.split}", flush=True)

    summary = controller.run_task(
        llm=llm, workspace=str(ws), max_usd=plan.budget.total_usd,
        deadline_s=plan.budget.timeout_s, discovery_frac=plan.discovery_frac(),
        verify_gate=plan.knobs.verify_gate, max_attempts=plan.knobs.max_attempts,
        max_discovery_rounds=plan.knobs.max_discovery_rounds)
    _write_usage(ws, llm, summary)

    if llm.served_model and llm.model.split("-2")[0] not in (llm.served_model or ""):
        print(f"[run_stages] WARNING: requested {llm.model} but API served "
              f"{llm.served_model}", file=sys.stderr)
    print("\n" + "=" * 60)
    # the per-stage log can be long; print the headline + one line per stage
    head = {k: summary[k] for k in ("harness", "sanitizer", "hypotheses", "solved",
                                    "signatures", "cost_usd", "stop")}
    print(json.dumps(head, indent=2))
    for e in summary.get("log", []):
        print(f"  {e.get('stage'):10} " + json.dumps({k: v for k, v in e.items()
              if k not in ('stage', 'log')})[:200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
