from __future__ import annotations
import argparse
from multi_agent.leader import run_pipeline
from multi_agent.state import PatcherAgentState, PatchInput
import logging
from pathlib import Path
import sys

def main():
    # Configure logging to file and console
    base_dir = Path(__file__).resolve().parents[1]
    logs_dir = base_dir / "logs"
    logs_dir.mkdir(exist_ok=True)
    log_file = logs_dir / "multi_agent.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(),
        ],
    )
    p = argparse.ArgumentParser(description="Multi-agent patcher demo")
    p.add_argument("--project", required=True, help="e.g., zookeeper")
    p.add_argument("--benchmark-path", help="e.g., /home/qingxiao/patch_benchmark")
    p.add_argument("--log-file", help="Absolute or relative path to save logs for this run")
    p.add_argument("--model", help="Override model id (sets env LLM_MODEL)")
    args = p.parse_args()

    # Determine log destination (CLI overrides default)
    if args.log_file:
        try:
            chosen_log = Path(args.log_file)
            if not chosen_log.is_absolute():
                chosen_log = (Path.cwd() / chosen_log).resolve()
            chosen_log.parent.mkdir(parents=True, exist_ok=True)
            log_dest = chosen_log
        except Exception:
            log_dest = log_file
    else:
        log_dest = log_file

    # Reconfigure handlers to honor CLI --log-file
    for h in list(logging.getLogger().handlers):
        logging.getLogger().removeHandler(h)
    logging.getLogger().setLevel(logging.INFO)
    logging.getLogger().addHandler(logging.FileHandler(log_dest))
    logging.getLogger().addHandler(logging.StreamHandler())

    # Optional model override via environment for agents reading LLM_MODEL
    if getattr(args, "model", None):
        import os as _os
        _os.environ["LLM_MODEL"] = args.model

    init = PatcherAgentState(context=PatchInput(project=args.project, benchmark_path=args.benchmark_path))
    out = run_pipeline(init)

    print("=== PATCH ATTEMPTS ===")
    for i, pa in enumerate(out.patch_attempts, 1):
        print(f"[{i}] status={pa.status.value} desc={pa.description}")
        if pa.patch:
            print(pa.patch.diff)

    print("=== DERIVED PATHS ===")
    print(f"project_root: {out.project_root}")
    print(f"source_dir:   {out.source_dir}")
    print(f"pov_path:     {out.pov_path}")
    print(f"helper.py:    {out.helper_script_path}")
    print(f"diff_path:    {out.diff_path}")
    print(f"harness_script_path: {out.harness_script_path}")

if __name__ == "__main__":
    main()