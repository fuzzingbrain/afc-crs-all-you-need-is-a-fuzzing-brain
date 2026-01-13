from __future__ import annotations
import argparse
import json
import re
import time
from datetime import datetime
from multi_agent.leader import run_pipeline
from multi_agent.state import PatcherAgentState, PatchInput
import logging
from pathlib import Path
import os

logger = logging.getLogger(__name__)
TOKEN_USAGE_LOG_RE = re.compile(r'TOKEN_USAGE\[([^\]]+)\]:\s*(\{[^}]+\})', re.IGNORECASE)


def _print_usage_summary(log_path: Path, duration: float) -> None:
    """Parse log file for token usage and print summary."""
    if not log_path.exists():
        return
    
    try:
        data = log_path.read_text(errors="ignore")
    except Exception:
        return
    
    prompt_sum = completion_sum = total_sum = 0
    api_call_count = 0
    usage_by_context = {}
    
    # Parse TOKEN_USAGE log entries
    for match in TOKEN_USAGE_LOG_RE.finditer(data):
        context = match.group(1)
        usage_json = match.group(2)
        try:
            usage_data = json.loads(usage_json)
            prompt = int(usage_data.get("prompt_tokens", 0))
            completion = int(usage_data.get("completion_tokens", 0))
            total = int(usage_data.get("total_tokens", 0))
            
            prompt_sum += prompt
            completion_sum += completion
            total_sum += total
            api_call_count += 1
            
            # Track usage by context
            if context not in usage_by_context:
                usage_by_context[context] = {"prompt": 0, "completion": 0, "total": 0, "calls": 0}
            usage_by_context[context]["prompt"] += prompt
            usage_by_context[context]["completion"] += completion
            usage_by_context[context]["total"] += total
            usage_by_context[context]["calls"] += 1
        except (json.JSONDecodeError, ValueError, KeyError):
            pass
    
    # Print summary (always show duration, even if no tokens)
    print("\n" + "="*60)
    print("USAGE SUMMARY")
    print("="*60)
    print(f"Duration:            {duration:.1f}s ({duration/60:.1f} minutes)")
    
    if total_sum == 0:
        print("No token usage data found in logs.")
        logger.info("="*60)
        logger.info("USAGE SUMMARY")
        logger.info(f"Duration: {duration:.1f}s")
        logger.info("No token usage data found in logs.")
        logger.info("="*60)
        # Force flush to ensure it's written to file
        for handler in logging.getLogger().handlers:
            if isinstance(handler, logging.FileHandler):
                handler.flush()
        return
    
    print(f"API Calls:           {api_call_count}")
    print(f"Total Tokens:        {total_sum:,}")
    print(f"  - Prompt:          {prompt_sum:,}")
    print(f"  - Completion:     {completion_sum:,}")
    
    if usage_by_context:
        print(f"\nUsage by Context:")
        for context, stats in sorted(usage_by_context.items()):
            print(f"  {context:15s}: {stats['total']:>8,} tokens ({stats['calls']:>3} calls)")
            print(f"    {'':15s}  Prompt: {stats['prompt']:>8,}, Completion: {stats['completion']:>8,}")
    
    print("="*60)
    
    # Also log to file
    logger.info("="*60)
    logger.info("USAGE SUMMARY")
    logger.info(f"Duration: {duration:.1f}s, API Calls: {api_call_count}")
    logger.info(f"Tokens: {total_sum:,} (Prompt: {prompt_sum:,}, Completion: {completion_sum:,})")
    logger.info("="*60)
    # Force flush to ensure it's written to file
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.FileHandler):
            handler.flush()


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
    p.add_argument(
        "--model",
        help=(
            "Override model id for all LLM calls (sets env LLM_MODEL, "
            "e.g. gpt-4o, gpt-4.1-mini, claude-3.7-sonnet)"
        ),
    )
    p.add_argument(
        "--temperature",
        type=float,
        help="Override temperature for all LLM calls (sets env LLM_TEMPERATURE)",
    )
    p.add_argument(
        "--api-base",
        help=(
            "Optional OpenAI-compatible base URL for all LLM calls "
            "(sets env OPENAI_BASE_URL and OPENAI_API_BASE, "
            "e.g. http://localhost:8080/v1 for a LiteLLM proxy)"
        ),
    )
    p.add_argument(
        "--api-key",
        help=(
            "Optional API key for the OpenAI-compatible endpoint "
            "(sets env OPENAI_API_KEY; use your proxy key when pointing at LiteLLM)"
        ),
    )
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

    # Optional model / temperature override via environment for all agents
    if getattr(args, "model", None):
        os.environ["LLM_MODEL"] = args.model
    if getattr(args, "temperature", None) is not None:
        os.environ["LLM_TEMPERATURE"] = str(args.temperature)
    if getattr(args, "api_base", None):
        # Support both legacy and new env var names used by OpenAI clients
        os.environ["OPENAI_BASE_URL"] = args.api_base
        os.environ["OPENAI_API_BASE"] = args.api_base
    if getattr(args, "api_key", None):
        os.environ["OPENAI_API_KEY"] = args.api_key

    start_time = time.time()
    init = PatcherAgentState(context=PatchInput(project=args.project, benchmark_path=args.benchmark_path))
    out = run_pipeline(init)
    duration = time.time() - start_time

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
    
    # Print usage summary
    _print_usage_summary(log_dest, duration)

if __name__ == "__main__":
    main()