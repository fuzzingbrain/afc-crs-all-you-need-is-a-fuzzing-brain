#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
# from datetime import datetime
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

# Simple orchestrator to run any of the three patch systems with one CLI,
# capture a common set of metrics, and optionally prune docker artifacts
# between runs to reduce OOM risk.


SYSTEM_CHOICES = ("multi-agent", "patch-delta", "patch-agent-tools")


def _now_iso() -> str:
    # return datetime.utcnow().isoformat() + "Z"
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _resolve_path(raw: str | None, fallback: Path) -> Path:
    if raw:
        p = Path(raw).expanduser()
        return p if p.is_absolute() else (Path.cwd() / p).resolve()
    return fallback


def _default_log_and_metrics(base_dir: Path, system: str, project: str) -> Tuple[Path, Path]:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    logs_dir = base_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir = base_dir / "logs" / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"{system}-{project}-{ts}.log"
    metrics_path = metrics_dir / f"{system}-{project}-{ts}.json"
    return log_path, metrics_path


def build_command(
    system: str,
    project: str,
    benchmark: str,
    model: str,
    log_file: Path,
    api_base: str | None,
    api_key: str | None,
) -> Tuple[List[str], Dict[str, str]]:
    python = sys.executable
    env = os.environ.copy()
    if api_base:
        env["OPENAI_BASE_URL"] = api_base
        env["OPENAI_API_BASE"] = api_base
    if api_key:
        env["OPENAI_API_KEY"] = api_key

    if system == "multi-agent":
        cmd = [
            python,
            "-m",
            "multi_agent",
            "--project",
            project,
            "--benchmark-path",
            benchmark,
            "--model",
            model,
            "--log-file",
            str(log_file),
        ]
        if api_base:
            cmd.extend(["--api-base", api_base])
        if api_key:
            cmd.extend(["--api-key", api_key])
    elif system == "patch-delta":
        cmd = [
            python,
            "-m",
            "patch_delta",
            "--project",
            project,
            "--benchmark-path",
            benchmark,
            "--model",
            model,
            "--log-file",
            str(log_file),
        ]
    elif system == "patch-agent-tools":
        script = (
            Path(__file__).resolve().parent
            / "patch-agent-tools"
            / "agents"
            / "patch_agent.py"
        )
        cmd = [
            python,
            str(script),
            "--project",
            project,
            "--benchmark-path",
            benchmark,
            "--model",
            model,
            "--log-file",
            str(log_file),
        ]
    else:
        raise ValueError(f"Unknown system {system}")

    return cmd, env


TOKEN_BLOCK = re.compile(r'"?token_usage"?\s*:\s*\{[^}]*\}', re.IGNORECASE | re.MULTILINE)
# New pattern for our custom TOKEN_USAGE log format
TOKEN_USAGE_LOG_RE = re.compile(r'TOKEN_USAGE\[([^\]]+)\]:\s*(\{[^}]*\})', re.IGNORECASE)
PROMPT_RE = re.compile(r'"?prompt_tokens"?\s*:\s*(\d+)', re.IGNORECASE)
COMPLETION_RE = re.compile(r'"?completion_tokens"?\s*:\s*(\d+)', re.IGNORECASE)
TOTAL_RE = re.compile(r'"?total_tokens"?\s*:\s*(\d+)', re.IGNORECASE)
MODEL_RE = re.compile(r'"?model[_ ]?name"?\s*[:=]\s*"([^"]+)"', re.IGNORECASE)
TOOL_LINE_RE = re.compile(r"tool_calls", re.IGNORECASE)
TOOL_NAME_JSON_RE = re.compile(r'"name"\s*:\s*"([A-Za-z0-9_\-]+)"')
TOOL_NAME_PY_RE = re.compile(r"'name'\s*:\s*'([A-Za-z0-9_\-]+)'")


def parse_log_metrics(log_path: Path) -> Dict[str, object]:
    stats = {
        "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "calls": 0},
        "api_calls": {"count": 0, "models": []},
        "tool_usage": {"total_tool_calls": 0, "by_name": {}},
    }
    if not log_path.exists():
        return stats

    data = log_path.read_text(errors="ignore")

    models = set()
    for m in MODEL_RE.finditer(data):
        models.add(m.group(1))
    stats["api_calls"]["models"] = sorted(models)

    prompt_sum = completion_sum = total_sum = 0
    api_call_count = 0
    
    # Method 1: Parse our custom TOKEN_USAGE log format
    for match in TOKEN_USAGE_LOG_RE.finditer(data):
        context = match.group(1)  # e.g., "CTX", "SWE", "REFLECTION"
        usage_json = match.group(2)
        try:
            usage_data = json.loads(usage_json)
            prompt_sum += int(usage_data.get("prompt_tokens", 0))
            completion_sum += int(usage_data.get("completion_tokens", 0))
            total_sum += int(usage_data.get("total_tokens", 0))
            api_call_count += 1
        except (json.JSONDecodeError, ValueError, KeyError):
            pass
    
    # Method 2: Look for standard token_usage blocks (fallback)
    if api_call_count == 0:
        for block in TOKEN_BLOCK.finditer(data):
            txt = block.group(0)
            p = PROMPT_RE.search(txt)
            c = COMPLETION_RE.search(txt)
            t = TOTAL_RE.search(txt)
            if p:
                prompt_sum += int(p.group(1))
            if c:
                completion_sum += int(c.group(1))
            if t:
                total_sum += int(t.group(1))
            api_call_count += 1
    
    if total_sum == 0 and prompt_sum + completion_sum > 0:
        total_sum = prompt_sum + completion_sum
    
    stats["token_usage"]["prompt_tokens"] = prompt_sum
    stats["token_usage"]["completion_tokens"] = completion_sum
    stats["token_usage"]["total_tokens"] = total_sum
    stats["token_usage"]["calls"] = api_call_count
    stats["api_calls"]["count"] = max(api_call_count, len(models))

    tool_counts: Counter[str] = Counter()
    for line in data.splitlines():
        if not TOOL_LINE_RE.search(line):
            continue
        for name in TOOL_NAME_JSON_RE.findall(line):
            tool_counts[name] += 1
        for name in TOOL_NAME_PY_RE.findall(line):
            tool_counts[name] += 1
    stats["tool_usage"]["total_tool_calls"] = sum(tool_counts.values())
    stats["tool_usage"]["by_name"] = dict(tool_counts.most_common())
    return stats


def stream_process(cmd: List[str], env: Dict[str, str], log_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as logf:
        logf.write(f"[runner] command: {' '.join(cmd)}\n")
        logf.flush()
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout
        for line in proc.stdout:
            sys.stdout.write(line)
            logf.write(line)
        proc.wait()
        return proc.returncode


def maybe_prune(enable: bool) -> None:
    if not enable:
        return
    docker = shutil.which("docker")
    if not docker:
        print("[runner] docker not found; skipping system prune")
        return
    print("[runner] running docker system prune -af to reclaim space")
    subprocess.run([docker, "system", "prune", "-af"], check=False)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Unified runner for patch agents with metrics collection",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--system", choices=SYSTEM_CHOICES, required=True, help="Which patch system to run")
    parser.add_argument("--project", required=True, help="Patch task / project name, e.g. commons-compress")
    parser.add_argument("--benchmark-path", required=True, help="Benchmark root path")
    parser.add_argument("--model", required=True, help="LLM model identifier")
    parser.add_argument("--api-base", help="Optional OpenAI-compatible base URL")
    parser.add_argument("--api-key", help="API key for the configured endpoint")
    parser.add_argument("--log-file", help="Path to append raw run logs")
    parser.add_argument("--metrics-file", help="Where to store parsed metrics JSON")
    parser.add_argument("--no-prune", action="store_true", help="Skip docker system prune after run")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    default_log, default_metrics = _default_log_and_metrics(base_dir, args.system, args.project)
    log_path = _resolve_path(args.log_file, default_log)
    metrics_path = _resolve_path(args.metrics_file, default_metrics)

    cmd, env = build_command(
        system=args.system,
        project=args.project,
        benchmark=str(Path(args.benchmark_path).expanduser().resolve()),
        model=args.model,
        log_file=log_path,
        api_base=args.api_base,
        api_key=args.api_key,
    )

    start = time.time()
    start_iso = _now_iso()
    rc = stream_process(cmd, env, log_path)
    end_iso = _now_iso()
    duration = time.time() - start

    maybe_prune(not args.no_prune)

    metrics = {
        "system": args.system,
        "project": args.project,
        "benchmark_path": str(Path(args.benchmark_path).expanduser().resolve()),
        "model": args.model,
        "api_base": args.api_base,
        "log_file": str(log_path),
        "command": cmd,
        "start_time": start_iso,
        "end_time": end_iso,
        "duration_sec": duration,
        "exit_code": rc,
        "stats": parse_log_metrics(log_path),
    }

    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print("\n[runner] complete")
    print(json.dumps(metrics, indent=2))
    if rc != 0:
        sys.exit(rc)


if __name__ == "__main__":
    main()

