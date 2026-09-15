#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Follow a running fbagent cell. One line per step, as it happens.

    tools/watch.py                 # follow the newest run
    tools/watch.py <file.jsonl>    # follow a specific one
    tools/watch.py --once          # print what is there and exit

Columns: elapsed, step, spend, baseline state, distinct faults, then the tools
called and any graded verdict. A run that is spraying shows `clean: ... 0 ms`
over and over with faults stuck at 0 -- which is the thing you want to see two
minutes in, not thirty.
"""
import json, os, sys, time
from pathlib import Path

def newest() -> Path | None:
    home = Path(os.environ.get("FBAGENT_HOME") or (Path.home() / ".fbagent"))
    files = sorted((home / "progress").glob("*.jsonl"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None

def render(rec: dict) -> str:
    k = rec.get("kind")
    t = f"{rec.get('t', 0):7.1f}s"
    if k == "start":
        return (f"{t}  START  {rec.get('model')}  max_usd={rec.get('max_usd')} "
                f"min_spend_frac={rec.get('min_spend_frac')} timeout={rec.get('timeout_s')}s")
    if k == "end":
        return (f"{t}  END    {rec.get('stop_reason')}  steps={rec.get('steps')} "
                f"${rec.get('usd')}")
    if k != "step":
        return f"{t}  {k}  {json.dumps({x: y for x, y in rec.items() if x not in ('t','kind')})}"
    tools = ",".join(rec.get("tools") or []) or "-"
    v = rec.get("verdicts") or []
    line = f"{t}  #{rec.get('n'):<4} ${rec.get('usd'):<7.3f}  {tools}"
    for x in v:
        line += f"\n{'':>9}    | {x}"
    return line

def main() -> int:
    once = "--once" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    path = Path(args[0]) if args else newest()
    if not path or not path.exists():
        print("no progress file found (is the agent running with FBAGENT_PROGRESS enabled?)",
              file=sys.stderr)
        return 1
    print(f"# {path}", file=sys.stderr)
    with path.open() as f:
        while True:
            line = f.readline()
            if not line:
                if once:
                    return 0
                time.sleep(0.4)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                print(render(json.loads(line)), flush=True)
            except Exception:
                print(line, flush=True)

if __name__ == "__main__":
    sys.exit(main())
