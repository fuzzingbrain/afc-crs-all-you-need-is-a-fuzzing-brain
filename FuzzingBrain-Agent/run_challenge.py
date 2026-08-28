#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the agent against one FuzzingBrain-Bench challenge.

    ./run_challenge.py avro-03
    ./run_challenge.py avro-03 --allow-network --max-time 900 --model opus

End to end: stage the public challenge out of its image, start the judge, run
one omp session with four tools over it, then report whether anything crashed.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fbagent import runner, stage  # noqa: E402
from fbagent.judge import Judge  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("challenge", help="challenge alias, e.g. avro-03")
    ap.add_argument("--out", default=None, help="output directory (default: runs/<challenge>-<ts>)")
    ap.add_argument("--model", default=None, help="model for omp (default: omp's own)")
    ap.add_argument("--max-time", type=int, default=1800, help="agent wall clock, seconds")
    ap.add_argument("--allow-network", action="store_true",
                    help="let the agent's shell reach the network (off by default)")
    ap.add_argument("--no-pull", action="store_true", help="fail rather than pull the image")
    ap.add_argument("--keep", action="store_true", help="keep the workspace after the run")
    args = ap.parse_args()

    image = stage.image_for(args.challenge)
    out = Path(args.out or f"runs/{args.challenge}-{time.strftime('%Y%m%d-%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    workspace = out / "workspace"

    print(f"challenge   {args.challenge}")
    print(f"image       {image}")
    print(f"output      {out}")
    print(f"network     {'allowed' if args.allow_network else 'blocked'}")
    print(f"tools       {', '.join(runner.AGENT_TOOLS)}")

    try:
        stage.ensure_image(image, pull=not args.no_pull)
        spec = stage.stage(image, workspace)
    except stage.StagingError as exc:
        print(f"\nstaging failed: {exc}")
        return 2

    print(f"staged      {stage.describe(workspace)}")
    print(f"spec        {spec.get('project')} / {spec.get('language')} / "
          f"{spec.get('sanitizer')} / {spec.get('engine')}")

    judge = Judge(workspace, image)
    judge.start()
    runner.write_config(workspace, no_network=not args.allow_network)

    print("\nrunning the agent ...")
    try:
        result = runner.run(
            workspace,
            model=args.model,
            max_time=args.max_time,
            no_network=not args.allow_network,
            log_path=out / "agent.log",
        )
    except runner.OmpMissing as exc:
        judge.stop()
        print(f"\n{exc}")
        return 2
    except Exception as exc:  # noqa: BLE001 - report, do not lose the judge log
        result = {"returncode": -1, "seconds": 0, "error": str(exc)}
    finally:
        judge.stop()

    judge.write_report(out / "judge.json")
    crashes = judge.crashed

    summary = {
        "challenge": args.challenge,
        "image": image,
        "spec": spec,
        "network": "allowed" if args.allow_network else "blocked",
        "tools": list(runner.AGENT_TOOLS),
        "agent": result,
        "attempts": len(judge.log),
        "crashes": len(crashes),
        "solved": bool(crashes),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2))

    print(f"\nagent exited {result.get('returncode')} after {result.get('seconds')}s")
    print(f"candidates tried  {len(judge.log)}")
    for entry in judge.log[-8:]:
        print(f"  {entry['verdict']:9} {entry['size']:>7}B  {entry['detail'][:88]}")

    if crashes:
        print(f"\nSOLVED — {len(crashes)} crashing input(s)")
        print(f"  blobs kept in {workspace / '.judge' / 'blobs'}")
    else:
        print("\nnot solved — no candidate crashed the harness")

    if not args.keep and not crashes:
        shutil.rmtree(workspace / "src", ignore_errors=True)
        print(f"  (src/ removed to save space; pass --keep to retain it)")

    print(f"\nsummary  {out / 'summary.json'}")
    return 0 if crashes else 1


if __name__ == "__main__":
    raise SystemExit(main())
