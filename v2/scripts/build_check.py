#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify that bench targets BUILD — in parallel, each in its own workspace.

The build-only complement to run_bench.py: no fuzzing, no grading. Materializes a
fresh isolated workspace per bug and runs the OSS-Fuzz build through the shared
builder engine, ``--max-workers`` at a time, then reports which targets produced
a fuzzer. Fast regression coverage that all N targets still build end-to-end.

Examples:
  python scripts/build_check.py --langs c,c++ --max-workers 4
  python scripts/build_check.py --bugs skia-raster8888-blur-oob,systemd-hwdb-trie-oob-read
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

V2_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(V2_DIR))

import yaml  # noqa: E402

from fuzzingbrain.importers.bench import _LANG_MAP  # noqa: E402
from fuzzingbrain.builder.orchestrator import build_bugs  # noqa: E402

DEFAULT_BENCH = "/data4/ze/FuzzingBrain-Bench"
DEFAULT_OSS_FUZZ = "/data4/ze/oss-fuzz"


def discover(bench_dir: Path, langs: set[str] | None,
             only_ids: set[str] | None) -> list[tuple[str, Path]]:
    """[(bug_id, bug_dir)] under bench_dir/bugs, filtered by language / id."""
    out: list[tuple[str, Path]] = []
    for yml in sorted((Path(bench_dir) / "bugs").glob("*/*/bench.yaml")):
        meta = yaml.safe_load(yml.read_text())
        bug_id = meta.get("bug_id", yml.parent.name)
        if only_ids and bug_id not in only_ids:
            continue
        raw = str(meta.get("target", {}).get("language", "")).lower()
        lang = _LANG_MAP.get(raw, raw)  # cpp -> c++ to match --langs
        if langs and lang not in langs:
            continue
        out.append((bug_id, yml.parent))
    return out


def _force_rmtree(path: Path) -> None:
    """Remove a workspace, including root-owned files docker leaves behind."""
    if not path.exists():
        return
    shutil.rmtree(path, ignore_errors=True)
    if path.exists():  # root-owned leftovers
        subprocess.run(["docker", "run", "--rm", "-v", f"{path.parent}:/wd",
                        "alpine", "rm", "-rf", f"/wd/{path.name}"],
                       check=False, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bench", default=DEFAULT_BENCH)
    ap.add_argument("--oss-fuzz", default=DEFAULT_OSS_FUZZ)
    ap.add_argument("--workdir", default="/tmp/fbbench-buildcheck")
    ap.add_argument("--bugs", default="", help="comma bug_ids (default: all)")
    ap.add_argument("--langs", default="", help="comma languages to include")
    ap.add_argument("--sanitizer", default="address")
    ap.add_argument("--max-workers", type=int, default=4,
                    help="concurrent builds (each its own workspace)")
    ap.add_argument("--keep", action="store_true",
                    help="keep workspaces (default: delete after building)")
    args = ap.parse_args(argv)

    langs = {x.strip() for x in args.langs.split(",") if x.strip()} or None
    only = {x.strip() for x in args.bugs.split(",") if x.strip()} or None
    bugs = discover(Path(args.bench), langs, only)
    if not bugs:
        print("no bugs matched", file=sys.stderr)
        return 2

    root = Path(args.workdir)
    root.mkdir(parents=True, exist_ok=True)
    print(f"building {len(bugs)} target(s), {args.max_workers} at a time "
          f"({args.sanitizer}) ...\n")

    done = [0]

    def _report(r) -> None:
        done[0] += 1
        mark = "ok  " if r.ok else "FAIL"
        detail = f"{r.fuzzer_count} fuzzer(s)" if r.ok else r.message
        name = r.label or r.project
        print(f"[{done[0]:>2}/{len(bugs)}] {mark} {name:42s} {detail} "
              f"({r.duration_s:.0f}s)")
        if not args.keep:
            _force_rmtree(root / (r.label or r.project))

    start = time.monotonic()
    results = build_bugs(
        [d for _, d in bugs], root, args.oss_fuzz,
        sanitizer=args.sanitizer, max_workers=args.max_workers,
        on_result=_report,
    )

    built = [r for r in results if r.ok]
    failed = [r for r in results if not r.ok]
    print(f"\n=== {len(built)}/{len(results)} built "
          f"in {time.monotonic() - start:.0f}s ===")
    for r in failed:
        print(f"  FAIL {r.label or r.project}: {r.message}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
