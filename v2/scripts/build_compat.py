#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""OSS-Fuzz build-compatibility harness.

Attempts to build a list of OSS-Fuzz projects exactly the way the v2 pipeline
does — ``helper.py build_image`` then ``helper.py build_fuzzers`` — and records
which projects build, which fail, and why. Resumable and self-contained: it
only needs an OSS-Fuzz checkout and Docker (no v2 runtime deps).

Usage:
    python3 build_compat.py --oss-fuzz-dir /path/to/oss-fuzz \\
        --projects libpng,libyaml,expat --output report.json

    python3 build_compat.py --projects-file projects.txt --sanitizer address \\
        --timeout 1800 --output report.json --resume

The report (JSON) is written incrementally after every project so a long run
can be interrupted and resumed. A markdown summary is written next to it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# Ordered failure classifiers: (label, regex). First match wins.
FAILURE_PATTERNS = [
    ("missing_source_file", r"No such file or directory"),
    ("build_fuzzers_failed", r"Building fuzzers failed"),
    ("compiler_error", r"\berror:\s"),
    ("undefined_reference", r"undefined reference"),
    (
        "docker_pull_failed",
        r"(manifest unknown|pull access denied|not found: manifest)",
    ),
    ("docker_error", r"(docker:|Cannot connect to the Docker daemon)"),
    ("checkout_missing", r"(does not exist|is not a directory)"),
    ("timeout", r"__HARNESS_TIMEOUT__"),
]


def classify_failure(output: str) -> str:
    for label, pattern in FAILURE_PATTERNS:
        if re.search(pattern, output, re.IGNORECASE):
            return label
    return "unknown"


def run_step(helper: Path, args: list[str], timeout: int) -> tuple[bool, str, float]:
    """Run one helper.py step; return (ok, tail_of_output, seconds)."""
    cmd = [sys.executable, str(helper), *args]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            env=env,
        )
        elapsed = time.time() - start
        tail = "\n".join(proc.stdout.splitlines()[-40:])
        return proc.returncode == 0, tail, elapsed
    except subprocess.TimeoutExpired as exc:
        elapsed = time.time() - start
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", "replace")
        tail = "\n".join(partial.splitlines()[-30:]) + "\n__HARNESS_TIMEOUT__"
        return False, tail, elapsed


def build_one(helper: Path, project: str, sanitizer: str, timeout: int) -> dict:
    """build_image then build_fuzzers; return a result record."""
    record: dict = {"project": project, "sanitizer": sanitizer}

    ok, out, secs = run_step(helper, ["build_image", "--pull", project], timeout)
    record["image_seconds"] = round(secs, 1)
    if not ok:
        record.update(
            success=False, stage="build_image", reason=classify_failure(out), tail=out
        )
        return record

    ok, out, secs = run_step(
        helper,
        ["build_fuzzers", "--sanitizer", sanitizer, "--engine", "libfuzzer", project],
        timeout,
    )
    record["fuzzers_seconds"] = round(secs, 1)
    if not ok:
        record.update(
            success=False, stage="build_fuzzers", reason=classify_failure(out), tail=out
        )
        return record

    record.update(success=True, stage="done", reason="ok", tail="")
    return record


def load_done(output: Path) -> dict[str, dict]:
    if not output.exists():
        return {}
    try:
        data = json.loads(output.read_text())
        return {r["project"]: r for r in data.get("results", [])}
    except (json.JSONDecodeError, KeyError):
        return {}


def write_report(output: Path, results: list[dict]) -> None:
    total = len(results)
    ok = sum(1 for r in results if r.get("success"))
    summary = {
        "total": total,
        "succeeded": ok,
        "failed": total - ok,
        "success_rate": round(ok / total, 3) if total else 0.0,
    }
    output.write_text(json.dumps({"summary": summary, "results": results}, indent=2))
    _write_markdown(output.with_suffix(".md"), summary, results)


def _write_markdown(path: Path, summary: dict, results: list[dict]) -> None:
    lines = [
        "# OSS-Fuzz build-compatibility report",
        "",
        f"- Projects: **{summary['total']}**",
        f"- Succeeded: **{summary['succeeded']}**",
        f"- Failed: **{summary['failed']}**",
        f"- Success rate: **{summary['success_rate'] * 100:.1f}%**",
        "",
        "## Failures by reason",
        "",
    ]
    reasons: dict[str, int] = {}
    for r in results:
        if not r.get("success"):
            reasons[r.get("reason", "unknown")] = (
                reasons.get(r.get("reason", "unknown"), 0) + 1
            )
    for reason, n in sorted(reasons.items(), key=lambda x: -x[1]):
        lines.append(f"- `{reason}`: {n}")
    lines += [
        "",
        "## Per project",
        "",
        "| project | result | stage | reason |",
        "|---|---|---|---|",
    ]
    for r in results:
        mark = "✅" if r.get("success") else "❌"
        lines.append(
            f"| {r['project']} | {mark} | {r.get('stage', '')} | {r.get('reason', '')} |"
        )
    path.write_text("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--oss-fuzz-dir",
        default=os.environ.get("OSS_FUZZ_DIR", "/data4/ze/oss-fuzz"),
        help="Path to an OSS-Fuzz checkout (contains infra/helper.py)",
    )
    parser.add_argument("--projects", help="Comma-separated project names")
    parser.add_argument("--projects-file", help="File with one project per line")
    parser.add_argument("--sanitizer", default="address")
    parser.add_argument(
        "--timeout", type=int, default=1800, help="Per-step timeout (s)"
    )
    parser.add_argument("--output", default="build_compat_report.json")
    parser.add_argument(
        "--resume", action="store_true", help="Skip already-recorded projects"
    )
    args = parser.parse_args(argv)

    helper = Path(args.oss_fuzz_dir) / "infra" / "helper.py"
    if not helper.exists():
        print(f"helper.py not found: {helper}", file=sys.stderr)
        return 2

    projects: list[str] = []
    if args.projects:
        projects += [p.strip() for p in args.projects.split(",") if p.strip()]
    if args.projects_file:
        projects += [
            ln.strip()
            for ln in Path(args.projects_file).read_text().splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
    if not projects:
        print("No projects given (use --projects or --projects-file)", file=sys.stderr)
        return 2

    output = Path(args.output)
    done = load_done(output) if args.resume else {}
    results = list(done.values())

    for project in projects:
        if project in done:
            print(f"[skip] {project} (already recorded)")
            continue
        print(f"[build] {project} ...", flush=True)
        record = build_one(helper, project, args.sanitizer, args.timeout)
        results.append(record)
        done[project] = record
        write_report(output, results)  # incremental: resumable
        status = "OK" if record["success"] else f"FAIL ({record['reason']})"
        print(f"[done] {project}: {status}")

    ok = sum(1 for r in results if r.get("success"))
    print(f"\n=== {ok}/{len(results)} built. Report: {output} (+ .md) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
