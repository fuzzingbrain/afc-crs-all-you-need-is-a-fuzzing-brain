#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run V2 across FuzzingBrain-Bench bugs and grade the results.

Per bug, end to end:

  1. spec_from_bench_bug(bug)          -> HarnessSpec
  2. build_workspace(spec)             -> fresh, isolated V2 workspace
  3. FuzzingBrain.sh <ws> --task-type pov --pov-count 1 --budget B --timeout T
  4. locate V2's POV blob(s), grade each via `fb-bench grade <bug> <blob>`
  5. append a result record (JSON lines) and refresh the scorecard

Enterprise properties: a fresh workspace per bug, resumable (bugs already in the
report are skipped), bounded (budget + timeout + blob cap per bug), and a
deterministic scorecard. Grading uses the bench's own oracle, so a SOLVED verdict
means the same thing as the published benchmark.

Examples:
  python scripts/run_bench.py --langs c,c++ --budget 8 --timeout 25
  python scripts/run_bench.py --bugs netsnmp-vacm-parse-npd,libpng-zlib-inflate-uaf
  python scripts/run_bench.py --resume            # continue an interrupted sweep
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

V2_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(V2_DIR))

from fuzzingbrain.importers.bench import spec_from_bench_bug  # noqa: E402
from fuzzingbrain.importers.external_harness import build_workspace  # noqa: E402

DEFAULT_BENCH = "/data4/ze/FuzzingBrain-Bench"
DEFAULT_OSS_FUZZ = "/data4/ze/oss-fuzz"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


# ---------------------------------------------------------------- discovery
def discover_bugs(bench_dir: Path, langs: set[str] | None) -> list[tuple[str, Path]]:
    """Return [(bug_id, bug_dir)] under bench_dir/bugs, filtered by language."""
    import yaml

    out = []
    for yml in sorted((bench_dir / "bugs").glob("*/*/bench.yaml")):
        meta = yaml.safe_load(yml.read_text())
        lang = str(meta.get("target", {}).get("language", "")).lower()
        if langs and lang not in langs:
            continue
        out.append((meta.get("bug_id", yml.parent.name), yml.parent))
    return out


# ------------------------------------------------------------------- run V2
def _scan_markers(log: str) -> dict:
    """Extract coarse pipeline progress from a V2 run log."""
    txt = ANSI.sub("", log)
    return {
        "built": "fuzzers available" in txt or "Build completed:" in txt,
        "dispatched": "Dispatched" in txt and "worker" in txt.lower(),
        "build_failed": "Code Analyzer failed: Build failed" in txt,
        "no_workers": "No workers were dispatched" in txt,
    }


def run_v2(ws: Path, budget: float, timeout_min: int, log_path: Path) -> dict:
    """Drive FuzzingBrain.sh on the workspace; return run metadata."""
    cmd = [
        "./FuzzingBrain.sh", str(ws), "--in-place",
        "--task-type", "pov", "--pov-count", "1",
        "--budget", str(budget), "--timeout", str(timeout_min),
    ]
    t0 = time.time()
    # Hard wall-clock ceiling above the in-pipeline --timeout so a wedged run
    # cannot block the sweep forever.
    wall = timeout_min * 60 + 600
    try:
        proc = subprocess.run(
            cmd, cwd=str(V2_DIR), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=wall,
        )
        out = proc.stdout.decode("utf-8", "replace")
        rc = proc.returncode
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace")
        rc = -9
    log_path.write_text(out)
    meta = _scan_markers(out)
    meta.update(v2_exit=rc, duration_s=round(time.time() - t0, 1))
    return meta


# ----------------------------------------------------------------- grading
def locate_blobs(ws: Path, cap: int = 12) -> list[Path]:
    """Find candidate POV blobs V2 produced (povs/<task>/<worker>/attempt/v*.bin)."""
    seen, blobs = set(), []
    for pat in ("**/attempt_*/v*.bin", "**/povs/**/*.bin", "results/**/*.bin"):
        for p in sorted(ws.glob(pat)):
            rp = p.resolve()
            if rp not in seen and p.is_file() and p.stat().st_size > 0:
                seen.add(rp)
                blobs.append(p)
    return blobs[:cap]


def grade(bench_dir: Path, bug_id: str, blob: Path, rounds: int) -> dict:
    """Grade one blob via the bench oracle. Returns {passed, capabilities, exit}."""
    try:
        proc = subprocess.run(
            ["./fb-bench", "grade", bug_id, str(blob.resolve()), "--rounds", str(rounds)],
            cwd=str(bench_dir), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return {"passed": False, "capabilities": {}, "exit": -9, "blob": str(blob)}
    txt = ANSI.sub("", proc.stdout.decode("utf-8", "replace"))
    caps = {}
    for flag in ("reach", "crash", "crash2", "class", "site"):
        m = re.search(rf"\b{flag}\b\s+(\w+)", txt)
        if m:
            caps[flag] = m.group(1)
    return {
        "passed": proc.returncode == 0,
        "capabilities": caps,
        "exit": proc.returncode,
        "blob": str(blob),
    }


def _cap_rank(caps: dict) -> int:
    """Higher = stronger result; used to pick the best blob."""
    order = ["reach", "crash", "crash2", "class", "site"]
    return sum(1 for f in order if caps.get(f) == "fired")


# -------------------------------------------------------------------- main
def run_bug(bug_id: str, bug_dir: Path, opts) -> dict:
    ws = Path(opts.workdir) / bug_id
    rec = {"bug_id": bug_id, "project": bug_dir.parent.name, "ts": int(time.time())}
    try:
        spec = spec_from_bench_bug(bug_dir, with_description=opts.hint)
        rec["hint"] = bool(spec.description)
        rec["language"] = spec.language
        build_workspace(spec, ws, opts.oss_fuzz, overwrite=True)
    except Exception as e:  # importer / materialize failure
        rec.update(stage="import", error=str(e), solved=False)
        return rec

    log_path = Path(opts.workdir) / f"{bug_id}.v2.log"
    meta = run_v2(ws, opts.budget, opts.timeout, log_path)
    rec.update(meta, stage="ran")

    blobs = locate_blobs(ws)
    rec["n_blobs"] = len(blobs)
    best = {"passed": False, "capabilities": {}}
    graded = []
    for blob in blobs:
        g = grade(Path(opts.bench), bug_id, blob, opts.rounds)
        graded.append(g)
        if g["passed"] or _cap_rank(g["capabilities"]) > _cap_rank(best["capabilities"]):
            best = g
        if g["passed"]:
            break
    rec["solved"] = bool(best["passed"])
    rec["capabilities"] = best["capabilities"]
    rec["graded"] = graded

    # Disk hygiene: a workspace (repo clone + multi-sanitizer build) is large and
    # there can be dozens. Preserve the produced blobs, then drop the workspace
    # unless the caller asked to keep it.
    if blobs:
        keep = Path(opts.workdir) / "blobs" / bug_id
        keep.mkdir(parents=True, exist_ok=True)
        for b in blobs:
            try:
                (keep / b.name).write_bytes(b.read_bytes())
            except Exception:
                pass
    if not opts.keep_workspace:
        import shutil
        shutil.rmtree(ws, ignore_errors=True)
    return rec


def load_done(report: Path) -> dict:
    done = {}
    if report.is_file():
        for line in report.read_text().splitlines():
            line = line.strip()
            if line:
                r = json.loads(line)
                done[r["bug_id"]] = r
    return done


def scorecard(records: list[dict]) -> str:
    total = len(records)
    solved = sum(1 for r in records if r.get("solved"))
    built = sum(1 for r in records if r.get("built"))
    disp = sum(1 for r in records if r.get("dispatched"))
    lines = [
        "",
        "=" * 60,
        f" V2 on FuzzingBrain-Bench: {solved}/{total} SOLVED",
        f"   built {built}/{total}   dispatched {disp}/{total}",
        "=" * 60,
        f" {'bug_id':<40s} {'built':<6} {'disp':<5} verdict",
        f" {'-'*40} {'-'*6} {'-'*5} -------",
    ]
    for r in sorted(records, key=lambda x: (not x.get("solved"), x["bug_id"])):
        verdict = "SOLVED" if r.get("solved") else (
            "build-fail" if r.get("build_failed") else
            "no-worker" if r.get("no_workers") else
            "no-pov" if r.get("n_blobs", 0) == 0 else "graded-fail"
        )
        lines.append(
            f" {r['bug_id']:<40s} {str(bool(r.get('built'))):<6} "
            f"{str(bool(r.get('dispatched'))):<5} {verdict}"
        )
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bench", default=DEFAULT_BENCH, help="FuzzingBrain-Bench checkout")
    ap.add_argument("--oss-fuzz", default=DEFAULT_OSS_FUZZ, help="OSS-Fuzz checkout")
    ap.add_argument("--workdir", default="/tmp/fbbench-runs", help="Where workspaces + logs go")
    ap.add_argument("--report", default=None, help="JSONL report path (default: <workdir>/report.jsonl)")
    ap.add_argument("--langs", default="c,c++", help="Comma languages to include (empty = all)")
    ap.add_argument("--bugs", default="", help="Comma bug_ids (overrides discovery)")
    ap.add_argument("--budget", type=float, default=8.0, help="Per-bug USD budget")
    ap.add_argument("--timeout", type=int, default=25, help="Per-bug pipeline timeout (min)")
    ap.add_argument("--rounds", type=int, default=1, help="Grade rounds per blob")
    ap.add_argument("--no-hint", dest="hint", action="store_false",
                    help="Disable the bug-description hint (pure autonomous discovery)")
    ap.set_defaults(hint=True)
    ap.add_argument("--resume", action="store_true", help="Skip bugs already in the report")
    ap.add_argument("--limit", type=int, default=0, help="Stop after N bugs (0=all)")
    ap.add_argument("--keep-workspace", action="store_true",
                    help="Keep each bug's workspace (default: delete after grading)")
    opts = ap.parse_args(argv)

    Path(opts.workdir).mkdir(parents=True, exist_ok=True)
    report = Path(opts.report) if opts.report else Path(opts.workdir) / "report.jsonl"
    bench_dir = Path(opts.bench)

    langs = {s.strip() for s in opts.langs.split(",") if s.strip()} or None
    if opts.bugs:
        wanted = {b.strip() for b in opts.bugs.split(",") if b.strip()}
        bugs = [(bid, d) for bid, d in discover_bugs(bench_dir, None) if bid in wanted]
    else:
        bugs = discover_bugs(bench_dir, langs)

    done = load_done(report) if opts.resume else {}
    if opts.resume:
        bugs = [(b, d) for b, d in bugs if b not in done]
    if opts.limit:
        bugs = bugs[: opts.limit]

    print(f"[run_bench] {len(bugs)} bug(s) to run; report -> {report}")
    records = list(done.values())
    for i, (bug_id, bug_dir) in enumerate(bugs, 1):
        print(f"\n[{i}/{len(bugs)}] {bug_id} ...", flush=True)
        rec = run_bug(bug_id, bug_dir, opts)
        records.append(rec)
        with report.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        verdict = "SOLVED" if rec.get("solved") else rec.get("stage", "?")
        print(f"    -> {verdict}  built={rec.get('built')} "
              f"blobs={rec.get('n_blobs')} {rec.get('duration_s', 0)}s", flush=True)

    print(scorecard(records))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
