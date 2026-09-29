#!/usr/bin/env bash
# Run one benchmark task from this artifact with no build step.
#
#   artifact/run.sh aixcc/cu-delta-02/tasks/curl_fuzzer_ws.json
#   artifact/run.sh cybergym-e2e/arrow_447480433/task.json
#   artifact/run.sh --dry-run <task>          resolve + check paths, don't run
#   BUDGET=20 CONCURRENCY=1 artifact/run.sh <task>   override the paper setting
#   FORCE_MODEL=gpt-4.1 artifact/run.sh <task>       every agent role on one model
#   POV_COUNT=4 artifact/run.sh <task>               stop after N distinct bugs (0 = never)
#   EVAL_PORT=18080 (default)                         eval server the run reports to
#
# The task JSON stores paths as $ARTIFACT/...; they are resolved to this
# directory. CyberGym cases run in place, so repo/ and fuzz-tooling/ are copied
# into a fresh workspace under $FB_RUN_ROOT (default: <repo>/workspace/artifact_runs)
# and the artifact itself is never written to.
set -euo pipefail
ART="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FB_ROOT="$(dirname "$ART")"
DRY=0
[ "${1:-}" = "--dry-run" ] && { DRY=1; shift; }
TASK="${1:?usage: run.sh [--dry-run] <task.json relative to artifact/>}"
[ -f "$TASK" ] || TASK="$ART/$TASK"
[ -f "$TASK" ] || { echo "no such task: $1" >&2; exit 1; }

RUN_ROOT="${FB_RUN_ROOT:-$FB_ROOT/workspace/artifact_runs}"
STAMP="$(date +%Y%m%d_%H%M%S)"
CASE="$(basename "$(dirname "$TASK")")"; [ "$CASE" = tasks ] && CASE="$(basename "$(dirname "$(dirname "$TASK")")")__$(basename "$TASK" .json)"
RUN_DIR="$RUN_ROOT/${CASE}_$STAMP"
mkdir -p "$RUN_DIR"

python3 - "$TASK" "$ART" "$RUN_DIR" "$DRY" <<'PY'
import json, os, sys
task, art, run_dir, dry = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1"
t = json.load(open(task))
ws = os.path.join(run_dir, "workspace")
def res(v):
    if isinstance(v, str):
        return v.replace("$ARTIFACT", art).replace("$RUN_WORKSPACE", ws)
    if isinstance(v, list):
        return [res(x) for x in v]
    if isinstance(v, dict):
        return {k: res(x) for k, x in v.items()}
    return v
t = res(t)
if os.environ.get("BUDGET"):
    t["budget_limit"] = float(os.environ["BUDGET"])
if os.environ.get("CONCURRENCY"):
    t["concurrency"] = int(os.environ["CONCURRENCY"])
if os.environ.get("FORCE_MODEL"):
    t["force_model"] = os.environ["FORCE_MODEL"]
if os.environ.get("POV_COUNT"):
    t["pov_count"] = int(os.environ["POV_COUNT"])
bad = []
for h, p in t["prebuilt_fuzzers"].items():
    if not os.path.isfile(p): bad.append(f"fuzzer {p}")
for f in ("functions.json", "callgraph.json"):
    p = os.path.join(t["prebuild_dir"], "mongodb", f)
    if not os.path.isfile(p): bad.append(f"graph {p}")
for h, srcs in t.get("fuzzer_sources", {}).items():
    if not srcs: bad.append(f"no harness source for {h}")
    for p in srcs:
        if not os.path.isfile(p): bad.append(f"harness source {p}")
if bad:
    sys.exit("MISSING:\n  " + "\n  ".join(bad))
json.dump(t, open(os.path.join(run_dir, "task.json"), "w"), indent=2)
print(f"resolved -> {run_dir}/task.json (budget={t.get('budget_limit')} concurrency={t.get('concurrency')} force_model={t.get('force_model')} pov_count={t.get('pov_count')})")
PY

if grep -q '"in_place": true' "$RUN_DIR/task.json"; then
  CDIR="$(dirname "$TASK")"
  if [ "$DRY" = 0 ]; then
    mkdir -p "$RUN_DIR/workspace"
    cp -a "$CDIR/repo" "$RUN_DIR/workspace/repo"
    cp -a "$CDIR/fuzz-tooling" "$RUN_DIR/workspace/fuzz-tooling"
  fi
fi

if [ "$DRY" = 1 ]; then
  echo "dry run ok"; rm -rf "$RUN_DIR"; exit 0
fi
cd "$FB_ROOT"
exec ./FuzzingBrain.sh --eval-port "${EVAL_PORT:-18080}" "$RUN_DIR/task.json"
