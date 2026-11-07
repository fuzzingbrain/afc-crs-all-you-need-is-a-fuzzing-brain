#!/usr/bin/env bash
# Run one benchmark task from this artifact with no build step.
#
#   artifact/run.sh artifact/tasks/aixcc/cu-delta-05__curl_fuzzer_dict.json
#   artifact/run.sh --dry-run <task>                  validate (--check), don't run
#   BUDGET=20 CONCURRENCY=1 artifact/run.sh <task>    override the paper setting
#   FORCE_MODEL=gpt-4.1 artifact/run.sh <task>        every role on one model
#   MODELS=poc=gpt-4.1 artifact/run.sh <task>         per-role change to the task's models
#   POC_COUNT=4 artifact/run.sh <task>                stop after N distinct bugs (0 = never)
#   OUTPUT=/abs/dir artifact/run.sh <task>            where the run writes (default below)
#
# Task paths are relative to the FuzzingBrain checkout. $OUTPUT (default
# <repo>/workspace/artifact_runs/<task>_<stamp>) gets the resolved task.json,
# and the run itself writes into $OUTPUT/run: preflight.json, result.json,
# logs/ and results/.
set -euo pipefail
ART="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FB_ROOT="$(dirname "$ART")"
DRY=0
ARGS=()
for a in "$@"; do [ "$a" = "--dry-run" ] && DRY=1 || ARGS+=("$a"); done
[ "${#ARGS[@]}" -eq 1 ] || { echo "usage: run.sh [--dry-run] <task.json>" >&2; exit 2; }
TASK="${ARGS[0]}"
[ -f "$TASK" ] || TASK="$FB_ROOT/$TASK"
[ -f "$TASK" ] || { echo "no such task: ${ARGS[0]}" >&2; exit 1; }

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUTPUT:-$FB_ROOT/workspace/artifact_runs/$(basename "$TASK" .json)_$STAMP}"
mkdir -p "$OUT"

"$FB_ROOT/venv/bin/python3" - "$TASK" "$OUT" <<'PY'
import json, os, sys
task, out = sys.argv[1], sys.argv[2]
t = json.load(open(task))
e = os.environ
if e.get("BUDGET"):
    t["budget_limit"] = float(e["BUDGET"])
if e.get("CONCURRENCY"):
    t["concurrency"] = int(e["CONCURRENCY"])
if e.get("FORCE_MODEL"):
    t["force_model"] = e["FORCE_MODEL"]
    t.pop("models", None)
if e.get("MODELS"):
    if t.get("force_model"):
        sys.exit("MODELS and FORCE_MODEL: give one")
    t["models"] = {**(t.get("models") or {}),
                   **dict(kv.split("=", 1) for kv in e["MODELS"].split(",") if kv)}
if e.get("POC_COUNT"):
    t["poc_count"] = int(e["POC_COUNT"])
t["output"] = os.path.join(out, "run")
json.dump(t, open(os.path.join(out, "task.json"), "w"), indent=2)
print(f"resolved -> {out}/task.json (budget={t.get('budget_limit')} concurrency={t.get('concurrency')} "
      f"force_model={t.get('force_model')} models={t.get('models')} poc_count={t.get('poc_count')})")
PY

cd "$FB_ROOT"
if [ "$DRY" = 1 ]; then
  ./venv/bin/python -m fuzzingbrain.main --config "$OUT/task.json" --check
  rm -rf "$OUT"
  exit 0
fi
exec ./venv/bin/python -m fuzzingbrain.main --config "$OUT/task.json"
