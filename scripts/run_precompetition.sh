#!/usr/bin/env bash
# Run the pre-competition challenge task files one at a time, overnight-safe.
#
#   scripts/run_precompetition.sh [--budget 20] [--timeout-minutes N] [--out DIR]
#                                 [--dry-run] [task.json ...]
#
# With no task files it takes every <challenge>__<harness>.json under the
# pre-competition examples (delta first, then full). Each run gets its own
# task_id, its own log, a hard wall-clock cap independent of the app's own
# timeout, and a teardown that kills the process group, anything else still
# naming the task, and every container carrying the task's label -- before the
# next run starts and again on Ctrl+C. Results accumulate in <out>/results.tsv;
# re-running with the same --out skips tasks that already have a row.
#
# Budget: 20 USD per task unless --budget says otherwise (CLAUDE.md). The task
# files carry 150/400 and the CLI --budget flag is ignored in --config mode, so
# the value is written into a per-run copy of each task file instead.
set -uo pipefail

ROOT=/home/ze/fbv2
EXAMPLES=/home/ze/afc-crs-all-you-need-is-a-fuzzing-brain/examples/aixcc-challenges/pre-competition
PY="$ROOT/venv/bin/python3"
BUDGET=20
TIMEOUT=-
OUT=""
DRY=0
TASKS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --budget) BUDGET="$2"; shift 2 ;;
    --timeout-minutes) TIMEOUT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) TASKS+=("$1"); shift ;;
  esac
done
[ -n "$OUT" ] || OUT="$ROOT/logs/precomp/$(date +%Y%m%d_%H%M)"
if [ ${#TASKS[@]} -eq 0 ]; then
  mapfile -t TASKS < <(ls "$EXAMPLES"/delta/*/*__*.json "$EXAMPLES"/full/*/*__*.json 2>/dev/null)
fi
[ ${#TASKS[@]} -gt 0 ] || { echo "no task files found under $EXAMPLES"; exit 2; }

cd "$ROOT"
mkdir -p "$OUT/logs"
RESULTS="$OUT/results.tsv"

echo "=== plan ($OUT) ==="
"$PY" scripts/precomp_plan.py "$OUT" "$BUDGET" "$TIMEOUT" "${TASKS[@]}" || exit $?
[ "$DRY" = 1 ] && { echo "(dry run, nothing started)"; exit 0; }

# Infrastructure the runs assume.
for c in fuzzingbrain-mongodb fuzzingbrain-redis; do
  docker ps --format '{{.Names}}' | grep -qx "$c" || { echo "container $c is not running"; exit 2; }
done
set -a; . "$ROOT/.env"; set +a
[ -f "$RESULTS" ] || printf 'tag\ttask_id\tstatus\tpovs\tsps\tcost_usd\tminutes\tfinished\tnote\n' > "$RESULTS"

CUR_PGID=""; CUR_TID=""
teardown() {
  # Process group first (CLI, celery worker, analysis server, agent subprocesses),
  # then whatever still names the task, then the task's containers.
  if [ -n "$CUR_PGID" ]; then
    kill -TERM "-$CUR_PGID" 2>/dev/null
    for _ in $(seq 20); do kill -0 "-$CUR_PGID" 2>/dev/null || break; sleep 0.5; done
    kill -KILL "-$CUR_PGID" 2>/dev/null
  fi
  if [ -n "$CUR_TID" ]; then
    pkill -KILL -f "$CUR_TID" 2>/dev/null
    ids=$(docker ps -q --filter "label=fuzzingbrain.task=$CUR_TID" 2>/dev/null)
    [ -n "$ids" ] && docker kill $ids >/dev/null 2>&1
  fi
  CUR_PGID=""; CUR_TID=""
}
trap 'echo; echo "interrupted -- tearing down"; teardown; exit 130' INT TERM

n=0
total=$(($(wc -l < "$OUT/plan.tsv") - 1))
# Process substitution, not a pipe: the loop must run in this shell so the
# trap sees CUR_PGID / CUR_TID of the run in flight.
while IFS=$'\t' read -r TAG TID MODE PROF POV MINS CFG; do
  n=$((n + 1))
  if awk -F'\t' -v t="$TAG" 'NR>1 && $1==t {f=1} END {exit !f}' "$RESULTS"; then
    echo "[$n/$total] $TAG already has a result, skipping"; continue
  fi
  LOG="$OUT/logs/$TAG.log"
  START=$(date +%s)
  echo "[$n/$total] $(date '+%H:%M') $TAG  ($MODE, $PROF, cap ${MINS}min, \$$BUDGET)"

  setsid "$PY" -m fuzzingbrain.main --config "$CFG" > "$LOG" 2>&1 &
  PID=$!
  CUR_PGID=$(ps -o pgid= -p "$PID" 2>/dev/null | tr -d ' ')
  CUR_TID="$TID"
  ( sleep $(( MINS * 60 + 600 )) && kill -TERM "-$CUR_PGID" 2>/dev/null ) &
  WALL=$!
  wait "$PID"; RC=$?
  kill "$WALL" 2>/dev/null; wait "$WALL" 2>/dev/null

  ELAPSED=$(( ($(date +%s) - START) / 60 ))
  RES=$("$PY" scripts/precomp_result.py "$TID" 2>/dev/null || printf 'unknown\t0\t0\t0\tresult query failed')
  IFS=$'\t' read -r STATUS POVS SPS COST NOTE <<< "$RES"
  [ "$RC" = 0 ] || NOTE="rc=$RC; $NOTE"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$TAG" "$TID" "$STATUS" "$POVS" "$SPS" "$COST" "$ELAPSED" "$(date '+%m-%d %H:%M')" "$NOTE" >> "$RESULTS"
  echo "        -> $STATUS  povs=$POVS  sps=$SPS  \$$COST  ${ELAPSED}min  $NOTE"

  teardown
  echo "        disk free: $(df -h / | awk 'NR==2{print $4}')   mem free: $(free -g | awk '/Mem/{print $7}')G"
done < <(tail -n +2 "$OUT/plan.tsv")

echo
echo "=== results ($RESULTS) ==="
column -t -s $'\t' "$RESULTS"
