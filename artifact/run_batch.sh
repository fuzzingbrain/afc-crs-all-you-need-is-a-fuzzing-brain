#!/usr/bin/env bash
# Run a list of AIxCC CPVs one task at a time, with cleanup between runs.
#
#   artifact/run_batch.sh artifact/batches/batch1.txt            run the batch
#   DRY_RUN=1 artifact/run_batch.sh artifact/batches/batch1.txt  validate every task, run nothing
#   BATCH_DIR=<existing dir> artifact/run_batch.sh <list>        resume: skip finished tasks
#   touch <batch dir>/STOP                                       stop after the current task
#
# The list holds CPV ids (artifact/tasks/aixcc/index.json); CPVs sharing a task run once.
# Settings (env, passed through to run.sh):
#   BUDGET       default: each task file's paper budget (delta $30, full $100); a number overrides
#   CONCURRENCY  default 5
#   FORCE_MODEL  unset = the task's models (period-correct: gpt-4.1 + o3)
#   MODELS       per-role change to the task's models, e.g. MODELS=poc=gpt-4.1
#   POC_COUNT    unset = the task's poc_count
#   FB_ABLATE_*  ablation switches are inherited by the run and logged in the header
#   MIN_FREE_GB  wait for this much MemAvailable before starting a task (default 16)
#   TIMEOUT_MARGIN_MIN  hard kill this long after the task's own timeout (default 20)
#
# Each run's own preflight (<run>/preflight.json) stops it before any spend when a
# fuzzer cannot start in its image; the outcome is read from <run>/result.json.
set -uo pipefail
ART="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FB_ROOT="$(dirname "$ART")"
PY="$FB_ROOT/venv/bin/python3"
INDEX="$ART/tasks/aixcc/index.json"
LIST="${1:?usage: run_batch.sh <list of CPV ids>}"
[ -f "$LIST" ] || { echo "no such list: $LIST" >&2; exit 1; }

export CONCURRENCY="${CONCURRENCY:-5}"
BUDGET="${BUDGET:-task}"
if [ "$BUDGET" = task ]; then unset BUDGET; else export BUDGET; fi
MIN_FREE_GB="${MIN_FREE_GB:-16}"
MARGIN="${TIMEOUT_MARGIN_MIN:-20}"
NAME="$(basename "$LIST" .txt)"
OUT="${BATCH_DIR:-$FB_ROOT/workspace/batches/${NAME}_$(date +%Y%m%d_%H%M%S)}"
[ "${DRY_RUN:-0}" = 1 ] && OUT="$(mktemp -d)"   # a plan check leaves nothing behind
mkdir -p "$OUT"
RESULTS="$OUT/results.tsv"
[ -f "$RESULTS" ] || printf "task\tcpvs\trun_id\texit\tstatus\tend_reason\tcost\tminutes\tdistinct_bugs\tbugs\n" > "$RESULTS"
log() { echo "[$(date +%F' '%T)] $*" | tee -a "$OUT/batch.log"; }

# CPV ids -> unique tasks, in list order: "task<TAB>cpv,cpv<TAB>timeout_minutes"
PLAN="$("$PY" - "$LIST" "$INDEX" "$FB_ROOT" <<'PY'
import json, sys
lst, index, root = sys.argv[1:4]
idx = {e["cpv"]: e for e in json.load(open(index))}
order, cpvs, bad = [], {}, []
for line in open(lst):
    c = line.split("#")[0].strip()
    if not c:
        continue
    if c not in idx:
        bad.append(c); continue
    t = idx[c]["task"]
    if t not in cpvs:
        order.append(t); cpvs[t] = []
    cpvs[t].append(c)
if bad:
    sys.exit("unknown CPV ids: " + " ".join(bad))
for t in order:
    j = json.load(open(f"{root}/{t}"))
    print(f"{t}\t{','.join(cpvs[t])}\t{j['timeout_minutes']}")
PY
)" || { echo "$PLAN" >&2; exit 1; }

N="$(printf '%s\n' "$PLAN" | wc -l)"
ABL="$(env | grep -E '^FB_ABLATE' | tr '\n' ' ')"
log "git: $(git -C "$FB_ROOT" rev-parse --abbrev-ref HEAD)@$(git -C "$FB_ROOT" rev-parse --short HEAD)  ablation: ${ABL:-none}"
log "batch $NAME: $N tasks -> $OUT (budget=${BUDGET:-task} concurrency=$CONCURRENCY force_model=${FORCE_MODEL:-task} models=${MODELS:-task} poc_count=${POC_COUNT:-task})"

if [ "${DRY_RUN:-0}" = 1 ]; then
  i=0
  while IFS=$'\t' read -r task cpv tmo; do
    i=$((i+1))
    printf '%2d/%d %-80s %-32s %s min  ' "$i" "$N" "$task" "$cpv" "$tmo"
    "$ART/run.sh" --dry-run "$task" 2>&1 | grep -E "Task is valid|ERROR|^  - " | head -3 | tr '\n' ' '
    echo
  done <<< "$PLAN"
  rm -rf "$OUT"
  exit 0
fi

# Kill whatever a finished or timed-out run left behind, scoped to its run id:
# the host is shared, so nothing is cleaned by image or name alone.
cleanup_run() {
  local rid="$1" task_json="$2"
  pkill -KILL -f "fuzzingbrain.main --config $task_json" 2>/dev/null
  [ -n "$rid" ] || return 0
  local pg
  for pg in $(pgrep -f "celery .*workers_$rid" | xargs -r ps -o pgid= -p | sort -u); do
    kill -KILL -- "-$pg" 2>/dev/null
  done
  local c
  c="$(docker ps -aq --filter "label=fuzzingbrain.run=$rid")"
  [ -n "$c" ] && docker rm -f $c >/dev/null 2>&1
  return 0
}

i=0
while IFS=$'\t' read -r task cpv tmo; do
  i=$((i+1))
  if [ -f "$OUT/STOP" ]; then log "STOP file found, stopping before $task"; break; fi
  if cut -f1 "$RESULTS" | grep -qxF "$task"; then log "[$i/$N] skip (done): $task"; continue; fi

  while :; do
    free_gb=$(awk '/MemAvailable/{printf "%d", $2/1048576}' /proc/meminfo)
    [ "$free_gb" -ge "$MIN_FREE_GB" ] && break
    log "waiting for memory: ${free_gb}G available < ${MIN_FREE_GB}G"; sleep 60
  done

  slug="$(printf '%02d' "$i")_$(basename "$task" .json)"
  RUN_OUT="$OUT/$slug"
  hard=$((tmo + MARGIN))
  log "[$i/$N] start $cpv  ($task, ${tmo}min, hard limit ${hard}min)"
  t0=$(date +%s)
  ( cd "$FB_ROOT" && OUTPUT="$RUN_OUT" timeout -k 120 "${hard}m" "$ART/run.sh" "$task" ) > "$OUT/$slug.console.log" 2>&1
  rc=$?
  mins=$(( ($(date +%s) - t0) / 60 ))

  row="$("$PY" - "$RUN_OUT/run" <<'PY'
import json, os, sys
run = sys.argv[1]
rid = ""
for f in ("result.json", "preflight.json"):
    p = os.path.join(run, f)
    if os.path.isfile(p):
        rid = json.load(open(p)).get("run_id") or rid
        if rid:
            break
p = os.path.join(run, "result.json")
if os.path.isfile(p):
    r = json.load(open(p))
    bugs = "; ".join(f"{c['vuln_type']}@{c['signature'][:60]}" for c in r["crashes"])
    print("\t".join([rid, r["status"], str(r.get("end_reason") or "-"), f"{r['cost']:.2f}",
                     str(len(r["crashes"])), bugs]))
else:
    pf = os.path.join(run, "preflight.json")
    why = "no result.json"
    if os.path.isfile(pf) and not json.load(open(pf)).get("ok"):
        why = "preflight failed: " + "; ".join(json.load(open(pf))["failures"])[:300]
    print("\t".join([rid, "error", why, "?", "?", ""]))
PY
)"
  rid="$(printf '%s' "$row" | cut -f1)"
  cleanup_run "$rid" "$RUN_OUT/task.json"
  IFS=$'\t' read -r rid status reason cost nbugs bugs <<< "$row"
  [ $rc -eq 124 ] && reason="hard timeout (killed)"
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$task" "$cpv" "${rid:-?}" "$rc" "$status" "$reason" "$cost" "$mins" "$nbugs" "$bugs" >> "$RESULTS"
  log "[$i/$N] done  $cpv  rc=$rc  $status/$reason  \$$cost  $mins min  run=$rid  bugs=$nbugs"
done <<< "$PLAN"

log "batch finished; results: $RESULTS"
