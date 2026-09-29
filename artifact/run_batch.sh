#!/usr/bin/env bash
# Run a list of AIxCC CPVs one task at a time, with cleanup between runs.
#
#   artifact/run_batch.sh artifact/batches/batch1.txt            run the batch
#   DRY_RUN=1 artifact/run_batch.sh artifact/batches/batch1.txt  plan + path check only
#   BATCH_DIR=<existing dir> artifact/run_batch.sh <list>        resume: skip finished tasks
#   touch <batch dir>/STOP                                       stop after the current task
#
# The list holds CPV ids (artifact/aixcc/index.json); CPVs sharing a task run once.
# Settings (env, passed through to run.sh):
#   BUDGET       default: each task file's paper budget (delta $30, full $100); a number overrides
#   CONCURRENCY  default 5
#   FORCE_MODEL  unset = the task's model_profile (period-correct: gpt-4.1 + o3)
#   MODELS       per-role override on the profile, e.g. MODELS=poc=gpt-4.1
#   POV_COUNT    unset = the task's pov_count
#   FB_ABLATE_*  ablation switches are inherited by the run and logged in the header
#   MIN_FREE_GB  wait for this much MemAvailable before starting a task (default 16)
#   TIMEOUT_MARGIN_MIN  hard kill this long after the task's own timeout (default 20)
#   PREFLIGHT    default 1: run each prebuilt fuzzer once on an empty input first and
#                skip the task (no FuzzingBrain run, no spend) if it cannot load
set -uo pipefail
ART="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FB_ROOT="$(dirname "$ART")"
PY="$FB_ROOT/venv/bin/python3"
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
[ -f "$RESULTS" ] || printf "task\tcpvs\ttask_id\texit\treason\tcost\tminutes\tdistinct_bugs\tbugs\n" > "$RESULTS"
log() { echo "[$(date +%F' '%T)] $*" | tee -a "$OUT/batch.log"; }

# CPV ids -> unique tasks, in list order: "task<TAB>cpv,cpv<TAB>timeout_minutes<TAB>project"
PLAN="$("$PY" - "$LIST" "$ART" <<'PY'
import json, sys
lst, art = sys.argv[1], sys.argv[2]
idx = {e["cpv"]: e for e in json.load(open(f"{art}/aixcc/index.json"))}
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
    j = json.load(open(f"{art}/{t}"))
    print(f"{t}\t{','.join(cpvs[t])}\t{j['timeout_minutes']}\t{j['project_name']}")
PY
)" || { echo "$PLAN" >&2; exit 1; }

N="$(printf '%s\n' "$PLAN" | wc -l)"
ABL="$(env | grep -E '^FB_ABLATE' | tr '\n' ' ')"
log "git: $(git -C "$FB_ROOT" rev-parse --abbrev-ref HEAD)@$(git -C "$FB_ROOT" rev-parse --short HEAD)  ablation: ${ABL:-none}"
log "batch $NAME: $N tasks -> $OUT (budget=${BUDGET:-task} concurrency=$CONCURRENCY force_model=${FORCE_MODEL:-profile} models=${MODELS:-profile} pov_count=${POV_COUNT:-task})"

if [ "${DRY_RUN:-0}" = 1 ]; then
  i=0
  while IFS=$'\t' read -r task cpv tmo proj; do
    i=$((i+1))
    printf '%2d/%d %-70s %-32s %s min  ' "$i" "$N" "$task" "$cpv" "$tmo"
    "$ART/run.sh" --dry-run "$task" 2>&1 | tail -1
  done <<< "$PLAN"
  rm -rf "$OUT"
  exit 0
fi

# Kill whatever a finished or timed-out run left behind. Scoped to its own task id:
# the host is shared, so nothing is cleaned by image or name alone.
cleanup_task() {
  local tid="$1" proj="$2" run_dir="$3"
  [ -n "$run_dir" ] && pkill -KILL -f "fuzzingbrain.main --config $run_dir/task.json" 2>/dev/null
  if [ -n "$tid" ]; then
    pkill -KILL -f "celery -A fuzzingbrain.*$tid" 2>/dev/null
    local c
    c="$(docker ps -aq --filter "label=fuzzingbrain.task=$tid")"
    [ -n "$c" ] && docker rm -f $c >/dev/null 2>&1
    for c in $(docker ps -aq --filter "ancestor=aixcc-afc/$proj:latest"); do
      docker inspect "$c" --format '{{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null \
        | grep -q "/workspace/${proj}_$tid" && docker rm -f "$c" >/dev/null 2>&1
    done
  fi
}

i=0
while IFS=$'\t' read -r task cpv tmo proj; do
  i=$((i+1))
  if [ -f "$OUT/STOP" ]; then log "STOP file found, stopping before $task"; break; fi
  if cut -f1 "$RESULTS" | grep -qxF "$task"; then log "[$i/$N] skip (done): $task"; continue; fi

  while :; do
    free_gb=$(awk '/MemAvailable/{printf "%d", $2/1048576}' /proc/meminfo)
    [ "$free_gb" -ge "$MIN_FREE_GB" ] && break
    log "waiting for memory: ${free_gb}G available < ${MIN_FREE_GB}G"; sleep 60
  done

  slug="$(printf '%02d' "$i")_$(echo "$task" | sed 's#aixcc/##; s#/tasks/#__#; s#\.json$##')"
  RUN_OUT="$OUT/$slug"; mkdir -p "$RUN_OUT"

  if [ "${PREFLIGHT:-1}" = 1 ]; then
    ( cd "$FB_ROOT" && timeout 300 "$PY" "$ART/preflight.py" "$task" ) > "$RUN_OUT/preflight.log" 2>&1
    pf=$?
    pf_lines="$(grep '^PREFLIGHT' "$RUN_OUT/preflight.log" | tr '\n' ' ')"
    if [ $pf -ne 0 ]; then
      log "[$i/$N] SKIP $cpv: harness broken -- ${pf_lines:-preflight rc=$pf, see $RUN_OUT/preflight.log}"
      printf "%s\t%s\t-\t-\tharness broken: %s\t0\t0\t0\t\n" "$task" "$cpv" "${pf_lines:-preflight rc=$pf}" >> "$RESULTS"
      continue
    fi
    log "[$i/$N] preflight ok: $pf_lines"
  fi
  hard=$((tmo + MARGIN))
  log "[$i/$N] start $cpv  ($task, ${tmo}min, hard limit ${hard}min)"
  t0=$(date +%s)
  ( cd "$FB_ROOT" && timeout -k 120 "${hard}m" "$ART/run.sh" "$task" ) > "$RUN_OUT/console.log" 2>&1
  rc=$?
  mins=$(( ($(date +%s) - t0) / 60 ))

  clean="$(sed 's/\x1b\[[0-9;]*m//g' "$RUN_OUT/console.log")"
  tid="$(printf '%s' "$clean" | grep -oE "/logs/${proj}_[0-9a-f]{24}_" | head -1 | grep -oE '[0-9a-f]{24}')"
  run_dir="$(printf '%s' "$clean" | grep -oE 'resolved -> [^ ]+/task.json' | head -1 | sed 's#resolved -> ##; s#/task.json##')"
  cleanup_task "$tid" "$proj" "$run_dir"
  reason="$(printf '%s' "$clean" | grep -oE 'Exit Reason: +[^│]+' | tail -1 | sed 's/Exit Reason: *//; s/ *$//')"
  [ -z "$reason" ] && { [ $rc -eq 124 ] && reason="hard timeout (killed)" || reason="rc=$rc"; }

  # Record the outcome from the database and keep a copy of this task's records.
  summary="$("$PY" - "$tid" "$RUN_OUT" <<'PY'
import json, re, sys
tid, out = sys.argv[1], sys.argv[2]
try:
    from bson import ObjectId, json_util
    from pymongo import MongoClient
    db = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=5000)["fuzzingbrain"]
    oid = ObjectId(tid)
    import os
    os.makedirs(f"{out}/db", exist_ok=True)
    for c in ["tasks", "workers", "agents", "suspicious_points", "povs", "llm_calls"]:
        q = {"_id": oid} if c == "tasks" else {"task_id": {"$in": [oid, tid]}}
        open(f"{out}/db/{c}.json", "w").write(json_util.dumps(list(db[c].find(q))))
    cost = sum(c.get("cost", 0) or 0 for c in db.llm_calls.find({"task_id": {"$in": [oid, tid]}}))
    sigs = {}
    for p in db.povs.find({"task_id": oid, "is_successful": True}):
        s = re.search(r"SUMMARY: \S+: (\S+) (\S+)", p.get("sanitizer_output") or "")
        where = f"{s.group(1)}@{s.group(2).split('/')[-1]}" if s else (p.get("vuln_type") or "?")
        sigs.setdefault(p.get("signature") or str(p["_id"]), f"{where}[{p.get('source')}]")
    vh = db.suspicious_points.count_documents({"task_id": oid})
    vh_sup = db.suspicious_points.count_documents({"task_id": oid, "status": "suppressed"})
    print(f"{cost:.2f}\t{len(sigs)}\t{'; '.join(sigs.values())} || VH={vh} suppressed={vh_sup}")
except Exception as e:
    print(f"?\t?\tsummary failed: {e}")
PY
)"
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$task" "$cpv" "${tid:-?}" "$rc" "$reason" "$summary" "$mins" \
    | awk -F'\t' 'BEGIN{OFS="\t"}{print $1,$2,$3,$4,$5,$6,$9,$7,$8}' >> "$RESULTS"
  log "[$i/$N] done  $cpv  rc=$rc  $reason  $mins min  task=$tid  bugs: $(echo "$summary" | cut -f2-)"
done <<< "$PLAN"

log "batch finished; results: $RESULTS"
