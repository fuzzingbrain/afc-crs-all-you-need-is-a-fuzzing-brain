#!/usr/bin/env bash
# Run one pure-fuzzing trial and judge every artifact while the fuzzer runs.
#   PF_FORK=2 ./run_one.sh cu4-del-08
# Layout: runs/<PF_RUN>/<id>/{corpus,crashes,seedcheck,judge,bin?,fuzz.log,result.json}
#
# Stop rule: the fuzzer is killed as soon as the target bug is hit -- the metric
# is time to first hit.  A harness that carries several target bugs (shadowsocks
# json_fuzz: five heap overflows in json_parse_ex) is one run that judges every
# artifact against every sibling bug and stops only when ALL of them are hit;
# each sibling id gets its own result.json with its own time_to_target.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
ID="${1:?target id}"
: "${PF_FORK:?set PF_FORK (libFuzzer -fork level; see README)}"
export PF_RUN="${PF_RUN:-pf-$(date +%F)}"
RUN="runs/$PF_RUN/$ID"
[ -e "$RUN/result.json" ] && { echo "$ID: $RUN/result.json exists, refusing to overwrite"; exit 2; }

read -r BIN_DIR WRAPPER MODE SIBS <<<"$(python3 - "$ID" <<'EOF'
import json, sys
m = json.load(open("manifest.json")); e = {x["id"]: x for x in m}[sys.argv[1]]
sibs = [x["id"] for x in m if x["challenge"] == e["challenge"] and x["harness"] == e["harness"]]
print(e["bin_dir"], e["wrapper"], e["mode"], ",".join(sibs))
EOF
)"
IFS=, read -r -a SIB <<<"$SIBS"
[ "${#SIB[@]}" -gt 1 ] && echo "$ID: shared harness, judging for all of: ${SIB[*]} (stop only when all are hit)"

mkdir -p "$RUN/corpus" "$RUN/crashes" "$RUN/judge"
CMDFILE="${PF_CMD_OVERRIDE:-cmd/$ID.sh}"
if [ "${PF_NO_SEEDS:-0}" = "1" ]; then
  # "Empty" arm: no shipped seeds and no dictionary, exactly how FBv2's Global Fuzzer starts
  # (manager.py creates an empty global/corpus; instance.py never passes -dict).
  sed 's/ -dict=[^ ]*//' "$CMDFILE" > "$RUN/cmd.empty.sh"; CMDFILE="$RUN/cmd.empty.sh"
  echo "$ID: empty-corpus arm (no seeds, no dict)"
else
  # libFuzzer writes new inputs into the first corpus dir; keep the pristine seeds untouched.
  cp -r "corpus/$ID/." "$RUN/corpus/"
fi
if [ "$WRAPPER" = "True" ]; then cp -r "$BIN_DIR" "$RUN/bin"; fi

# Seed pre-check: execute every seed once (-runs=0). A seed that already
# triggers the target is a t=0 "hit" that fuzzing gets no credit for.
mkdir -p "$RUN/seedcheck"
if [ -n "$(ls -A "$RUN/corpus")" ]; then
  sed -e 's#/crashes:/crashes#/seedcheck:/crashes#' -e 's#-fork=${PF_FORK:?} ##' \
      -e 's#-max_total_time=$T#-runs=0#' -e 's#> $RUN/fuzz.log#> $RUN/seedcheck.log#' "$CMDFILE" | bash
fi

# Batch replay: one container per poll for all new artifacts; verdicts per sibling are pure text checks.
REP="$RUN/judge/rep"; mkdir -p "$REP"
replay_new() { ./replay.sh "$ID" "$RUN/crashes" "$REP" >/dev/null 2>&1; }
judge_cached() {   # <sib> <artifact> -> exit code; verdict cached in judge/<sib>-crashes-<a>.verdict
  local sib="$1" a="$2" vf="$RUN/judge/$1-crashes-$2.verdict" rcj v
  if [ -e "$vf" ]; then return "$(head -1 "$vf")"; fi
  [ -e "$REP/$a.txt" ] || return 1
  v=$(python3 verdict.py "$sib" "$REP/$a.txt"); rcj=$?
  printf '%s\n%s\n' "$rcj" "$v" > "$vf"; return "$rcj"
}

START=$(date +%s)
echo "$ID: start $(date -Is) fork=$PF_FORK run=$RUN"
bash "$CMDFILE" &
CPID=$!
declare -A HIT=(); STOPPED_ON_HIT=0; NA=0
while kill -0 "$CPID" 2>/dev/null; do
  sleep 15
  [ -n "$(ls -A "$RUN/crashes" 2>/dev/null)" ] && [ "$NA" -lt 10000 ] && replay_new
  for a in $(ls -tr "$RUN/crashes" 2>/dev/null); do
    [ -e "$RUN/judge/.seen-$a" ] && continue
    [ "$NA" -ge 10000 ] && break          # cap live judging; the rest is replayed post-run (up to 100000)
    [ -e "$REP/$a.txt" ] || continue      # arrived after this poll's replay; next round
    for sib in "${SIB[@]}"; do
      [ -n "${HIT[$sib]:-}" ] && continue
      if judge_cached "$sib" "$a"; then
        HIT[$sib]="$a"
        echo "$ID: TARGET HIT [$sib] by $a at $(( $(stat -c %Y "$RUN/crashes/$a") - START ))s (${#HIT[@]}/${#SIB[@]} bugs)"
      fi
    done
    touch "$RUN/judge/.seen-$a"; NA=$((NA+1))
  done
  if [ "${#HIT[@]}" -eq "${#SIB[@]}" ]; then
    echo "$ID: all ${#SIB[@]} target bug(s) hit -> stopping fuzzer"
    docker kill $(docker ps -q --filter "label=pf_baseline=$ID") >/dev/null 2>&1; STOPPED_ON_HIT=1; break
  fi
done
wait "$CPID"; RC=$?
END=$(date +%s)
echo "$ID: fuzzer exited rc=$RC after $((END-START))s; artifacts: $(ls "$RUN/crashes" | wc -l); stopped_on_hit=$STOPPED_ON_HIT; hits=${#HIT[@]}/${#SIB[@]}"

# Post-run: per sibling, judge what the live loop did not reach (cap), then write result.json for every sibling.
python3 finalize.py "$ID" "$RUN" "$START" "$END" "$RC" "$PF_FORK" "$STOPPED_ON_HIT" "$SIBS"
