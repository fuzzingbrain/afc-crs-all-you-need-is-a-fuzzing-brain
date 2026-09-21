#!/usr/bin/env bash
# Autonomous Codex-arm orchestrator: wait for the libFuzzer-30 gate to finish,
# then run the OFFICIAL batch_run.sh (agent=codex, gpt-5.5, $20, isolation on)
# over the 30 libFuzzer tasks at parallel 3, guarded by a memory watchdog, then
# backfill any failed/killed tasks serially so all 30 get a real result.
set +e
REPO=/tmp/claude-1000/cybergym-e2e-repo
export PATH="$REPO/.venv/bin:$PATH"   # so batch_run.sh python3 == venv python
ED=/home/ze/fbv2/experiments/cybergym_e2e
SPDIR="/tmp/claude-1000/-home-ze-fbv2-paper-fbv2-new-paper-cybergym/422f01b2-0b87-43ab-8eb0-492387c442f1/scratchpad"
source "$SPDIR/litellm/creds.env"
export LITELLM_BASE_URL="http://172.19.0.1:4000"
export LITELLM_MASTER_KEY="$MKEY"
export OPENAI_API_KEY=$(grep -E '^OPENAI_API_KEY=' /home/ze/fbv2/.env | sed 's/^OPENAI_API_KEY=//')
export MODE=e2e AGENT=codex MODEL_PROVIDER=litellm LITELLM_MODEL_ID=gpt-5.5
OUT="$ED/codex_arm"; export AGENT_OUTPUT_DIR="$OUT"
LIST="$ED/sample_30_libfuzzer_seed42.txt"
mkdir -p "$OUT"

echo "[orch $(date +%H:%M:%S)] waiting for libFuzzer-30 gate to finish..."
while pgrep -f "gt_poc_gate.py.*new12" >/dev/null 2>&1; do sleep 30; done
echo "[orch $(date +%H:%M:%S)] gate finished. gate results:"
tail -3 "$ED/gate_out_lf/run.log" 2>/dev/null

# start memory watchdog
DANGER_GB=6 "$ED/mem_watchdog.sh" "$OUT/watchdog.log" &
WDPID=$!
echo "[orch $(date +%H:%M:%S)] watchdog pid=$WDPID; launching batch parallel=3"

# OFFICIAL batch runner, parallel 3
cd "$REPO"
MAX_PARALLEL=3 bash scripts/batch_run.sh "$LIST" 3 > "$OUT/batch_run.log" 2>&1
echo "[orch $(date +%H:%M:%S)] batch done"

# backfill: any task without a success summary -> re-run serially
backfill() {
  while read -r t; do
    [ -z "$t" ] && continue
    tn=$(echo "$t" | tr '/' '_')
    ok=$(find "$OUT/$tn" -name summary.json 2>/dev/null | xargs grep -l '"status": "success"' 2>/dev/null | head -1)
    latest=$(find "$OUT/$tn" -name summary.json 2>/dev/null | head -1)
    if [ -z "$latest" ]; then
      echo "[orch] backfill (never ran): $t"
      .venv/bin/python scripts/run_agent.py "$t" --mode e2e --agent codex --model-provider litellm --litellm-model-id gpt-5.5 --agent-output "$OUT" >> "$OUT/backfill.log" 2>&1
    fi
  done < "$LIST"
}
echo "[orch $(date +%H:%M:%S)] backfill pass (serial) for tasks that never produced a summary"
backfill

kill "$WDPID" 2>/dev/null
date > "$OUT/ALL_DONE"
echo "[orch $(date +%H:%M:%S)] ALL DONE"
