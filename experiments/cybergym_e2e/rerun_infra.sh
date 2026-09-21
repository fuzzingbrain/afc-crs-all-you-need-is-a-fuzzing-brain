#!/usr/bin/env bash
set +e
REPO=/tmp/claude-1000/cybergym-e2e-repo; ED=/home/ze/fbv2/experiments/cybergym_e2e
export PATH="$REPO/.venv/bin:$PATH"
export LITELLM_BASE_URL="http://172.19.0.1:4000" LITELLM_MASTER_KEY="sk-a05377ea090bfd09ae3e71abbcfbef65"
export OPENAI_API_KEY=$(grep -E '^OPENAI_API_KEY=' /home/ze/fbv2/.env | sed 's/^OPENAI_API_KEY=//')
cd "$REPO"
for T in mruby/arvo_18756 arrow/oss-fuzz_447480433; do
  echo "[rerun $(date +%H:%M:%S)] $T"
  .venv/bin/python scripts/run_agent.py "$T" --mode e2e --agent codex --model-provider litellm --litellm-model-id gpt-5.5 --agent-output "$ED/codex_arm" >> "$ED/codex_arm/rerun_infra.log" 2>&1
done
date > "$ED/codex_arm/RERUN_DONE"
echo "[rerun $(date +%H:%M:%S)] done"
