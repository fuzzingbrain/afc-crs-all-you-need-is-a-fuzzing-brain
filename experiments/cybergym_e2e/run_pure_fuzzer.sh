#!/usr/bin/env bash
set +e
ED=/home/ze/fbv2/experiments/cybergym_e2e; OUT="$ED/pf_out"; mkdir -p "$OUT"
echo "[pf-orch $(date +%H:%M:%S)] Phase 1: 非MSan 8并行"
python3 "$ED/pure_fuzzer.py" --tasks "$ED/pf_asan_ubsan.txt" --out "$OUT" --parallel 8 --mem-mb 5000 --max-time 5400 >> "$OUT/orch.log" 2>&1
echo "[pf-orch $(date +%H:%M:%S)] Phase 2: MSan 4并行"
python3 "$ED/pure_fuzzer.py" --tasks "$ED/pf_msan.txt" --out "$OUT" --parallel 4 --mem-mb 10000 --max-time 5400 >> "$OUT/orch.log" 2>&1
date > "$OUT/PF_DONE"
echo "[pf-orch $(date +%H:%M:%S)] ALL DONE"
