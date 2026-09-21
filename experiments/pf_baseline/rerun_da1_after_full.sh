#!/usr/bin/env bash
# Re-run da1-fu-01 alone (24 GB cap) once the full pass (pid 397556) has exited.
cd "$(dirname "${BASH_SOURCE[0]}")"
while kill -0 397556 2>/dev/null; do sleep 60; done
echo "$(date -Is) full pass exited; re-running da1-fu-01 with 24 GB cap" >> chain.log
PF_FORK=2 PF_RUN=pf-full-n2-r1 PF_TIME_FULL=7200 timeout 9000 ./run_one.sh da1-fu-01 >> chain.log 2>&1
python3 summarize.py runs/pf-full-n2-r1 >> chain.log
echo "$(date -Is) da1-fu-01 rerun finished" >> chain.log
