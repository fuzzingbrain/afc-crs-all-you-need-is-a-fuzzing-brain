#!/usr/bin/env bash
# Wait for the delta pass (run_parallel.sh 3 delta) to finish, then run the full pass with the same settings.
cd "$(dirname "${BASH_SOURCE[0]}")"
while pgrep -f "run_parallel.sh 3 delta" >/dev/null; do sleep 60; done
echo "$(date -Is) delta pass finished; starting full pass" >> chain.log
PF_FORK=2 PF_RUN=pf-full-n2-r1 PF_TIME_FULL=7200 timeout 50400 ./run_parallel.sh 3 full >> chain.log 2>&1
echo "$(date -Is) full pass finished rc=$?" >> chain.log
