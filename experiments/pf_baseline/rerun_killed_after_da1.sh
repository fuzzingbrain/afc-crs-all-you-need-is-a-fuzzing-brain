#!/usr/bin/env bash
# Re-run the 4 full targets (ss1 group, mg1, ws1-fu-05, xz1) that an external 'docker kill' cut short at 20:13,
# once the da1 rerun (pid 734908) has exited. 3 parallel, fork=2, 2 h each.
cd "$(dirname "${BASH_SOURCE[0]}")"
while kill -0 734908 2>/dev/null; do sleep 60; done
echo "$(date -Is) da1 rerun exited; re-running externally killed targets" >> chain.log
PF_FORK=2 PF_RUN=pf-full-n2-r1 PF_TIME_FULL=7200 timeout 18000 ./run_parallel.sh 3 ss1-fu-00 mg1-fu-00 ws1-fu-05 xz1-fu-01 >> chain.log 2>&1
echo "$(date -Is) reruns finished" >> chain.log
