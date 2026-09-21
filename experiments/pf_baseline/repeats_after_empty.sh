#!/usr/bin/env bash
# After the empty arm (pid 3749247) finishes: regenerate the table, then run two more empty-corpus repeats
# of the 7 targets whose conclusions hinge on time-to-hit, 3 parallel, fork=2.
cd "$(dirname "${BASH_SOURCE[0]}")"
while kill -0 3749247 2>/dev/null; do sleep 60; done
python3 make_results_md.py >> chain.log 2>&1
for k in 2 3; do
  echo "$(date -Is) starting empty-corpus repeat r$k" >> chain.log
  PF_NO_SEEDS=1 PF_FORK=2 PF_RUN=pf-empty-n2-r$k PF_TIME_DELTA=3600 PF_TIME_FULL=7200 timeout 21600 ./run_parallel.sh 3 lx3-del-04 cu5-del-01 ws4-del-07 ex3-del-02 xz1-fu-01 sd1-fu-05 sd1-fu-03 >> chain.log 2>&1
  python3 make_results_md.py >> chain.log 2>&1
done
echo "$(date -Is) repeats finished" >> chain.log
