#!/usr/bin/env bash
cd "$(dirname "${BASH_SOURCE[0]}")"; date +%T
docker ps --filter label=pf_baseline --format '{{.Label "pf_baseline"}} {{.Status}}'
python3 summarize.py runs/pf-empty-n2-r1 | grep -E "^runs|yes|no "
for id in cu5-del-01 ex3-del-02 lx3-del-04 ex2-del-01 sd1-fu-04 sd1-fu-03 sd1-fu-05; do d=runs/pf-empty-n2-r1/$id; [ -f $d/fuzz.log ] && [ ! -f $d/result.json ] || continue
  n=$(ls $d/crashes 2>/dev/null | wc -l); st=$(grep -E "^#[0-9]+: cov" $d/fuzz.log | tail -1 | sed -E 's/.*cov: ([0-9]+).*exec\/s: ([0-9]+) oom\/timeout\/crash: ([0-9\/]+) time: ([0-9]+)s.*/cov=\1 exec\/s=\2 otc=\3 t=\4s/'); echo "$id RUNNING artifacts=$n $st"; tail -1 $d/fuzz.log | grep -q Killed && echo "$id KILLED"; done
pgrep -f "run_parallel.sh 3 cu5-del-01" | grep -v pgrep | wc -l | sed 's/^/runner procs: /'; free -g | sed -n 2p
