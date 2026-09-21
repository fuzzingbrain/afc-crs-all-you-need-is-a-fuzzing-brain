#!/usr/bin/env bash
cd "$(dirname "${BASH_SOURCE[0]}")"; date +%T
docker ps --filter label=pf_baseline --format '{{.Label "pf_baseline"}} {{.Status}}'
for k in 2 3; do [ -d runs/pf-empty-n2-r$k ] || continue; python3 summarize.py runs/pf-empty-n2-r$k | grep -E "yes|no " | sed "s/^/r$k /"
  for id in lx3-del-04 cu5-del-01 ws4-del-07 ex3-del-02 xz1-fu-01 sd1-fu-05 sd1-fu-03; do d=runs/pf-empty-n2-r$k/$id; [ -f $d/fuzz.log ] && [ ! -f $d/result.json ] || continue
    n=$(ls $d/crashes 2>/dev/null | wc -l); grep -E "^#[0-9]+: cov" $d/fuzz.log | tail -1 | sed -E 's/.*cov: ([0-9]+).*exec\/s: ([0-9]+) oom\/timeout\/crash: ([0-9\/]+) time: ([0-9]+)s.*/r'"$k"' '"$id"' RUNNING artifacts='"$n"' cov=\1 exec\/s=\2 otc=\3 t=\4s/'; tail -1 $d/fuzz.log | grep -q Killed && echo "r$k $id KILLED"; done; done
tail -1 chain.log | cut -c1-80; free -g | sed -n 2p
