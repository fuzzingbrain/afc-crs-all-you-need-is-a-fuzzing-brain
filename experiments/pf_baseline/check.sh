#!/usr/bin/env bash
# One-shot status for the scheduled check: containers, changed rows, live progress, dav1d variants.
cd "$(dirname "${BASH_SOURCE[0]}")"; date +%T
docker ps --filter label=pf_baseline --format '{{.Label "pf_baseline"}} {{.Status}}'
python3 summarize.py runs/pf-full-n2-r1 | grep -E "^runs|REVIEW|no "
for id in ss1-fu-00 mg1-fu-00 ws1-fu-05 xz1-fu-01; do d=runs/pf-full-n2-r1/$id; [ -f $d/fuzz.log ] && [ ! -f $d/result.json ] || continue
  n=$(ls $d/crashes 2>/dev/null | wc -l); st=$(grep -E "^#[0-9]+: cov" $d/fuzz.log | tail -1 | sed -E 's/.*cov: ([0-9]+).*exec\/s: ([0-9]+) oom\/timeout\/crash: ([0-9\/]+) time: ([0-9]+)s.*/cov=\1 exec\/s=\2 otc=\3 t=\4s/')
  hits=$(find $d/judge -maxdepth 1 -name "*.verdict" -print0 2>/dev/null | xargs -0 -r grep -l "^0$" 2>/dev/null | sed -E 's#.*/judge/([a-z0-9-]+)-crashes-.*#\1#' | sort -u | tr '\n' ' '); echo "$id RUNNING artifacts=$n $st hits=[$hits]"; done
for v in da1guard4g da1fork1; do d=runs/pf-full-n2-r1-$v/da1-fu-01; [ -f $d/fuzz.log ] || continue
  if [ -f $d/result.json ]; then python3 -c "import json;r=json.load(open('$d/result.json'));print('$v DONE hit=',r['target_hit'],'t=',r['time_to_target_s'],'rc=',r['fuzzer_rc'],'kinds=',r['artifact_kinds'],'site=',r.get('site_line_match'))"
  else n=$(ls $d/crashes 2>/dev/null | wc -l); grep -E "^#[0-9]+: cov" $d/fuzz.log | tail -1 | sed -E 's/.*cov: ([0-9]+).*exec\/s: ([0-9]+) oom\/timeout\/crash: ([0-9\/]+) time: ([0-9]+)s.*/'"$v"' RUNNING artifacts='"$n"' cov=\1 exec\/s=\2 otc=\3 t=\4s/'; tail -1 $d/fuzz.log | grep -q Killed && echo "$v KILLED"; fi; done
pgrep -fa "run_parallel|rerun_" | grep -v "pgrep\|bash -c" | wc -l | sed 's/^/runner+waiter procs: /'; free -g | sed -n 2p
