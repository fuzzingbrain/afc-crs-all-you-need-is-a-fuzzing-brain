#!/usr/bin/env bash
# Run targets J at a time (each container is cgroup-capped: --cpus=PF_FORK, --memory=2048*PF_FORK+1024 MB).
#   PF_FORK=2 PF_RUN=pf-delta-n2-r1 ./run_parallel.sh 3 delta      # 12 delta targets not in skip_sok_nonpf.txt
#   PF_FORK=2 PF_RUN=pf-full-n2-r1  ./run_parallel.sh 3 full
#   PF_FORK=2 PF_RUN=x ./run_parallel.sh 2 av2-del-02 ex2-del-01   # explicit ids, never skipped
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
: "${PF_FORK:?set PF_FORK}"; export PF_RUN="${PF_RUN:-pf-$(date +%F)}"
J="${1:?jobs}"; shift
if [ "$#" -eq 1 ] && [[ "$1" =~ ^(delta|full|all)$ ]]; then
  SKIP=$(grep -v '^#' skip_sok_nonpf.txt); [ "${PF_SKIP:-}" = "none" ] && SKIP=""
  mapfile -t IDS < <(python3 -c "import json,sys;m=json.load(open('manifest.json'));seen=set();out=[]
for e in m:
    k=(e['challenge'],e['harness'])
    if (sys.argv[1]=='all' or e['mode']==sys.argv[1]) and k not in seen: seen.add(k); out.append(e['id'])
print('\n'.join(out))" "$1" | grep -vxF -f <(printf '%s\n' "$SKIP" | grep . || echo __none__))
else IDS=("$@"); fi
mkdir -p "runs/$PF_RUN"
echo "$(date -Is) jobs=$J fork=$PF_FORK run=$PF_RUN targets(${#IDS[@]}): ${IDS[*]}" | tee -a "runs/$PF_RUN/parallel.log"
printf '%s\n' "${IDS[@]}" | xargs -P "$J" -I{} bash -c '[ -e "runs/$PF_RUN/{}/result.json" ] && { echo "skip {} (done)"; exit 0; }; ./run_one.sh {} 2>&1 | sed -u "s/^/[{}] /"' 2>&1 | tee -a "runs/$PF_RUN/parallel.log"
python3 summarize.py "runs/$PF_RUN" | tee -a "runs/$PF_RUN/parallel.log"
