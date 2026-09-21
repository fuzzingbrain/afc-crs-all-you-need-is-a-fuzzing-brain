#!/usr/bin/env bash
# Sequential pass over all 40 targets (concurrency 1, as CLAUDE.md requires).
#   PF_FORK=8 PF_RUN=pf-r1 ./run_all.sh            # all 40
#   PF_FORK=8 PF_RUN=pf-r1 ./run_all.sh cu4-del-08 cu3-del-07
# A target with an existing result.json is skipped, so the pass can be resumed.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
: "${PF_FORK:?set PF_FORK}"
export PF_RUN="${PF_RUN:-pf-$(date +%F)}"
# Default pass = all 40 minus skip_sok_nonpf.txt (PF_SKIP=none runs all 40). Explicit ids are never skipped.
if [ $# -gt 0 ]; then IDS=("$@"); SKIP=""; else
  mapfile -t IDS < <(python3 -c "import json;m=json.load(open('manifest.json'));seen=set();out=[]
for e in m:
    k=(e['challenge'],e['harness'])
    if k not in seen: seen.add(k); out.append(e['id'])
print('\n'.join(out))")
  SKIP=$(grep -v '^#' skip_sok_nonpf.txt); [ "${PF_SKIP:-}" = "none" ] && SKIP=""
fi
for id in "${IDS[@]}"; do
  grep -qx "$id" <<<"$SKIP" && { echo "skip $id (SoK: not PF-solvable, see skip_sok_nonpf.txt)"; continue; }
  [ -e "runs/$PF_RUN/$id/result.json" ] && { echo "skip $id (done)"; continue; }
  ./run_one.sh "$id" 2>&1 | tee -a "runs/$PF_RUN/run_all.log"
done
python3 summarize.py "runs/$PF_RUN"
