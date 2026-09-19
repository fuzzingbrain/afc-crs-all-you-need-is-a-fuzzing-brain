#!/usr/bin/env bash
# FBv2 cybergym 顺序批跑(concurrency=1)。RQ3 空闲后运行。每任务:跑 FuzzingBrain.sh ->
# 杀 celery pool -> 从 Mongo 取胜出 PoV blob -> grade.py 双镜像 oracle + provenance(S/G)。
set -uo pipefail
cd /home/ze/fbv2
CG=/tmp/claude-1000/rq_runs/cg_pilot
KILL=/tmp/claude-1000/killrun.sh
PROG=$CG/fbv2_batch_progress.log
BACKSTOP=7800   # 130min 硬上限/任务
TASKS=("$@"); [ ${#TASKS[@]} -eq 0 ] && TASKS=(1065 10400 368 47101)
echo "=== FBv2 cybergym batch start $(date '+%F %T') tasks=${TASKS[*]} ===" | tee -a "$PROG"
for id in "${TASKS[@]}"; do
  # 安全闸:若有别的 FuzzingBrain 跑(如 RQ3),等它空闲
  while pgrep -f 'fuzzingbrain.main' >/dev/null || pgrep -f 'rq3_handoff.sh|rq2_freeze.sh|full_n3.sh|watch_rq' >/dev/null; do echo "  [$id] 等待其它 FuzzingBrain/RQ 臂空闲..." | tee -a "$PROG"; sleep 60; done
  TJ=$CG/fbv2_$id.json
  echo "--- [fbv2] arvo:$id start $(date '+%T') ---" | tee -a "$PROG"
  ./FuzzingBrain.sh "$TJ" > "$CG/fbv2_$id.out" 2>&1 &
  FB=$!; waited=0
  while kill -0 $FB 2>/dev/null; do sleep 30; waited=$((waited+30)); [ $waited -ge $BACKSTOP ] && { echo "  [$id] HANG>130min 强杀" | tee -a "$PROG"; break; }; done
  bash "$KILL" >> "$CG/fbv2_$id.kill" 2>&1
  wait $FB 2>/dev/null
  # 取胜出 PoV + grade
  venv/bin/python3 - "$id" >> "$PROG" 2>&1 <<'PY'
import sys,base64,json,subprocess,os
from pymongo import MongoClient
id=sys.argv[1]
db=MongoClient("mongodb://localhost:27017",serverSelectionTimeoutMS=5000)['fuzzingbrain']
proj=json.load(open(f"/tmp/claude-1000/rq_runs/cg_pilot/fbv2_{id}.json"))["project_name"]
t=db.tasks.find_one({"project_name":proj},sort=[('_id',-1)])
if not t:
    print(f"  [fbv2] arvo:{id}: NO task doc for project={proj}"); sys.exit()
o=t['_id']
cost=sum((l.get('cost') or 0) for l in db.llm_calls.find({"task_id":o},{'cost':1}))
nsp=db.suspicious_points.count_documents({"task_id":o})
succ=list(db.povs.find({"task_id":o,"is_successful":True}))
prov="-"; verdict="NO-POV"
if succ:
    p=succ[0]
    # provenance: Running: 行 v1.bin=agent(S) / crash-<hash>=fuzzer(G)
    out=p.get('sanitizer_output') or ''
    for l in out.splitlines():
        if 'Running:' in l:
            b=l.split('Running:')[1].strip().split('/')[-1]
            prov='S' if b.startswith('v1') else ('G' if b.startswith('crash') else b)
    blob=None
    if p.get('blob'): blob=base64.b64decode(p['blob'])
    elif p.get('blob_path') and os.path.exists(p['blob_path']): blob=open(p['blob_path'],'rb').read()
    if blob:
        bp=f"/tmp/claude-1000/rq_runs/cg_pilot/results/fbv2_arvo{id}_pov.bin"; open(bp,'wb').write(blob)
        r=json.loads(subprocess.run(["python3","/tmp/claude-1000/rq_runs/cg_pilot/grade.py",id,bp],capture_output=True,text=True).stdout)
        verdict=r['verdict']; verdict+=f"|fn={r['vul']['fn']}|match={r['fn_match']}"
print(f"  [fbv2] arvo:{id}: SPs={nsp} succ={len(succ)} prov={prov} cost=${cost:.2f} verdict={verdict}")
PY
done
echo "=== FBv2 batch done $(date '+%F %T') ===" | tee -a "$PROG"
