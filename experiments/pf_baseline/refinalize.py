#!/usr/bin/env python3
"""Re-run finalize.py on finished runs (reports are cached, so this only recomputes verdict/audit fields).
  python3 refinalize.py runs/<tag>"""
import json, os, subprocess, sys
run = sys.argv[1]
for d in sorted(os.listdir(run)):
    p = os.path.join(run, d, "result.json")
    if not os.path.exists(p): continue
    r = json.load(open(p))
    if r.get("group_leader", r["id"]) != r["id"]: continue
    if d != r["id"]: continue          # skip *.killed-* / *.oomkilled-* dirs set aside; their result points at the live run dir
    env = {**os.environ, "PF_RUN": os.path.basename(run.rstrip("/")), "PF_FORK": str(r["fork"])}
    out = subprocess.run(["python3", "finalize.py", r["id"], r["run"], str(r["start"]), str(r["end"]), str(r["fuzzer_rc"]),
                          str(r["fork"]), "1" if r.get("stopped_on_hit") else "0", ",".join(r.get("group", [r["id"]]))],
                         capture_output=True, text=True, env=env)
    print(out.stdout.strip().splitlines()[-1] if out.stdout.strip() else out.stderr[-300:])
