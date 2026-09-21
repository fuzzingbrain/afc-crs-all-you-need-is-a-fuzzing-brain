#!/usr/bin/env python3
"""Post-run pass of run_one.sh, callable standalone for a run dir that never got its result.json:
  python3 finalize.py <id> <run-dir> <start-epoch> <end-epoch> <fuzzer-rc> <fork> <stopped-on-hit 0|1> <sib1,sib2,...>
"""
import json, os, re, subprocess, sys
tid, run, start, end, rc, fork, stopped, sibs = (sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
                                                int(sys.argv[5]), int(sys.argv[6]), sys.argv[7] == "1", sys.argv[8].split(","))
crashes = os.path.join(run, "crashes")
arts = sorted((os.path.getmtime(os.path.join(crashes, a)), a) for a in os.listdir(crashes))
rep = os.path.join(run, "judge", "rep"); os.makedirs(rep, exist_ok=True)
# replay (once per artifact) whatever the live loop did not reach, capped at 300 artifacts
missing = [a for _, a in arts if not os.path.exists(os.path.join(rep, a + ".txt"))]
if missing:
    subprocess.run(["./replay.sh", tid, crashes, rep], capture_output=True, env={**os.environ, "PF_REPLAY_MAX": "100000"})
seeddir = os.path.join(run, "seedcheck"); seedrep = os.path.join(run, "judge", "seedrep")
if os.path.isdir(seeddir) and os.listdir(seeddir):
    os.makedirs(seedrep, exist_ok=True); subprocess.run(["./replay.sh", tid, seeddir, seedrep], capture_output=True)
sys.path.insert(0, "."); from verdict import verdict as _verdict, site_compare as _site

def judge(sib, sub, a, t):
    rp = os.path.join(rep if sub == "crashes" else seedrep, a + ".txt")
    if not os.path.exists(rp):
        why = "not replayed: timeout/oom artifact" if not a.startswith("crash-") else "UNREPLAYED (cap)"
        return {"artifact": a, "kind": a.split("-")[0], "t_seconds": t, "target_hit": False,
                "verdict": why, "sanitizer": None, "frame0": None, "frames": []}
    txt = open(rp, errors="replace").read()
    rcj, out = _verdict(sib, txt)
    err = re.search(r"ERROR: \w+Sanitizer: ([^ \n]+)|(deadly signal)", txt)
    f0 = re.search(r"#0 0x[0-9a-f]+ in (\S+)", txt)
    fn = [m.group(1) for m in re.finditer(r"#\d+ 0x[0-9a-f]+ in (\S+)", txt)][:4]
    d = {"artifact": a, "kind": a.split("-")[0], "t_seconds": t, "target_hit": rcj == 0, "verdict": out,
         "sanitizer": (err.group(1) or err.group(2)) if err else None, "frame0": f0.group(1) if f0 else None, "frames": fn}
    if rcj == 0:
        d.update(_site(sib, txt))     # crash-site audit against the official PoV's crash.txt
    return d

log = open(os.path.join(run, "fuzz.log"), errors="replace").read()
status = re.findall(r"^#(\d+):\s+cov: (\d+) ft: (\d+) corp: (\d+).*?exec/s: (\d+) oom/timeout/crash: (\d+)/(\d+)/(\d+) time: (\d+)s", log, re.M)
last = status[-1] if status else None
stats = {"seed": (re.search(r"INFO: Seed: (\d+)", log) or [None, None])[1],
         "seed_inputs": int((re.search(r"-fork=\d+: (\d+) seed inputs", log) or [0, 0])[1]),
         "status_lines": len(status),
         "final": {"runs": int(last[0]), "cov": int(last[1]), "ft": int(last[2]), "corp": int(last[3]),
                   "exec_s": int(last[4]), "oom": int(last[5]), "timeout": int(last[6]), "crash": int(last[7]),
                   "time_s": int(last[8])} if last else None,
         "exited": (re.search(r"INFO: exiting: (\d+) time: (\d+)s", log) or [None, None, None])[1],
         "cov_curve": [(int(x[8]), int(x[1])) for x in status[::max(1, len(status)//60)]]}
kinds = {}
for _, a in arts: kinds[a.split("-")[0]] = kinds.get(a.split("-")[0], 0) + 1
env = {k: os.environ.get(k) for k in ("PF_FORK", "PF_TIME_DELTA", "PF_TIME_FULL", "PF_RSS_MB", "PF_IMAGE", "PF_RUN")}
seedfiles = sorted(os.listdir(os.path.join(run, "seedcheck"))) if os.path.isdir(os.path.join(run, "seedcheck")) else []

summary = []
for sib in sibs:
    judged, first, unjudged = [], None, 0
    for mtime, a in arts:
        if first is not None and len(judged) >= 200:
            unjudged += 1; continue          # after this bug is hit, do not list hundreds of duplicates
        judged.append(judge(sib, "crashes", a, round(mtime - start, 1)))
        if judged[-1]["target_hit"] and first is None:
            first = judged[-1]
    seedcheck = [judge(sib, "seedcheck", a, 0.0) for a in seedfiles]
    res = {"id": sib, "run": run, "group": sibs, "group_leader": tid, "fork": fork, "start": start, "end": end,
           "elapsed_s": end - start, "fuzzer_rc": rc, "artifacts": len(arts), "artifact_kinds": kinds,
           "unjudged": unjudged, "stopped_on_hit": stopped, "target_hit": first is not None,
           "review_needed": bool(first) and not first.get("site_line_match", True),
           "site_fn_match": first.get("site_fn_match") if first else None,
           "site_line_match": first.get("site_line_match") if first else None,
           "time_to_target_s": first["t_seconds"] if first else None, "first_hit": first,
           "seeds": len(os.listdir(os.path.join("corpus", tid))),
           "seed_crashes": len(seedcheck), "seed_hits_target": any(j["target_hit"] for j in seedcheck), "seedcheck": seedcheck,
           "fuzzer_stats": stats, "judged": judged, "env": env}
    os.makedirs(os.path.join("runs", os.environ["PF_RUN"], sib), exist_ok=True)
    json.dump(res, open(os.path.join("runs", os.environ["PF_RUN"], sib, "result.json"), "w"), indent=1)
    tag = "" if not first else (" site=same" if first.get("site_line_match") else " site=REVIEW(" + ",".join(first.get("artifact_site", [])[:1]) + " vs " + ",".join(first.get("official_site", [])[:1]) + ")")
    summary.append(f"{sib}: target_hit={res['target_hit']} time_to_target_s={res['time_to_target_s']}{tag}")
print(f"{tid}: artifacts={len(arts)} {kinds} stopped_on_hit={stopped} final={stats['final']}")
print("\n".join(summary))
