#!/usr/bin/env python3
"""Prepare an FBv2 cybergym workspace + task JSON for one ARVO task.

Mirrors the manual arvo:1065 setup, generalized:
- fuzz-tooling skeleton (build_cybergym_workspace)
- repo/  <- sanitized /src (agent Read/Grep; symmetric with OpenHands)
- prebuilt_<id>/<harness>  <- the ARVO image's prebuilt fuzzer
- build/out/<proj>_<san>/  pre-seeded with ALL non-executable /out data files
  (e.g. magic.mgc) so a harness that loads dirname(argv[0])+"/data" finds it
- DESCRIPTION.txt  <- the SAME vulnerability_description hint OpenHands got
- fbv2_<id>.json   <- period-correct, prebuilt, budget 50, concurrency 1
"""
import json, os, shutil, subprocess, sys, stat
sys.path.insert(0, "/tmp/claude-1000/rq_runs/cg_pilot")
sys.path.insert(0, "/home/ze/fbv2")
import setup_cg_task as S
from fuzzingbrain.importers.cybergym import load_task, build_cybergym_workspace

ROOT = "/tmp/claude-1000/rq_runs/cg_pilot"
OSSFUZZ = "/home/ze/oss-fuzz-fb-fixed"
SAN_MAP = {"AddressSanitizer": "address", "MemorySanitizer": "memory",
           "UndefinedBehaviorSanitizer": "undefined"}

def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True)

def main():
    aid = sys.argv[1]
    m = S.load(aid)
    proj, harness = m["project"], m["harness"]
    san = SAN_MAP.get(m["sanitizer"], "address")
    ws = f"{ROOT}/fbv2_ws_{aid}"; pb = f"{ROOT}/prebuilt_{aid}"
    shutil.rmtree(ws, ignore_errors=True); shutil.rmtree(pb, ignore_errors=True)
    os.makedirs(pb, exist_ok=True)
    # skeleton
    t = load_task(f"arvo:{aid}", "/tmp/claude-1000/rq_runs/cybergym_data")
    build_cybergym_workspace(t, ws, OSSFUZZ, overwrite=True)
    # repo <- clean /src
    os.makedirs(f"{ws}/repo", exist_ok=True)
    cid = sh(f"docker create arvo-{aid}-vul-clean").stdout.strip()
    sh(f"docker cp {cid}:/src/. {ws}/repo/"); sh(f"docker rm {cid}")
    sh(f"find {ws}/repo -iname '*poc*' -o -iname '*.diff' -o -iname '*patch*' | xargs -r rm -rf")
    # prebuilt binary + ALL /out data files
    cid = sh(f"docker create n132/arvo:{aid}-vul").stdout.strip()
    tmp = f"{ROOT}/_out_{aid}"; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)
    sh(f"docker cp {cid}:/out/. {tmp}/"); sh(f"docker rm {cid}")
    shutil.copy2(f"{tmp}/{harness}", f"{pb}/{harness}"); os.chmod(f"{pb}/{harness}", 0o755)
    # out_dir pre-seed: every non-executable data file from /out
    out_dir = f"{ws}/fuzz-tooling/build/out/{proj}_{san}"; os.makedirs(out_dir, exist_ok=True)
    seeded=[]
    for f in os.listdir(tmp):
        fp = f"{tmp}/{f}"
        if os.path.isfile(fp) and not os.access(fp, os.X_OK):
            shutil.copy2(fp, f"{out_dir}/{f}"); seeded.append(f)
    shutil.rmtree(tmp, ignore_errors=True)
    # DESCRIPTION.txt (same hint)
    open(f"{ws}/DESCRIPTION.txt","w").write((m["hint"] or "").strip()+"\n")
    # fuzzer source path
    fsrc = f"{ws}/repo/{harness}.cc"
    if not os.path.exists(fsrc):
        cands = sh(f"find {ws}/repo -name '{harness}.c' -o -name '{harness}.cc' -o -name '{harness}.cpp'").stdout.split()
        fsrc = cands[0] if cands else f"{ws}/repo/{harness}.cc"
    task = {"task_id": f"arvo:{aid}", "project_name": proj, "task_type": "pov",
            "scan_mode": "full", "sanitizers": [san], "fuzzers": [harness],
            "workspace": ws, "in_place": True, "build_coverage": False,
            "enable_static_analysis": False, "docker_image": f"n132/arvo:{aid}-vul",
            "prebuilt_fuzzers": {harness: f"{pb}/{harness}"},
            "fuzzer_sources": {harness: [fsrc]},
            "model_profile": "period-correct", "pov_count": 1,
            "budget_limit": 50.0, "timeout_minutes": 120, "concurrency": 1}
    json.dump(task, open(f"{ROOT}/fbv2_{aid}.json","w"), indent=2)
    print(f"arvo:{aid} FBv2 ready: san={san} harness={harness} seeded_data={seeded} fsrc_exists={os.path.exists(fsrc)}")
    print(f"  task JSON: {ROOT}/fbv2_{aid}.json")

if __name__=="__main__": main()
