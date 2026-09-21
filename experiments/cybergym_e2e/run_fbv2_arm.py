#!/usr/bin/env python3
"""Serial runner for the FBv2 arm (Arm B) of the CyberGym-E2E study.

Runs each task ONE AT A TIME (no parallelism): launch FuzzingBrain on the task,
wait for it to exit (it stops itself on the first verified PoV since pov_count=1,
or at timeout_minutes=90), record the outcome, immediately start the next.

  - launcher: cd /home/ze/fbv2 && ./FuzzingBrain.sh --eval-port 18080 <task.json>
    (NO --budget: budget_limit=20 is in the JSON; --eval-port 18080 -> live dashboard)
  - S1 (PoV) = FBv2 produced a verified crashing PoV: exit reason "POV target
    reached" in the run log, and/or a results/povs/pov_*/ with is_successful.
  - records per task: solved, wall seconds, API cost, exit reason -> results jsonl.

    python run_fbv2_arm.py --list <ordered task list> --out fbv2_arm_out
"""
import argparse, json, os, re, subprocess, time
from pathlib import Path

FBV2 = "/home/ze/fbv2"
ARM = Path(os.environ.get("FBV2_ARM_DIR", "/tmp/claude-1000/e2e-fbv2-arm"))
EVAL_PORT = os.environ.get("FBV2_EVAL_PORT", "18080")


def wid_of(task):
    proj, idp = task.split("/", 1)
    return f"{proj}_{idp.split('_')[-1]}"


def find_pov(ws):
    """A verified crashing PoV present in the workspace results."""
    povs = ws / "results" / "povs"
    if not povs.is_dir():
        return None
    # prefer a pov_*/pov.bin; fall back to any crash_*.bin
    for d in sorted(povs.glob("pov_*")):
        pb = d / "pov.bin"
        if pb.exists():
            return str(pb)
    cr = sorted(povs.glob("crash_*.bin"))
    return str(cr[0]) if cr else None


def parse_log(text):
    cost = None
    m = re.findall(r"API Cost:\s*\$([0-9.]+)", text)
    if m:
        cost = float(m[-1])
    reason = None
    rm = re.search(r"Exit Reason:\s*([^\n│]+)", text)
    if rm:
        reason = rm.group(1).strip()
    povtarget = "POV target reached" in text
    return cost, reason, povtarget


def run_task(task, out, safety_s=6900):
    wid = wid_of(task)
    proj = task.split("/", 1)[0]
    jp = ARM / wid / f"fbv2_{proj}.json"
    ws = ARM / wid
    log = Path(out) / f"{wid}.log"
    r = {"task": task, "wid": wid, "solved": False, "wall_s": None,
         "cost": None, "exit_reason": None, "pov": None, "rc": None, "note": ""}
    if not jp.exists():
        r["note"] = "task json missing"
        return r
    t0 = time.time()
    try:
        with open(log, "w") as fh:
            p = subprocess.run(
                ["bash", "-lc",
                 f"cd {FBV2} && ./FuzzingBrain.sh --eval-port {EVAL_PORT} {jp}"],
                stdout=fh, stderr=subprocess.STDOUT, timeout=safety_s)
            r["rc"] = p.returncode
    except subprocess.TimeoutExpired:
        r["note"] = "safety-timeout"
    r["wall_s"] = round(time.time() - t0, 1)
    txt = log.read_text(errors="replace") if log.exists() else ""
    r["cost"], r["exit_reason"], povtarget = parse_log(txt)
    pov = find_pov(ws)
    r["pov"] = pov
    r["solved"] = bool(pov) or povtarget
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", required=True, help="ordered task list (one per run)")
    ap.add_argument("--out", default=str(ARM / "fbv2_arm_out"))
    ap.add_argument("--safety-min", type=int, default=115,
                    help="hard cap per task (FBv2 self-stops at 90min)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    tasks = [l.strip() for l in open(a.list) if l.strip() and not l.startswith("#")]
    rp = Path(a.out) / "fbv2_arm_results.jsonl"
    done = set()
    if rp.exists():
        done = {json.loads(l)["task"] for l in open(rp) if l.strip()}
    todo = [t for t in tasks if t not in done]
    print(f"[fbv2-arm] {len(todo)} tasks to run (serial), {len(done)} already done",
          flush=True)
    with open(rp, "a") as fh:
        for i, t in enumerate(todo, 1):
            print(f"[fbv2-arm] ({i}/{len(todo)}) START {wid_of(t)}  {time.strftime('%H:%M:%S')}",
                  flush=True)
            r = run_task(t, a.out, safety_s=a.safety_min * 60)
            fh.write(json.dumps(r) + "\n"); fh.flush()
            tag = "SOLVED" if r["solved"] else "no-pov"
            print(f"[fbv2-arm] ({i}/{len(todo)}) {tag} {r['wid']}  "
                  f"t={r['wall_s']}s cost=${r['cost']} reason={r['exit_reason']}",
                  flush=True)
    print("[fbv2-arm] ALL DONE", flush=True)


if __name__ == "__main__":
    main()
