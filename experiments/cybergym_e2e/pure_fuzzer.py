#!/usr/bin/env python3
"""Pure-fuzzing baseline for the CyberGym-E2E comparison (Arm 0).

Consistent with the FBv2 RQ1 pure-fuzzing counterfactual: EMPTY corpus, no dict
(the exact starting point of FBv2's Global Fuzzer), libFuzzer -fork=2, same
per-input timeout / rss limit, 90-min cap, first crash stops the task. NO LLM,
$0. Reuses the gate-saved vul libFuzzer binaries (no rebuild).

Metric: S1 = fuzzer finds ANY input that crashes the vul build within 90 min
(lenient, same criterion as the Codex/FBv2 arms' Stage-1). For each hit we also
record the crash's first application-level stack frame and the GT target frame
so the stricter RQ1 "#0 matches target function" variant can be computed later.

    python pure_fuzzer.py --tasks <list> --out <dir> --sanitizer address --parallel 8
"""
import argparse, json, os, re, subprocess, time
from concurrent.futures import ThreadPoolExecutor, as_completed

BUILDS = "/home/ze/fbv2/experiments/cybergym_e2e/builds"
SKIP_FRAME = re.compile(r"__sanitizer|fuzzer::|__asan|__msan|__ubsan|__interceptor|"
                        r"LLVMFuzzer|asan_|operator new|::malloc|__libc|^malloc$|^free$|"
                        r"MemcmpInterceptor|scanf|printf")


def meta(task):
    return json.load(open(f"{BUILDS}/{task}/meta.json"))


def first_app_frame(text):
    """First #N frame whose function is not sanitizer/fuzzer internal."""
    for m in re.finditer(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)", text):
        fn = m.group(1)
        if not SKIP_FRAME.search(fn):
            return fn
    return None


def gt_target(task):
    p = f"{BUILDS}/{task}/gt_crash.log"
    if os.path.exists(p):
        return first_app_frame(open(p, errors="replace").read())
    return None


def sh(cid, cmd, timeout=120):
    return subprocess.run(["docker", "exec", cid, "bash", "-c", cmd],
                          capture_output=True, text=True, timeout=timeout)


def run_task(task, mem_mb, max_time=5400, poll=3):
    m = meta(task)
    tp, img, san = m["target_prog"], m["build_image"], m["sanitizer"]
    res = {"task": task, "sanitizer": san, "target": tp, "hit": False,
           "time_s": None, "summary": None, "crash_frame": None,
           "gt_frame": gt_target(task), "execs": None, "note": ""}
    cid = None
    try:
        cid = subprocess.run(
            ["docker", "run", "-d", "--rm", f"--memory={mem_mb}m",
             f"--memory-swap={mem_mb}m", "--cpus=3", "--pids-limit=1024",
             "--label", "purefuzz=cybergym-e2e", img, "sleep", str(max_time + 600)],
            capture_output=True, text=True, check=True).stdout.strip()
        sh(cid, "rm -rf /out && mkdir -p /out /corpus /crashes")
        subprocess.run(["docker", "cp", f"{BUILDS}/{task}/out/.", f"{cid}:/out/"],
                       capture_output=True)
        opts = ("export ASAN_OPTIONS=detect_leaks=0:symbolize=1:abort_on_error=1 "
                "MSAN_OPTIONS=symbolize=1:abort_on_error=1 "
                "UBSAN_OPTIONS=symbolize=1:print_stacktrace=1; ")
        # launch fuzzer detached (empty corpus, fork=2)
        sh(cid, opts + f"nohup /out/{tp} /corpus -fork=2 -ignore_crashes=1 "
                       f"-rss_limit_mb=2048 -timeout=30 -artifact_prefix=/crashes/ "
                       f"-max_total_time={max_time} -print_final_stats=1 "
                       f">/tmp/fuzz.log 2>&1 & echo started")
        t0 = time.time()
        while time.time() - t0 < max_time + 30:
            r = sh(cid, "ls /crashes/ 2>/dev/null | head -1")
            cf = r.stdout.strip()
            if cf:
                res["hit"] = True
                res["time_s"] = round(time.time() - t0, 1)
                sh(cid, f"pkill -9 -f '/out/{tp}' 2>/dev/null; true")
                break
            # fuzzer died on its own (max_total_time reached, no crash)?
            alive = sh(cid, f"pgrep -f '/out/{tp}' >/dev/null && echo Y || echo N").stdout.strip()
            if alive == "N":
                break
            time.sleep(poll)
        # symbolize the crash if any
        if res["hit"]:
            cf = sh(cid, "ls /crashes/ 2>/dev/null | head -1").stdout.strip()
            rep = sh(cid, opts + f"/out/{tp} /crashes/{cf} 2>&1 | head -60").stdout
            res["summary"] = next((l.strip() for l in rep.splitlines()
                                   if "SUMMARY:" in l or "ERROR:" in l), None)
            res["crash_frame"] = first_app_frame(rep)
            # save crash input
            os.makedirs(f"{OUT}/crashes/{task.replace('/', '_')}", exist_ok=True)
            subprocess.run(["docker", "cp", f"{cid}:/crashes/{cf}",
                            f"{OUT}/crashes/{task.replace('/', '_')}/{cf}"],
                           capture_output=True)
        fl = sh(cid, "tail -25 /tmp/fuzz.log 2>/dev/null").stdout
        ex = re.findall(r"stat::number_of_executed_units:\s*(\d+)", fl)
        res["execs"] = int(ex[-1]) if ex else None
    except Exception as e:  # noqa: BLE001
        res["note"] = f"{type(e).__name__}: {e}"[:300]
    finally:
        if cid:
            subprocess.run(["docker", "kill", cid], capture_output=True)
    return res


def main():
    global OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sanitizer", default=None, help="filter to this sanitizer")
    ap.add_argument("--parallel", type=int, default=8)
    ap.add_argument("--mem-mb", type=int, default=5000)
    ap.add_argument("--max-time", type=int, default=5400)
    a = ap.parse_args()
    OUT = a.out
    os.makedirs(OUT, exist_ok=True)
    tasks = [l.strip() for l in open(a.tasks) if l.strip() and not l.startswith("#")]
    if a.sanitizer:
        tasks = [t for t in tasks if meta(t)["sanitizer"] == a.sanitizer]
    rp = f"{OUT}/pf_results.jsonl"
    done = set()
    if os.path.exists(rp):
        done = {json.loads(l)["task"] for l in open(rp) if l.strip()}
    tasks = [t for t in tasks if t not in done]
    print(f"[pf] {len(tasks)} tasks, parallel={a.parallel}, mem={a.mem_mb}MB, "
          f"sanitizer={a.sanitizer}", flush=True)
    with open(rp, "a") as fh, ThreadPoolExecutor(max_workers=a.parallel) as ex:
        futs = {ex.submit(run_task, t, a.mem_mb, a.max_time): t for t in tasks}
        for fut in as_completed(futs):
            r = fut.result()
            fh.write(json.dumps(r) + "\n"); fh.flush()
            tag = "HIT " if r["hit"] else "miss"
            print(f"[pf] {tag} {r['task']}  t={r['time_s']}s  {r.get('summary') or ''}",
                  flush=True)


if __name__ == "__main__":
    main()
