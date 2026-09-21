#!/usr/bin/env python3
"""Offline GT-PoC well-posedness gate for the CyberGym-E2E comparison.

For each task we take the benchmark's OWN ground-truth PoC (data/projects/<t>/
poc.bin) and check whether it crashes the freshly built *vulnerable* target,
i.e. CyberGym-E2E Stage 1 with the GT PoC as input. This runs NO agent and NO
LLM: it is a pure, deterministic sanity check that the task is well-posed.

  passed  -> GT PoC crashes the vul build; task is well-posed, keep it.
  failed  -> GT PoC does not crash; broken/OOD task -> infra-drop (report it).
  error   -> build/setup/timeout problem; treat as infra-drop, log the reason.

We reuse CyberGym-E2E's unchanged container setup (utils.setup_workspace) and
its unchanged scorer (validate.py --only-stage 1). The only thing we add is the
per-container resource cap (fuzzingbrain.core.docker_limits.docker_resource_args)
so a runaway build cannot livelock this shared host, and a sequential,
concurrency-1 driver. Nothing in the evaluated arms is touched by this file.

    python gt_poc_gate.py --tasks sample_30_seed42.txt \
        --repo /tmp/claude-1000/cybergym-e2e-repo \
        --out  <results-dir>
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import tomli


def load_helpers(repo):
    scripts = Path(repo) / "scripts"
    sys.path.insert(0, str(scripts))
    import utils  # noqa: E402  (path set above)
    # Load fbv2's canonical docker caps by file path. Importing the package
    # (fuzzingbrain.core) would drag in bson/pymongo and the whole task model;
    # docker_limits.py only needs os/subprocess/loguru, so load it standalone.
    import importlib.util
    dl_path = "/home/ze/fbv2/fuzzingbrain/core/docker_limits.py"
    spec = importlib.util.spec_from_file_location("_fbv2_docker_limits", dl_path)
    dl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dl)
    return utils, scripts, dl.docker_resource_args, dl.task_label_args


def resolve_build_image(script_path):
    """Same resolution as dataset_validate.py: project.toml then config.toml."""
    config = tomli.loads((script_path / "../project.toml").read_text())
    config.update(tomli.loads((script_path / "config.toml").read_text()))
    return config.get(
        "build_image",
        "gcr.io/oss-fuzz-base/base-builder@sha256:"
        "8eda74a11e800aead5a041ee479a65b33dab3150d6e89e5694e2b6eb27be98fc",
    )


def start_capped_container(image, res_args, label_args):
    cmd = ["docker", "run", "-d", "--rm", *res_args, *label_args,
           image, "sleep", "infinity"]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()


def parse_meta(script_path, build_image):
    """target_prog from config.toml, sanitizer from compile.sh (for FBv2 JSON)."""
    config = tomli.loads((script_path / "../project.toml").read_text())
    config.update(tomli.loads((script_path / "config.toml").read_text()))
    target_prog = config.get("target_prog")
    sanitizer = None
    lang = None
    comp = script_path / "compile.sh"
    if comp.exists():
        for line in comp.read_text().splitlines():
            s = line.strip()
            if s.startswith("export SANITIZER="):
                sanitizer = s.split("=", 1)[1].strip().strip('"')
            elif s.startswith("export FUZZING_LANGUAGE="):
                lang = s.split("=", 1)[1].strip().strip('"')
    return {"target_prog": target_prog, "sanitizer": sanitizer,
            "language": lang, "build_image": build_image}


def save_build(cid, task, save_builds):
    """Copy the container's /out (compiled fuzzer + corpus/deps) to the host so
    the FBv2 arm can reuse the vul build instead of recompiling. Returns the
    saved path, or None if nothing was captured."""
    if not save_builds:
        return None
    dest = Path(save_builds) / task
    dest.mkdir(parents=True, exist_ok=True)
    # size check: don't save an empty /out (compile failed)
    code = subprocess.run(
        ["docker", "exec", cid, "bash", "-c",
         "ls -A /out 2>/dev/null | head -1"], capture_output=True, text=True)
    if not code.stdout.strip():
        return None
    cp = subprocess.run(["docker", "cp", f"{cid}:/out", str(dest)],
                        capture_output=True, text=True)
    return str(dest / "out") if cp.returncode == 0 else None


def run_one(task, repo, utils, scripts_dir, res_args, label_args, timeout,
            save_builds=None):
    data_path = Path(repo) / "data" / "projects" / task
    script_path = Path(repo) / "projects" / task
    poc = data_path / "poc.bin"
    if not poc.exists():
        return {"task": task, "stage1": "no-data", "seconds": 0.0,
                "build_image": None, "detail": "poc.bin missing"}

    build_image = resolve_build_image(script_path)
    meta = parse_meta(script_path, build_image)
    t0 = time.time()
    cid = None
    try:
        cid = start_capped_container(build_image, res_args, label_args)
        # faithful container setup (their code, unchanged)
        utils.setup_workspace(cid, data_path, script_path, mode="e2e",
                              scripts_dir=scripts_dir)
        # feed the GROUND-TRUTH poc as the "agent" poc for stage 1
        utils.copy_to_container(cid, poc, "/output/poc.bin")
        cmd = ("/scripts/.venv/bin/python /scripts/validate.py "
               "--src-dir /src --config-dir /config --data-dir /data "
               "--json-output /output/validation_results.json "
               "--only-stage 1 --poc-file /output/poc.bin --run-prepare")
        code, out, err = utils.exec_run(cid, cmd, f"gate stage1 {task}",
                                        timeout=timeout, workdir="/")
        # pull the json verdict (validate.py writes {"stage1": "<status>", ...})
        tmp = Path("/tmp") / f"gate_{task.replace('/', '_')}.json"
        cp = subprocess.run(
            ["docker", "cp", f"{cid}:/output/validation_results.json", str(tmp)],
            capture_output=True)
        tail = ((out or "")[-500:] + "\n" + (err or "")[-500:]).strip()
        if cp.returncode == 0:
            res = json.loads(tmp.read_text())
            status = res.get("stage1") or "error"
            detail = tail if status != "passed" else ""
            tmp.unlink(missing_ok=True)
        else:
            status, detail = "error", f"no results json; exec code={code}; {tail[-500:]}"
        # preserve the compiled vul build for the FBv2 arm (before cleanup)
        saved = None
        try:
            saved = save_build(cid, task, save_builds)
            if saved:
                dest = Path(save_builds) / task
                (dest / "meta.json").write_text(
                    json.dumps({**meta, "task": task, "stage1": status}, indent=2))
                # copy reference files so each challenge folder is self-contained
                import shutil
                for f in ("compile.sh", "run_poc.sh", "config.toml", "patch.diff",
                          "prepare.sh"):
                    src = script_path / f
                    if src.exists():
                        shutil.copy2(src, dest / f)
                for f in ("poc.bin", "crash.log"):
                    src = data_path / f
                    if src.exists():
                        shutil.copy2(src, dest / ("gt_" + f))
        except Exception as e:  # noqa: BLE001 - saving must never fail the gate
            detail = (detail + f" | save_build err: {e}")[-600:]
        return {"task": task, "stage1": status, "seconds": round(time.time() - t0, 1),
                "build_image": build_image, "target_prog": meta["target_prog"],
                "sanitizer": meta["sanitizer"], "saved_build": saved, "detail": detail}
    except Exception as e:  # noqa: BLE001 - any setup/build failure is an infra-drop
        saved = None
        if cid:  # a compile may have produced /out before the failure
            try:
                saved = save_build(cid, task, save_builds)
            except Exception:
                pass
        return {"task": task, "stage1": "error", "seconds": round(time.time() - t0, 1),
                "build_image": build_image, "target_prog": meta.get("target_prog"),
                "sanitizer": meta.get("sanitizer"), "saved_build": saved,
                "detail": f"{type(e).__name__}: {e}"[-600:]}
    finally:
        if cid:
            try:
                utils.cleanup_container(cid)
            except Exception:
                subprocess.run(["docker", "rm", "-f", cid], capture_output=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=int, default=5400,
                    help="per-task validate.py timeout (s); covers compile+run")
    ap.add_argument("--mem-mb", type=int, default=12000)
    ap.add_argument("--cpus", type=float, default=4.0)
    ap.add_argument("--save-builds", default=None,
                    help="dir to save each task's compiled /out (vul build) for "
                         "reuse by the FBv2 arm; skip to not save")
    a = ap.parse_args()

    utils, scripts_dir, docker_resource_args, task_label_args = load_helpers(a.repo)
    res_args = docker_resource_args(a.mem_mb, a.cpus)
    label_args = task_label_args("cybergym-e2e-gtpoc-gate")

    tasks = [l.strip() for l in open(a.tasks)
             if l.strip() and not l.startswith("#")]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    results_path = out / "gate_results.jsonl"
    # resume: skip tasks already recorded
    done = set()
    if results_path.exists():
        for line in results_path.read_text().splitlines():
            if line.strip():
                done.add(json.loads(line)["task"])

    print(f"[gate] {len(tasks)} tasks, {len(done)} already done, "
          f"caps={res_args}", flush=True)
    with results_path.open("a") as fh:
        for i, task in enumerate(tasks, 1):
            if task in done:
                print(f"[gate] ({i}/{len(tasks)}) SKIP {task} (already done)",
                      flush=True)
                continue
            print(f"[gate] ({i}/{len(tasks)}) RUN  {task}", flush=True)
            r = run_one(task, a.repo, utils, scripts_dir, res_args, label_args,
                        a.timeout, save_builds=a.save_builds)
            fh.write(json.dumps(r) + "\n")
            fh.flush()
            print(f"[gate] ({i}/{len(tasks)}) {r['stage1'].upper():8s} {task} "
                  f"({r['seconds']}s)", flush=True)

    # summary
    rows = [json.loads(l) for l in results_path.read_text().splitlines() if l.strip()]
    from collections import Counter
    c = Counter(r["stage1"] for r in rows)
    print("\n[gate] === SUMMARY ===", flush=True)
    for k in ("passed", "failed", "error", "no-data"):
        if c.get(k):
            print(f"[gate]   {k:8s}: {c[k]}", flush=True)
    keep = [r["task"] for r in rows if r["stage1"] == "passed"]
    (out / "well_posed.txt").write_text("\n".join(sorted(keep)) + "\n")
    drop = [r for r in rows if r["stage1"] != "passed"]
    (out / "infra_drops.txt").write_text(
        "\n".join(f"{r['task']}\t{r['stage1']}\t{r['detail'][:200]}" for r in drop) + "\n")
    print(f"[gate] well-posed (kept): {len(keep)}  ->  {out/'well_posed.txt'}",
          flush=True)
    print(f"[gate] infra-drops:       {len(drop)}  ->  {out/'infra_drops.txt'}",
          flush=True)


if __name__ == "__main__":
    main()
