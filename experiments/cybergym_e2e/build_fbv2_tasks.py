#!/usr/bin/env python3
"""Build FBv2 task JSONs for the CyberGym-E2E FBv2 arm (30 libFuzzer seed-42 tasks).

For each task we give FBv2 exactly what Codex/pure-fuzzer get: the source tree
(src.tgz -> repo/) and the fuzzer harness, NO vulnerability description. FBv2 runs
its full-scan pipeline on the prebuilt target (same /out binary the other arms use),
force_model=gpt-5.5 for strict model parity, concurrency=1, $20 budget.
"""
import json, os, subprocess, sys, tarfile, glob

ED = "/home/ze/fbv2/experiments/cybergym_e2e"
REPO_DATA = "/tmp/claude-1000/cybergym-e2e-repo/data/projects"
ARM = f"{ED}/fbv2_arm"
LIST = f"{ED}/sample_30_libfuzzer_seed42.txt"

os.makedirs(ARM, exist_ok=True)

def find_harness(repo_root, target_prog):
    """Return the harness source file (contains LLVMFuzzerTestOneInput), best-effort."""
    hits = []
    for dp, dn, fn in os.walk(repo_root):
        # prune vendored/tooling dirs
        dn[:] = [d for d in dn if d not in (".git", "fuzz-tooling", "aflplusplus", "honggfuzz")]
        for f in fn:
            if f.endswith((".c", ".cc", ".cpp", ".cxx", ".C")):
                p = os.path.join(dp, f)
                try:
                    with open(p, "r", errors="ignore") as fh:
                        txt = fh.read()
                except Exception:
                    continue
                if "LLVMFuzzerTestOneInput" in txt:
                    # prefer a file whose name resembles the target
                    score = 0
                    base = f.lower()
                    if target_prog.lower() in base or base.split(".")[0] in target_prog.lower():
                        score += 10
                    if "fuzz" in base:
                        score += 3
                    hits.append((score, p))
    if not hits:
        return None
    hits.sort(reverse=True)
    return hits[0][1]

def main():
    tasks = [l.strip() for l in open(LIST) if l.strip()]
    built, skipped = [], []
    for t in tasks:
        proj, tid = t.split("/", 1)
        meta = json.load(open(f"{ED}/builds/{t}/meta.json"))
        build_image = meta["build_image"]
        target_prog = meta["target_prog"]
        sanitizer = meta.get("sanitizer") or "address"
        # normalize sanitizer name for FBv2 (address/memory/undefined)
        san = {"address": "address", "memory": "memory", "undefined": "address"}.get(sanitizer, sanitizer)

        ws = f"{ARM}/ws/{proj}__{tid}"
        repo = f"{ws}/repo"
        os.makedirs(repo, exist_ok=True)
        # 1) extract source (same /src the agent saw)
        srctgz = f"{REPO_DATA}/{t}/src.tgz"
        if not glob.glob(f"{repo}/*"):
            with tarfile.open(srctgz) as tar:
                tar.extractall(repo)
        # src.tgz may unpack into repo/src/... ; find the real project root
        roots = [d for d in glob.glob(f"{repo}/*") if os.path.isdir(d)]
        src_root = repo
        if len(roots) == 1 and os.path.basename(roots[0]) in ("src", proj):
            src_root = roots[0]

        # 2) prebuilt binary (reuse the gate's /out, same binary all arms use)
        prebuilt_dir = f"{ARM}/prebuilt/{proj}__{tid}"
        os.makedirs(prebuilt_dir, exist_ok=True)
        subprocess.run(["cp", "-a", f"{ED}/builds/{t}/out/.", prebuilt_dir + "/"], check=True)
        prebuilt_bin = f"{prebuilt_dir}/{target_prog}"
        if not os.path.exists(prebuilt_bin):
            skipped.append((t, f"no prebuilt binary {target_prog}"))
            continue

        # 3) locate harness source
        harness = find_harness(src_root, target_prog)
        fuzzer_sources = {target_prog: [harness]} if harness else {}

        task_json = {
            "project_name": proj,
            "task_type": "pov",
            "scan_mode": "full",
            "sanitizers": [san],
            "fuzzers": [target_prog],
            "workspace": ws,
            "in_place": True,
            "build_coverage": False,
            "enable_static_analysis": False,
            "docker_image": build_image,
            "prebuilt_fuzzers": {target_prog: prebuilt_bin},
            "fuzzer_sources": fuzzer_sources,
            "force_model": "gpt-5.5",
            "pov_count": 1,
            "budget_limit": 20.0,
            "timeout_minutes": 120,
            "concurrency": 1,
            "work_id": f"cybergym-e2e-{proj}-{tid}",
        }
        outp = f"{ARM}/fbv2_{proj}__{tid}.json"
        json.dump(task_json, open(outp, "w"), indent=2)
        built.append((t, target_prog, san, "harness" if harness else "NO-HARNESS"))

    print(f"built {len(built)} JSONs, skipped {len(skipped)}")
    for t, tp, s, h in built:
        print(f"  OK  {t}  prog={tp} san={s} {h}")
    for t, why in skipped:
        print(f"  SKIP {t}: {why}")

if __name__ == "__main__":
    main()
