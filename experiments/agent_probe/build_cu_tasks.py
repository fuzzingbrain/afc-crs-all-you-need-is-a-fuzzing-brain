# SPDX-License-Identifier: Apache-2.0
"""Build zero-build task JSONs for all cu (curl) bugs, ready for a serial sweep.

Each task: local repo/fuzz-tooling URLs (bypass GitHub throttle), prebuilt binary
(skip compile), prebuild graph import, curl harness source injected via
fuzzer_sources, docker_image=aixcc-afc/curl:latest (verify runs where the binary's
libs live), concurrency 1, budget 20. Delta commits derived as
delta=origin/challenges/<c>, base=its parent; cu-full-01 runs full scan.
"""
import json, os, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPECS = HERE / "sp_specs"
PRE = HERE / "prebuild"
OUT = Path("/tmp/claude-1000/-home-ze-fbv2/1538ddfb-f5a8-4c15-bfc4-4af67fc18183/scratchpad/cu_tasks")
OUT.mkdir(parents=True, exist_ok=True)

bins = json.loads((PRE / "binaries.json").read_text())
# curl harness source (shared across all cu harnesses)
HSRC = PRE / "cu-delta-02" / "curl_fuzzer_ws" / "harness_src"
harness_files = [str(HSRC / f) for f in
                 ("curl_fuzzer.cc", "curl_fuzzer.h", "curl_fuzzer_tlv.cc", "curl_fuzzer_callback.cc")]


def _sh(repo, *a):
    try:
        return subprocess.check_output(["git", "-C", repo, *a], text=True,
                                       stderr=subprocess.DEVNULL)
    except Exception:
        return ""


def find_delta(repo, ch, fn):
    """The commit that introduced the vulnerable function on the challenge branch
    (variable depth: challenge heads carry extra scaffolding/test commits above the
    real delta), and its parent as base. Off-by-N-safe: walks the branch and takes
    the first commit whose diff-vs-parent mentions the ground-truth function."""
    for c in _sh(repo, "rev-list", "--max-count=15", f"origin/challenges/{ch}").split():
        if fn in _sh(repo, "diff", f"{c}^", c):
            return c, _sh(repo, "rev-parse", f"{c}^").strip()
    return None, None


built = []
for p in sorted(SPECS.glob("cu-*.json")):
    d = json.loads(p.read_text())
    tag, ch, harness = d["tag"], d["challenge"], d["harness"]
    hb = harness.split("@")[0]
    repo = f"/home/ze/fb-graphs/build/{ch}/repo"
    tooling = f"/home/ze/fb-graphs/build/{ch}/fuzz-tooling"
    binary = str((HERE / bins[tag]["binary"]).resolve())
    graph_dir = str(PRE / ch / harness.replace("/", "_"))   # holds mongodb/
    scan = d.get("scan_mode", "delta")

    task = {
        "repo_url": repo,
        "project_name": "curl",
        "task_type": "pov",
        "scan_mode": scan,
        "fuzz_tooling_url": tooling,
        "fuzz_tooling_ref": f"challenge-state/{ch}",
        "sanitizers": ["address"],
        "fuzzers": [harness],
        "remove_git": True,
        "timeout_minutes": 45,
        "budget_limit": 20.0,
        "concurrency": 1,
        "enable_static_analysis": True,
        "docker_image": "aixcc-afc/curl:latest",
        "prebuilt_fuzzers": {harness: binary},
        "prebuild_dir": graph_dir,
        "work_id": ch,
        "fuzzer_sources": {harness: harness_files},
    }
    if scan == "delta":
        gt = d["ground_truth_functions"][0]
        delta, base = find_delta(repo, ch, gt)
        if not (delta and base):
            print(f"[SKIP] {tag}: could not find vuln commit for {gt}"); continue
        task["base_commit"] = base
        task["delta_commit"] = delta

    fp = OUT / f"{tag}.json"
    fp.write_text(json.dumps(task, indent=2))
    built.append((tag, str(fp), scan, harness))

print(f"built {len(built)} cu task JSONs in {OUT}")
for tag, fp, scan, h in built:
    print(f"  {tag:24} scan={scan:5} harness={h}")
# validate binaries + graphs + harness src exist
prob = []
for tag, fp, scan, h in built:
    t = json.loads(Path(fp).read_text())
    b = list(t["prebuilt_fuzzers"].values())[0]
    g = Path(t["prebuild_dir"]) / "mongodb" / "callgraph.json"
    if not os.path.exists(b): prob.append(f"{tag}: binary missing {b}")
    if not g.exists(): prob.append(f"{tag}: graph missing {g}")
for hf in harness_files:
    if not os.path.exists(hf): prob.append(f"harness src missing {hf}")
print("PROBLEMS:", prob or "none")
