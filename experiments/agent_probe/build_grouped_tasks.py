# SPDX-License-Identifier: Apache-2.0
"""Build ONE task per (challenge, harness) -- not per bug.

Same challenge version + same harness = one build, one run. Bugs that share a
build must not be run separately (redundant, and an agent can crash a different
bug in the same binary). Instead we run the harness once with pov_count = number
of distinct ground-truth functions, and score each target bug by whether its
ground-truth function appears in the run's crashes (verify_target_hit).

Emits grouped task JSONs into grouped_tasks/ plus a manifest mapping each run to
its target bugs, and group lists (pre / cu / union / all) for the sweep.
"""
import json, os, subprocess
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPECS = HERE / "sp_specs"
PRE = HERE / "prebuild"
FBG = Path("/home/ze/fb-graphs/build")
AFC = Path("/home/ze/afc-crs-all-you-need-is-a-fuzzing-brain/examples/aixcc-challenges")
OUT = Path("/tmp/claude-1000/-home-ze-fbv2/1538ddfb-f5a8-4c15-bfc4-4af67fc18183/scratchpad/grouped_tasks")
OUT.mkdir(parents=True, exist_ok=True)

bins = json.loads((PRE / "binaries.json").read_text())
HSRC = PRE / "cu-delta-02" / "curl_fuzzer_ws" / "harness_src"
_CURL_SHARED = [str(HSRC / f) for f in ("curl_fuzzer.h", "curl_fuzzer_tlv.cc", "curl_fuzzer_callback.cc")]
CURL_WS_SET = [str(HSRC / "curl_fuzzer.cc")] + _CURL_SHARED
CURL_FULL_SET = [str(PRE / "cu-full-01" / "curl_fuzzer" / "harness_src" / "fuzz_url.cc")] + _CURL_SHARED
_HDR = (".h", ".hpp", ".hh")


def _sh(repo, *a):
    try:
        return subprocess.check_output(["git", "-C", repo, *a], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return ""


def find_delta(repo, ch, fn):
    for c in _sh(repo, "rev-list", "--max-count=15", f"origin/challenges/{ch}").split():
        if fn in _sh(repo, "diff", f"{c}^", c):
            return c, _sh(repo, "rev-parse", f"{c}^").strip()
    return None, None


def project_of(ch):
    d = FBG / ch / "fuzz-tooling" / "projects"
    names = [p.name for p in d.iterdir()] if d.is_dir() else []
    return names[0] if names else None


def comp_of(ch):
    for comp in ("pre-competition", "final-competition"):
        for mode in ("delta", "full"):
            if (AFC / comp / mode / ch).is_dir():
                return comp
    return "??"


def harness_sources(ch, proj, harness, funcs):
    if harness.startswith("curl_fuzzer") and harness != "curl_fuzzer":
        return [p for p in CURL_WS_SET if os.path.exists(p)]
    if harness == "curl_fuzzer":
        return [p for p in CURL_FULL_SET if os.path.exists(p)]
    entry = [f for f in funcs if f.get("name") == "LLVMFuzzerTestOneInput"]
    if not entry:
        return []
    fp = entry[0].get("file_path") or ""
    name = Path(fp).name
    roots = [FBG / ch / "repo", FBG / ch / "fuzz-tooling" / "projects" / proj, FBG / ch / "fuzz-tooling"]
    src = None
    for r in roots:
        cand = r / fp.lstrip("/")
        if cand.is_file():
            src = cand.resolve(); break
    if src is None:
        for r in roots:
            if r.is_dir():
                hits = [h for h in sorted(r.rglob(name)) if h.is_file()]
                if hits:
                    src = hits[0].resolve(); break
    if src is None:
        return []
    out = [str(src)]
    for s in _HDR:
        if src.with_suffix(s).is_file():
            out.append(str(src.with_suffix(s)))
    return out


# --- group sp_specs by (challenge, harness) ---
groups = defaultdict(list)
for p in sorted(SPECS.glob("*.json")):
    d = json.loads(p.read_text())
    groups[(d["challenge"], d["harness"])].append(d)

built, problems, manifest = [], [], {}
for (ch, harness), specs in sorted(groups.items()):
    scan = specs[0].get("scan_mode", "delta")
    repo = str(FBG / ch / "repo")
    tooling = str(FBG / ch / "fuzz-tooling")
    project = project_of(ch)
    run_id = f"{ch}__{harness.replace('/', '_').replace('@', '_')}"

    # binary + graph are the same build for the whole group; use the first bug's
    tag0 = specs[0]["tag"]
    if tag0 not in bins:
        problems.append(f"{run_id}: no binary for {tag0}"); continue
    binary = str((HERE / bins[tag0]["binary"]).resolve())
    graph_dir = str(PRE / ch / harness.replace("/", "_"))
    if not project:
        problems.append(f"{run_id}: no project for {ch}"); continue

    fdata = json.loads((Path(graph_dir) / "mongodb" / "functions.json").read_text())
    _funcs = fdata if isinstance(fdata, list) else fdata.get("functions", [])
    hsrc = harness_sources(ch, project, harness, _funcs)
    if not hsrc:
        problems.append(f"{run_id}: no harness source"); continue

    # distinct ground-truth functions across the group's bugs
    target_bugs = [{"tag": s["tag"], "gt": s["ground_truth_functions"][0]} for s in specs]
    distinct_gt = sorted({b["gt"] for b in target_bugs})

    task = {
        "repo_url": repo, "project_name": project, "task_type": "pov", "scan_mode": scan,
        "fuzz_tooling_url": tooling, "fuzz_tooling_ref": f"challenge-state/{ch}",
        "sanitizers": ["address"], "fuzzers": [harness], "remove_git": True,
        "timeout_minutes": 120 if scan == "delta" else 240,
        "budget_limit": 150.0 if scan == "delta" else 400.0,
        "concurrency": 1, "enable_static_analysis": True,
        "docker_image": f"aixcc-afc/{project}:latest",
        "prebuilt_fuzzers": {harness: binary},
        "prebuild_dir": graph_dir, "work_id": ch,
        "fuzzer_sources": {harness: hsrc},
        "model_profile": "period-correct",
        # one run must be allowed to find every distinct bug on this harness
        "pov_count": max(1, len(distinct_gt)),
    }
    if scan == "delta":
        delta, base = find_delta(repo, ch, target_bugs[0]["gt"])
        if not (delta and base):
            problems.append(f"{run_id}: no vuln commit for {target_bugs[0]['gt']}"); continue
        task["base_commit"] = base
        task["delta_commit"] = delta

    (OUT / f"{run_id}.json").write_text(json.dumps(task, indent=2))
    manifest[run_id] = {"challenge": ch, "harness": harness, "competition": comp_of(ch),
                        "scan": scan, "target_bugs": target_bugs, "pov_count": task["pov_count"]}
    built.append((comp_of(ch), run_id, scan, len(target_bugs)))

(OUT / "_manifest.json").write_text(json.dumps(manifest, indent=2))

# group lists
def write_group(name, pred):
    rows = sorted(r for c, r, s, n in built if pred(c, r))
    (OUT / f"_group_{name}.txt").write_text("\n".join(rows) + "\n")
    return rows

pre = write_group("pre", lambda c, r: c == "pre-competition")
fin = write_group("final", lambda c, r: c == "final-competition")
cu = write_group("cu", lambda c, r: r.startswith("cu-"))
union = write_group("union", lambda c, r: c == "pre-competition" or r.startswith("cu-"))
allr = write_group("all", lambda c, r: True)

nbugs = sum(n for _, _, _, n in built)
print(f"built {len(built)} grouped runs covering {nbugs} bugs")
print(f"  pre={len(pre)} runs | final={len(fin)} runs | cu={len(cu)} | union={len(union)} | all={len(allr)}")
for comp in ("pre-competition", "final-competition"):
    sub = [b for b in built if b[0] == comp]
    print(f"\n=== {comp}: {len(sub)} runs ===")
    for _, rid, scan, nb in sorted(sub):
        star = f"  <- {nb} bugs" if nb > 1 else ""
        print(f"  {rid:44} scan={scan:5} bugs={nb}{star}")
print("\nPROBLEMS:", problems or "none")
