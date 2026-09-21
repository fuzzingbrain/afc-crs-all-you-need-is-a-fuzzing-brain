# SPDX-License-Identifier: Apache-2.0
"""Build zero-build task JSONs for ALL AIxCC bugs (generalises build_cu_tasks.py).

Per challenge, derived automatically:
  * project_name  <- fuzz-tooling/projects/<name>  (single project per challenge)
  * docker_image  <- aixcc-afc/<project_name>:latest  (binary's build image)
  * prebuilt bin  <- binaries.json[tag]
  * prebuild graph<- prebuild/<challenge>/<harness>/mongodb  (functions.json carries
                     each function's `content`, so the finder reads source via the
                     graph -- no harness-source injection needed except for curl,
                     where the proven curl_fuzzer sources are kept).
  * delta commits <- find_delta(): first commit on origin/challenges/<ch> whose diff
                     vs its parent mentions the ground-truth function; parent = base.

Emits one JSON per sp_spec into all_tasks/, and prints the pre-competition (17),
cu (8) and their union (23) groupings so a sweep can select a subset.
"""
import json, os, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPECS = HERE / "sp_specs"
PRE = HERE / "prebuild"
FBG = Path("/home/ze/fb-graphs/build")
AFC = Path("/home/ze/afc-crs-all-you-need-is-a-fuzzing-brain/examples/aixcc-challenges")
OUT = Path("/tmp/claude-1000/-home-ze-fbv2/1538ddfb-f5a8-4c15-bfc4-4af67fc18183/scratchpad/all_tasks")
OUT.mkdir(parents=True, exist_ok=True)

bins = json.loads((PRE / "binaries.json").read_text())

# curl harness sources (hand-extracted from the image; the .h holds the TLV type
# table an agent must not have to infer). Shared machinery reused across harnesses.
HSRC = PRE / "cu-delta-02" / "curl_fuzzer_ws" / "harness_src"
_CURL_SHARED = [str(HSRC / f) for f in ("curl_fuzzer.h", "curl_fuzzer_tlv.cc", "curl_fuzzer_callback.cc")]
# entry curl_fuzzer.cc (ws/http/dict/ftp harnesses)
CURL_WS_SET = [str(HSRC / "curl_fuzzer.cc")] + _CURL_SHARED
# entry fuzz_url.cc (cu-full-01 "curl_fuzzer" full-scan harness)
CURL_FULL_SET = [str(PRE / "cu-full-01" / "curl_fuzzer" / "harness_src" / "fuzz_url.cc")] + _CURL_SHARED

_SRC_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".C")
_HDR_SUFFIXES = (".h", ".hpp", ".hh")


def harness_sources(ch, proj, harness, funcs):
    """Absolute paths to the harness source (+ same-stem header) so the run's
    get_fuzzer_source hits its `fuzzer_sources` config directly, never the disk-
    search heuristic. curl uses the hand-extracted set; everything else is resolved
    from the graph's recorded entry file_path against the on-disk checkout."""
    # curl special cases
    if harness.startswith("curl_fuzzer") and harness != "curl_fuzzer":
        return [p for p in CURL_WS_SET if os.path.exists(p)]
    if harness == "curl_fuzzer":  # cu-full-01
        return [p for p in CURL_FULL_SET if os.path.exists(p)]
    # generic: entry file_path from functions.json -> disk
    entry = [f for f in funcs if f.get("name") == "LLVMFuzzerTestOneInput"
             or f.get("symbol") == "LLVMFuzzerTestOneInput"]
    if not entry:
        return []
    fp = entry[0].get("file_path") or ""
    name = Path(fp).name
    roots = [FBG / ch / "repo", FBG / ch / "fuzz-tooling" / "projects" / proj, FBG / ch / "fuzz-tooling"]
    src = None
    for r in roots:                                   # exact relative path first
        cand = r / fp.lstrip("/")
        if cand.is_file():
            src = cand.resolve(); break
    if src is None:                                   # else basename search
        for r in roots:
            if r.is_dir():
                hits = [h for h in sorted(r.rglob(name)) if h.is_file()]
                if hits:
                    src = hits[0].resolve(); break
    if src is None:
        return []
    out = [str(src)]
    for s in _HDR_SUFFIXES:                            # same-stem companion header
        if src.with_suffix(s).is_file():
            out.append(str(src.with_suffix(s)))
    return out


def _sh(repo, *a):
    try:
        return subprocess.check_output(["git", "-C", repo, *a], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return ""


def find_delta(repo, ch, fn):
    """First commit on the challenge branch whose diff-vs-parent mentions the
    ground-truth function; parent = base. Off-by-N-safe against scaffolding commits."""
    for c in _sh(repo, "rev-list", "--max-count=15", f"origin/challenges/{ch}").split():
        if fn in _sh(repo, "diff", f"{c}^", c):
            return c, _sh(repo, "rev-parse", f"{c}^").strip()
    return None, None


def project_of(ch):
    d = FBG / ch / "fuzz-tooling" / "projects"
    names = [p.name for p in d.iterdir()] if d.is_dir() else []
    return names[0] if len(names) == 1 else (names[0] if names else None), names


def comp_of(ch):
    for comp in ("pre-competition", "final-competition"):
        for mode in ("delta", "full"):
            if (AFC / comp / mode / ch).is_dir():
                return comp
    return "??"


built, problems = [], []
for p in sorted(SPECS.glob("*.json")):
    d = json.loads(p.read_text())
    tag, ch, harness = d["tag"], d["challenge"], d["harness"]
    scan = d.get("scan_mode", "delta")
    repo = str(FBG / ch / "repo")
    tooling = str(FBG / ch / "fuzz-tooling")

    if tag not in bins:
        problems.append(f"{tag}: no binary entry"); continue
    binary = str((HERE / bins[tag]["binary"]).resolve())
    graph_dir = str(PRE / ch / harness.replace("/", "_"))
    project, projlist = project_of(ch)
    if not project:
        problems.append(f"{tag}: cannot resolve project_name for {ch} ({projlist})"); continue

    # resolve harness source (fuzzer_sources) from the graph's entry file_path
    fdata = json.loads((Path(graph_dir) / "mongodb" / "functions.json").read_text())
    _funcs = fdata if isinstance(fdata, list) else fdata.get("functions", [])
    hsrc = harness_sources(ch, project, harness, _funcs)
    if not hsrc:
        problems.append(f"{tag}: could NOT resolve harness source for {harness}"); continue

    task = {
        "repo_url": repo,
        "project_name": project,
        "task_type": "pov",
        "scan_mode": scan,
        "fuzz_tooling_url": tooling,
        "fuzz_tooling_ref": f"challenge-state/{ch}",
        "sanitizers": ["address"],
        "fuzzers": [harness],
        "remove_git": True,
        # FB single-node caps (FBv2 paper): Delta 120 min / $150, Full 240 min / $400.
        # Budget is set high enough that TIME is the binding cap (our OpenAI spend is
        # ~$3-8/challenge, far under these), keeping the comparison apples-to-apples.
        "timeout_minutes": 120 if scan == "delta" else 240,
        "budget_limit": 150.0 if scan == "delta" else 400.0,
        "concurrency": 1,
        "enable_static_analysis": True,
        "docker_image": f"aixcc-afc/{project}:latest",
        "prebuilt_fuzzers": {harness: binary},
        "prebuild_dir": graph_dir,
        "work_id": ch,
        "fuzzer_sources": {harness: hsrc},
        "model_profile": "period-correct",
    }

    if scan == "delta":
        gt = d["ground_truth_functions"][0]
        delta, base = find_delta(repo, ch, gt)
        if not (delta and base):
            problems.append(f"{tag}: could not find vuln commit for {gt}"); continue
        task["base_commit"] = base
        task["delta_commit"] = delta

    fp = OUT / f"{tag}.json"
    fp.write_text(json.dumps(task, indent=2))
    built.append((comp_of(ch), tag, ch, scan, harness, project))

# --- report ---
built.sort()
print(f"built {len(built)} task JSONs in {OUT}")
for comp in ("pre-competition", "final-competition", "??"):
    sub = [b for b in built if b[0] == comp]
    if not sub:
        continue
    print(f"\n=== {comp}: {len(sub)} ===")
    for _, tag, ch, scan, h, proj in sub:
        print(f"  {tag:42} scan={scan:5} proj={proj:12} harness={h}")

pre = sorted(b[1] for b in built if b[0] == "pre-competition")
cu = sorted(b[1] for b in built if b[1].startswith("cu-"))
union = sorted(set(pre) | set(cu))
print(f"\n=== groupings ===")
print(f"  pre-competition : {len(pre)}")
print(f"  cu (all)        : {len(cu)}")
print(f"  UNION pre ∪ cu  : {len(union)}  <- the target sweep set")
(OUT / "_group_pre.txt").write_text("\n".join(pre) + "\n")
(OUT / "_group_cu.txt").write_text("\n".join(cu) + "\n")
(OUT / "_group_union.txt").write_text("\n".join(union) + "\n")
print(f"  wrote _group_pre.txt / _group_cu.txt / _group_union.txt to {OUT}")

if problems:
    print(f"\nPROBLEMS ({len(problems)}):")
    for x in problems:
        print("  ", x)
else:
    print("\nPROBLEMS: none")
