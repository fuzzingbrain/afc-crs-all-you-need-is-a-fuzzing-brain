# SPDX-License-Identifier: Apache-2.0
"""Generate zero-build task JSONs for the AIxCC challenges, github-source format.

Each task: github repo + fuzz-tooling (clone source), the pre-made call graph
imported via prebuild_dir (shared-tree <challenge>/mongodb) + work_id, the pre-built
ASan binary (skip compile) via prebuilt_fuzzers, docker_image=aixcc-afc/<project>
(binary's libs live there), ONE fuzzer per task (multi-fuzzer challenges are split),
concurrency 1, budget 20, model_profile current (all-Claude).

Graphs/binaries/manifests come from the shared challenge tree (read-only):
  /home/ze/afc-crs-all-you-need-is-a-fuzzing-brain/examples/aixcc-challenges
"""
import json, glob, os
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ST = Path("/home/ze/afc-crs-all-you-need-is-a-fuzzing-brain/examples/aixcc-challenges")
PRE = HERE / "prebuild"
OUT = HERE / "tasks"
OUT.mkdir(exist_ok=True)

# group sp_specs by challenge: round, project, scan, {harness: bug}
ch = defaultdict(lambda: {"round": None, "project": None, "scan": None, "hb": {}})
for f in glob.glob(str(HERE / "sp_specs" / "*.json")):
    d = json.load(open(f))
    e = ch[d["challenge"]]
    e["round"] = d.get("round"); e["project"] = d.get("project"); e["scan"] = d.get("scan_mode")
    e["hb"].setdefault(d["harness"], d["bug"])


def chdir_of(c, rnd, scan):
    rd = "pre-competition" if (rnd or "").startswith("pre") else "final-competition"
    p = ST / rd / scan / c
    return p if p.is_dir() else None


def harness_src(c, harness):
    d = PRE / c / harness.replace("/", "_") / "harness_src"
    if d.is_dir():
        return sorted(str(p) for p in d.iterdir() if p.is_file())
    return []


built, problems = [], []
for c in sorted(ch):
    e = ch[c]
    cdir = chdir_of(c, e["round"], e["scan"])
    if not cdir:
        problems.append(f"{c}: challenge dir not found"); continue
    man = json.load(open(cdir / "manifest.json"))
    repo = man.get("source", {}).get("repo")
    tool = man.get("fuzz_tooling", {})
    base_ref = man.get("base_ref")
    delta_ref = man.get("delta_ref")  # branch challenges/<c>
    graph_ok = (cdir / "mongodb" / "callgraph.json").exists()

    for harness, bug in sorted(e["hb"].items()):
        elf = harness.split("@")[0]
        binp = cdir / "bugs" / bug / "bin" / "address" / elf
        tag = f"{c}__{harness.replace('/', '_')}"
        task = {
            "repo_url": repo,
            "project_name": e["project"],
            "task_type": "pov",
            "scan_mode": e["scan"],
            "fuzz_tooling_url": tool.get("repo"),
            "fuzz_tooling_ref": tool.get("ref"),
            "sanitizers": ["address"],
            "fuzzers": [harness],
            "remove_git": True,
            "timeout_minutes": 45,
            "budget_limit": 20.0,
            "concurrency": 1,
            "docker_image": f"aixcc-afc/{e['project']}:latest",
            "prebuilt_fuzzers": {harness: str(binp)},
            "prebuild_dir": str(cdir),
            "work_id": c,
            "model_profile": "current",
            "pov_count": 1,
        }
        if e["scan"] == "delta":
            task["base_commit"] = base_ref
            task["delta_commit"] = delta_ref
        hs = harness_src(c, harness)
        if hs:
            task["fuzzer_sources"] = {harness: hs}
        # validate the local pieces
        if not binp.exists():
            problems.append(f"{tag}: binary missing {binp}")
        if not graph_ok:
            problems.append(f"{tag}: graph missing")
        (OUT / f"{tag}.json").write_text(json.dumps(task, indent=2))
        built.append((tag, e["round"], e["scan"], len(e["hb"]) > 1))

print(f"built {len(built)} task JSONs -> {OUT}")
n_multi = sum(1 for *_, m in built if m)
print(f"  single-fuzzer: {len(built)-n_multi}   multi-fuzzer(split): {n_multi}")
print(f"PROBLEMS ({len(problems)}):")
for p in problems[:30]:
    print("  ", p)
