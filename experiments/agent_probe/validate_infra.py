# SPDX-License-Identifier: Apache-2.0
"""
Validate that every one of the 57 bugs can actually get its real infrastructure
for a zero-build pipeline run:
  1. graph      -- prebuild/<challenge>/<harness>/mongodb/{functions,callgraph}.json (valid)
  2. source     -- fb-graphs repo checkout for the challenge
  3. binary     -- an already-built ASan fuzzer binary on disk (for prebuilt_fuzzers)
  4. image      -- the aixcc-afc challenge image (binary is extractable if present)

Prints a per-bug table + a summary of what's ready vs missing.
"""
from __future__ import annotations
import json, glob, os, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPECS = HERE / "sp_specs"
PRE = HERE / "prebuild"


def _docker_images() -> set:
    try:
        out = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                             capture_output=True, text=True, timeout=30).stdout
        return set(l.strip() for l in out.splitlines() if l.strip())
    except Exception:
        return set()


def _find_binary(challenge: str, harness: str, project: str) -> str | None:
    """Search known on-disk locations for a built ASan fuzzer binary."""
    hbase = harness.split("@")[0]
    cands = []
    fbg = Path(f"/home/ze/fb-graphs/build/{challenge}")
    # per-bug extracted bin, whole-challenge out, and workspace copies
    cands += glob.glob(str(fbg / "bugs" / "*" / "bin" / "address" / hbase))
    cands += glob.glob(str(fbg / "**" / "build" / "out" / f"*address*" / hbase), recursive=True)
    cands += glob.glob(str(HERE.parents[1] / "workspace" / f"{project}_*" /
                           "fuzz-tooling" / "build" / "out" / f"{project}_address" / hbase))
    for c in cands:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def main():
    manifest = json.loads((PRE / "manifest.json").read_text())
    valid_graph = {b["bug"]: b["valid"] for b in manifest["bugs"]}
    images = _docker_images()

    rows = []
    for p in sorted(SPECS.glob("*.json")):
        d = json.loads(p.read_text())
        tag, ch, harness = d["tag"], d["challenge"], d["harness"]
        project = d.get("project") or (d.get("challenge_image", "").split("/")[-1].split(":")[0])
        img = d.get("challenge_image", "")
        repo = d.get("source_root", "")
        graph_ok = valid_graph.get(tag, False)
        repo_ok = bool(repo) and os.path.isdir(repo)
        binary = _find_binary(ch, harness, project)
        img_ok = img in images
        rows.append({
            "bug": tag, "challenge": ch, "harness": harness, "project": project,
            "graph": graph_ok, "source": repo_ok,
            "binary": binary, "image": img_ok,
            # aixcc images are BUILDERS (/out empty) -- a missing binary means a
            # one-time compile is still needed; the image is not a shortcut.
            "zero_build_ready": bool(graph_ok and repo_ok and binary),
            "needs_build": bool(graph_ok and repo_ok and not binary),
            "blocked": bool(not (graph_ok and repo_ok and img_ok)),
        })

    print(f"{'bug':40} grph src  binary                 img(builder) STATUS")
    for r in rows:
        b = "on-disk" if r["binary"] else "-"
        st = "ZERO-BUILD" if r["zero_build_ready"] else ("needs-build" if r["needs_build"] else "BLOCKED")
        print(f"{r['bug']:40} {'Y' if r['graph'] else '.':^4}{'Y' if r['source'] else '.':^4}"
              f"{b:22} {'Y' if r['image'] else '.':^6}    {st}")

    ready = [r for r in rows if r["zero_build_ready"]]
    needs = [r for r in rows if r["needs_build"]]
    blocked = [r for r in rows if r["blocked"]]
    print(f"\nsummary of {len(rows)} bugs (graph+source+image all present = infra reachable):")
    print(f"  ZERO-BUILD ready (binary already on disk):        {len(ready)}")
    print(f"  needs one-time build (image is a builder, /out empty): {len(needs)}")
    print(f"  BLOCKED (missing graph/source/image):             {len(blocked)}")
    (PRE / "infra_report.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False))
    print(f"  report: {PRE/'infra_report.json'}")


if __name__ == "__main__":
    main()
