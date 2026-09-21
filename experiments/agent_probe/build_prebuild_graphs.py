# SPDX-License-Identifier: Apache-2.0
"""
Prepare prebuild graph directories for all 57 known bugs, in the exact contract
`import_from_prebuild()` expects: <prebuild_root>/<challenge>/mongodb/{functions.json,
callgraph.json}. fb-graphs already emits these files in the right shape (task_id
prefix "prebuild_<challenge>", all required fields), so we symlink them (3.4 GB
total -- no point duplicating a stable source) and write a manifest mapping each
bug to its {work_id, prebuild_dir, harness}.

Run:  python experiments/agent_probe/build_prebuild_graphs.py
Then a run imports a graph with:
  python -m fuzzingbrain.main --prebuild-dir <dir> --work-id <challenge> --enable-static-analysis ...
"""
from __future__ import annotations
import json, glob, os, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPECS = HERE / "sp_specs"
ROOT = HERE / "prebuild"                       # output root (preserved with the experiment)


def _graph_dir(challenge_build: Path, harness: str) -> Path | None:
    """The fb-graphs graph dir for a specific harness. fb-graphs keeps one
    `graph-<harness>` per harness (full name, including any '@fuzztest' suffix)."""
    for cand in (f"graph-{harness}", f"graph-{harness.split('@')[0]}"):
        d = challenge_build / cand
        if d.is_dir():
            return d
    return None


def _safe(name: str) -> str:
    return name.replace("/", "_")


def main():
    # Rebuild from scratch: the previous per-challenge layout used the wrong
    # graph for multi-harness challenges. Key correctly by (challenge, harness).
    import shutil
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir(parents=True)

    bugs = []
    for p in sorted(SPECS.glob("*.json")):
        d = json.loads(p.read_text())
        bugs.append((d["tag"], d["challenge"], d["harness"], Path(d["callgraph"])))

    prepared, problems = {}, []      # (challenge, harness) -> info
    manifest = []
    for tag, challenge, harness, cg_path in bugs:
        challenge_build = cg_path.parent.parent          # .../build/<challenge>
        gdir = _graph_dir(challenge_build, harness)
        key = f"{challenge}::{harness}"
        pdir = ROOT / challenge / _safe(harness)
        if key not in prepared:
            info = {"prebuild_dir": str(pdir), "work_id": challenge,
                    "harness": harness, "graph_dir": str(gdir) if gdir else None,
                    "valid": False, "functions": None, "callgraph_nodes": None}
            if gdir is None:
                problems.append(f"{key}: no graph-<harness> dir under {challenge_build}")
            else:
                md = pdir / "mongodb"
                md.mkdir(parents=True, exist_ok=True)
                for fn in ("functions.json", "callgraph.json"):
                    dst = md / fn
                    if dst.is_symlink() or dst.exists():
                        dst.unlink()
                    dst.symlink_to(gdir / fn)
                try:
                    cg = json.loads((md / "callgraph.json").read_text())
                    fns = json.loads((md / "functions.json").read_text())
                    tid = cg[0].get("task_id", "")
                    if tid != f"prebuild_{challenge}":
                        problems.append(f"{key}: task_id {tid!r} != prebuild_{challenge!r}")
                    else:
                        info.update(valid=True, functions=len(fns),
                                    callgraph_nodes=len(cg))
                except Exception as e:
                    problems.append(f"{key}: {type(e).__name__}: {e}")
            prepared[key] = info
        manifest.append({"bug": tag, "challenge": challenge, "harness": harness,
                         "work_id": challenge, "prebuild_dir": str(pdir),
                         "graph_dir": prepared[key]["graph_dir"],
                         "valid": prepared[key]["valid"]})

    (ROOT / "manifest.json").write_text(json.dumps(
        {"graphs": prepared, "bugs": manifest}, indent=2, ensure_ascii=False))

    nvalid = sum(1 for v in prepared.values() if v["valid"])
    print(f"prepared {len(prepared)} (challenge,harness) graphs ({nvalid} valid) "
          f"for {len(bugs)} bugs across {len({b[1] for b in bugs})} challenges")
    bad = [m["bug"] for m in manifest if not m["valid"]]
    print(f"bugs without a valid graph ({len(bad)}): {bad}")
    if problems:
        print("PROBLEMS:", *problems, sep="\n  ")
    print(f"manifest: {ROOT/'manifest.json'}")


if __name__ == "__main__":
    main()
