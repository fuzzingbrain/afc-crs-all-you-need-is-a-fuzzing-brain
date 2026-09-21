# SPDX-License-Identifier: Apache-2.0
"""
Clone challenge source trees and generate probe specs.

Reads the cleanly-scorable delta bugs (delta scan_mode, SHA base_ref, non-empty
patch_functions) from the examples/ bug bundles, clones each unique repo once
(blobless partial clone — small, any commit checkoutable), adds a git worktree
per challenge checked out at its delta_ref (the vulnerable state), generates the
base..delta diff, and writes a probe spec per bug.

No LLM, no agents — pure data prep. Run the probe afterwards on the written specs.

Layout produced (all git-ignored):
    _repos/<repo_name>/            one blobless clone per repo
    _work/<challenge>/repo/         worktree at delta_ref (source_root)
    _work/<challenge>/diff/ref.diff base..delta diff (for get_diff)
    challenges/<challenge>__<bug>.json   the spec
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPOS = HERE / "_repos"
WORK = HERE / "_work"
SPECS = HERE / "challenges"
SHA = re.compile(r"^[0-9a-f]{40}$")


def sh(args, cwd=None, timeout=1200, check=True):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"cmd failed ({r.returncode}): {' '.join(args)}\n{r.stderr[-800:]}")
    return r


def repo_name(url: str) -> str:
    return url.rstrip("/").split("/")[-1].removesuffix(".git")


def select_bugs():
    sel = []
    for bugjson in HERE.parent.parent.glob("examples/aixcc-challenges/*/*/*/bugs/*/bug.json"):
        chdir = bugjson.parents[2]
        manifest = chdir / "manifest.json"
        if not manifest.exists():
            continue
        m = json.loads(manifest.read_text())
        bug = json.loads(bugjson.read_text())
        langd = m.get("language")
        lang = (list(langd.values())[0] if isinstance(langd, dict) and langd else "")
        if lang.lower() not in ("c", "c++", "cpp"):
            continue
        cons = bug.get("consistency", {}) or {}
        fns = cons.get("patch_functions") or []
        base = m.get("base_ref")
        delta = m.get("delta_ref")
        if m.get("scan_mode") != "delta" or not fns or not (base and SHA.match(base)):
            continue
        harness = bug.get("harness") or ""
        fuzzer = harness.split("@", 1)[0] if harness else (m.get("oss_fuzz_projects") or [""])[0]
        sel.append({
            "challenge": m.get("challenge"),
            "bug": bug.get("bug"),
            "repo": (m.get("source") or {}).get("repo"),
            "base": base,
            "delta": delta,
            "fuzzer": fuzzer,
            "patch_functions": fns,
            "crash_type": cons.get("crash_type"),
        })
    return sel


def ensure_repo(url: str) -> Path:
    dest = REPOS / repo_name(url)
    if (dest / ".git").exists() or (dest / "HEAD").exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[clone] {url} -> {dest}")
    sh(["git", "clone", "--filter=blob:none", "--no-checkout", url, str(dest)], timeout=1800)
    return dest


def ensure_worktree(repo: Path, s: dict) -> Path:
    wt = WORK / s["challenge"] / "repo"
    if (wt / ".git").exists():
        return wt
    wt.parent.mkdir(parents=True, exist_ok=True)
    local = f"probe/{s['challenge']}"
    # Bring the base commit (for the diff) and the delta branch into a deterministic
    # local ref — no --depth, so base..delta diff has the history it needs. The
    # worktree is checked out at the DELTA state (the code containing the bug).
    sh(["git", "fetch", "origin", s["base"]], cwd=repo, timeout=1800, check=False)
    sh(["git", "fetch", "origin", f"{s['delta']}:{local}"], cwd=repo, timeout=1800)
    sh(["git", "worktree", "add", "--detach", str(wt), local], cwd=repo, timeout=900)
    return wt


def write_diff(repo: Path, wt: Path, s: dict) -> Path:
    diff_dir = WORK / s["challenge"] / "diff"
    diff_dir.mkdir(parents=True, exist_ok=True)
    diff_path = diff_dir / "ref.diff"
    r = sh(["git", "-C", str(wt), "diff", s["base"], "HEAD"], timeout=600, check=False)
    diff_path.write_text(r.stdout)
    return diff_path


def main():
    sel = select_bugs()
    print(f"[plan] {len(sel)} bugs across {len({s['repo'] for s in sel})} repos")
    SPECS.mkdir(parents=True, exist_ok=True)
    done, failed = [], []
    # Clone each repo once.
    repos = {}
    for url in sorted({s["repo"] for s in sel}):
        try:
            repos[url] = ensure_repo(url)
        except Exception as e:
            print(f"[clone FAIL] {url}: {e}")
    for s in sel:
        tag = f"{s['challenge']}__{s['bug']}"
        try:
            repo = repos.get(s["repo"])
            if repo is None:
                failed.append((tag, "repo clone failed")); continue
            wt = ensure_worktree(repo, s)
            if not (wt / ".git").exists():
                failed.append((tag, "worktree failed")); continue
            write_diff(repo, wt, s)
            spec = {
                "challenge": tag,
                "source_root": str(wt),
                "workspace": str(wt.parent),
                "repo_subdir": "repo",
                "diff_filename": "diff/ref.diff",
                "fuzzer": s["fuzzer"],
                "sanitizer": "address",
                "scan_mode": "delta",
                "changed_functions": s["patch_functions"],
                "ground_truth_functions": s["patch_functions"],
                "crash_type": s["crash_type"],
            }
            (SPECS / f"{tag}.json").write_text(json.dumps(spec, indent=2))
            nfiles = sum(1 for _ in wt.rglob("*.c")) + sum(1 for _ in wt.rglob("*.h"))
            print(f"[ok] {tag:28} fuzzer={s['fuzzer'][:20]:20} fns={s['patch_functions']} (.c/.h={nfiles})")
            done.append(tag)
        except Exception as e:
            print(f"[FAIL] {tag}: {e}")
            failed.append((tag, str(e)[:120]))
    print(f"\n[done] specs written: {len(done)} | failed: {len(failed)}")
    for tag, why in failed:
        print(f"   FAIL {tag}: {why}")


if __name__ == "__main__":
    main()
