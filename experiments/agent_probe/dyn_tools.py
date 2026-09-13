# SPDX-License-Identifier: Apache-2.0
"""
Deterministic evidence tools for the evidence-verifier, backed by the fb-graphs
build (source + built ASan binary + call graph + corpus, all per challenge).

Three deterministic capabilities the current verifier lacks:
  - reachability(func)  : from the real call graph (callgraph.json, incl. indirect edges)
  - gdb_reach(input, target) : run the built ASan binary under gdb 15 in a container,
                               break at target func/line, report hit + crash + ASan type
  - crash(input)        : run the built ASan binary, report crash + type (subset of gdb_reach)

Assets live under fb-graphs/build/<challenge>/:
  repo/                                     source tree
  graph-<harness>/callgraph.json,functions.json
  bugs/<bug>/bin/address/<elf>              built ASan binary (+ @-wrapper, + corpus/)
  bugs/<bug>/blob                           reference crash input (the "answer" — avoid feeding it)

No LLM here. The gdb runner image `gdbx-u24` (base-runner ubuntu-24 + gdb 15) is
built on first use; binaries are standalone (only standard libs), so one image
serves every challenge.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

GRAPHS = Path("/home/ze/fb-graphs/build")
GDB_IMAGE = "gdbx-u24"
_ASAN_TYPE = re.compile(r"AddressSanitizer:\s*([\w-]+)")


def _sh(args, timeout=300):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def ensure_gdb_image() -> bool:
    """Build the gdb-15 runner image once (base-runner ubuntu-24 + gdb)."""
    r = _sh(["docker", "image", "inspect", GDB_IMAGE], timeout=30)
    if r.returncode == 0:
        return True
    dockerfile = (
        "FROM gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04\n"
        "RUN apt-get update -qq && apt-get install -y -qq gdb >/dev/null 2>&1 || true\n"
    )
    r = subprocess.run(
        ["docker", "build", "-q", "-t", GDB_IMAGE, "-f", "-", "."],
        input=dockerfile, capture_output=True, text=True, timeout=600,
    )
    return r.returncode == 0


class ChallengeAssets:
    """Locate the fb-graphs assets for one (challenge, bug)."""

    def __init__(self, challenge: str, bug: str, harness: str):
        self.challenge = challenge
        self.bug = bug
        self.harness = harness  # e.g. "avif_fuzztest_yuvrgb@YuvRgbFuzzTest.Convert"
        self.root = GRAPHS / challenge
        self.bug_dir = self.root / "bugs" / bug
        # fuzztest harness "bin@Suite.Test" -> elf "bin", fuzz "Suite.Test"
        if "@" in harness:
            self.elf, self.fuzztest = harness.split("@", 1)
        else:
            self.elf, self.fuzztest = harness, None
        self.bin_dir = self.bug_dir / "bin" / "address"
        self.corpus_dir = self.bin_dir / "corpus"
        self.blob = self.bug_dir / "blob"
        self.repo = self.root / "repo"
        self.graph_dir = self.root / f"graph-{harness}"

    def exists(self) -> bool:
        return (self.bin_dir / self.elf).exists() and self.graph_dir.exists()

    def run_argv(self, input_in_container: str) -> List[str]:
        """Argv to run the ELF on one input (fuzztest vs libFuzzer shape)."""
        binp = f"/b/{self.elf}"
        if self.fuzztest:
            return [binp, f"--fuzz={self.fuzztest}", "--stack_limit_kb=512", "--", input_in_container]
        return [binp, input_in_container]

    def corpus_seeds(self, limit: int = 0) -> List[Path]:
        if not self.corpus_dir.is_dir():
            return []
        seeds = sorted(p for p in self.corpus_dir.iterdir() if p.is_file())
        return seeds[:limit] if limit else seeds


# ---- reachability (deterministic, from the real call graph) --------------

def reachability(assets: ChallengeAssets, func: str) -> Dict[str, Any]:
    cg = assets.graph_dir / "callgraph.json"
    if not cg.exists():
        return {"reachable": None, "note": "no callgraph.json"}
    try:
        nodes = json.loads(cg.read_text())
    except Exception as e:
        return {"reachable": None, "note": f"callgraph parse error: {e}"}
    for n in nodes:
        if n.get("function_name") == func:
            return {
                "reachable": True,
                "call_depth": n.get("call_depth"),
                "reached_via": n.get("reached_via"),
                "n_callers": len(n.get("callers", [])),
            }
    return {"reachable": False, "note": "not in fuzzer call graph"}


# ---- dynamic gdb reach + crash (deterministic) ---------------------------

def gdb_reach(
    assets: ChallengeAssets,
    input_path: Path,
    target: str,
    timeout: int = 120,
) -> Dict[str, Any]:
    """Run the ASan binary on `input_path` under gdb, break at `target`
    (a function name or "file.c:LINE"), report reach + crash + ASan type.

    Deterministic: no LLM. Returns {hit, crashed, asan_type, breakpoint_bound}.
    """
    import shutil, tempfile

    work = Path(tempfile.mkdtemp(prefix="gdbreach_"))
    try:
        # stage the whole bin/address dir (elf + wrapper + corpus) + the input
        for p in assets.bin_dir.iterdir():
            if p.is_file():
                shutil.copy(p, work / p.name)
        shutil.copy(input_path, work / "the_input")
        script = "\n".join([
            "set pagination off", "set confirm off",
            f"break {target}",
            "commands", "  silent", '  printf ">>>HIT<<<\\n"', "  continue", "end",
            "run", "quit", "",
        ])
        (work / "probe.gdb").write_text(script)
        argv = assets.run_argv("/b/the_input")
        cmd = [
            "docker", "run", "--rm", "--cap-add=SYS_PTRACE",
            "--security-opt", "seccomp=unconfined",
            "--memory=4096m", "--memory-swap=4096m", "--cpus=1", "--pids-limit=512",
            "-v", f"{work}:/b",
            "-e", "ASAN_OPTIONS=abort_on_error=1:detect_leaks=0",
            GDB_IMAGE, "bash", "-c",
            f"chmod +x /b/{assets.elf}; gdb -batch -x /b/probe.gdb --args " + " ".join(argv),
        ]
        r = _sh(cmd, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        m = _ASAN_TYPE.search(out)
        return {
            "hit": ">>>HIT<<<" in out,
            "crashed": bool(m) or "SUMMARY: AddressSanitizer" in out
                       or bool(re.search(r"received signal SIG(SEGV|ABRT|BUS|FPE|ILL)", out)),
            "asan_type": m.group(1) if m else None,
            "breakpoint_bound": bool(re.search(r"Breakpoint \d+ at", out))
                or "reached" not in out.lower(),
            "raw_tail": out[-600:],
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def ensure_gdb_image_for(project: str) -> str:
    """Build gdb-<project>-fixed FROM the project image aixcc-afc/<project> (which
    carries the fuzzer binary's shared libs) + gdb. Generic base-runner lacks the
    project libs (libssl, libnghttp2, ...), so per-project is required. Returns the
    image tag; falls back to GDB_IMAGE if the build fails."""
    tag = f"gdb-{project}-fixed"
    r = _sh(["docker", "image", "inspect", tag], timeout=30)
    if r.returncode == 0:
        return tag
    dockerfile = (
        f"FROM aixcc-afc/{project}:latest\n"
        "RUN apt-get update -qq && apt-get install -y -qq gdb >/dev/null 2>&1 || true\n"
    )
    r = subprocess.run(["docker", "build", "-q", "-t", tag, "-f", "-", "."],
                       input=dockerfile, capture_output=True, text=True, timeout=600)
    return tag if r.returncode == 0 else GDB_IMAGE
