# SPDX-License-Identifier: Apache-2.0
"""The two F(MS) strategies: xs0_delta and xs1_c_full, reproduced.

Control flow mirrors FuzzingBrain snapshot 4d7eee6c. Prompts and output helpers
are byte-for-byte (FMS.legacy_funcs); this file is the orchestration the legacy
`main` / `doPoV` / `process_vulnerable_function` performed, with the analysis
service replaced by the prebuilt graph and the 45-min wall clock replaced by the
task budget/deadline.

  delta (xs0_delta): diff -> create_commit_based_prompt -> doPoV loop.
  full  (xs1_c_full): reachable -> rank (score>=5, dedup, first non-empty model)
                      -> per candidate: call path -> doPoV loop.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Callable

import FMS.legacy_funcs as L
from FMS.substrate import Budget, Graph, LLM, Task, run_blob

MAX_ITER_DELTA = 5      # xs0_delta MAX_ITERATIONS (legacy); passes repeat via the outer re-run loop
MAX_ITER_FULL = 3       # xs1_c_full main override (legacy); passes repeat via the outer re-run loop
MAX_BLOBS = 6           # x.bin, x1.bin .. x5.bin
CHUNK = 100
RANK_MODELS = ["o3", "gpt-4.1"]              # period-correct; legacy [o3,opus-4,3.7,sonnet-4]


# --------------------------------------------------------------------------- #
# Generated-code execution -> blob files (legacy run_python_code)
# --------------------------------------------------------------------------- #
def _extract_python(text: str) -> str | None:
    m = re.search(r"```(?:python)?\s*([\s\S]*?)```", text)
    return m.group(1).strip() if m else None


def _run_python(code: str, xbin_dir: Path) -> tuple[bool, str]:
    """Run generated code; success iff it wrote x.bin..x5.bin. Legacy semantics."""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
        tmp = f.name
    try:
        r = subprocess.run(["python3", tmp], cwd=str(xbin_dir),
                           capture_output=True, text=True, timeout=30)
        for i in range(MAX_BLOBS):
            name = "x.bin" if i == 0 else f"x{i}.bin"
            if (xbin_dir / name).exists():
                return True, r.stderr or ""
        return False, r.stderr or ""
    except subprocess.TimeoutExpired:
        return False, "Execution timed out"
    except Exception as e:  # noqa: BLE001
        return False, str(e)
    finally:
        os.unlink(tmp)


def _blobs(xbin_dir: Path) -> list[Path]:
    out = []
    for i in range(MAX_BLOBS):
        p = xbin_dir / ("x.bin" if i == 0 else f"x{i}.bin")
        if p.exists():
            out.append(p)
    return out




class Run:
    """One strategy run against one task; records outcome + PoV artifacts."""

    def __init__(self, task: Task, llm: LLM, out_dir: Path, log: Callable[[str], None]):
        self.task = task
        self.llm = llm
        self.out = out_dir
        self.log = log
        self.system = L.SYSTEM_PROMPT_FULL  # identical to delta's
        self.povs: list[dict] = []
        self.xp0 = out_dir / "xp0"
        self.xp0.mkdir(parents=True, exist_ok=True)
        # Non-crashing blobs are dropped here for the background fuzzer to pick up
        # (legacy <fuzzer>_seed_corpus). Set by run_delta / run_full.
        self.corpus = (out_dir / "corpus").resolve()
        self.corpus.mkdir(parents=True, exist_ok=True)
        self.bg = None   # background fuzzer; set by run.py so the strategy stops
                         # when a POV already exists (legacy has_successful_pov).

    def _pov_exists(self) -> bool:
        """A POV has been found by this strategy or the background fuzzer -- the
        legacy has_successful_pov check (glob of successful_povs* / the POV dir)."""
        return bool(self.povs) or bool(self.bg and self.bg.povs)

    # ---- doPoV loop (legacy doPoV / doPoV_full) -------------------------- #
    def do_pov(self, initial_msg: str, max_iter: int) -> bool:
        pov_id = uuid.uuid4().hex[:8]
        found = False
        for model in self.llm.POV_MODELS:
            if self.llm.budget.over():
                break
            messages = [{"role": "system", "content": self.system},
                        {"role": "user", "content": initial_msg}]
            model_success = 0
            fails = 0
            for it in range(1, max_iter + 1):
                if self.llm.budget.over():
                    break
                if self._pov_exists():
                    return True
                text, ok = self.llm(messages, model)
                if not ok:
                    # Transient API error/rate-limit: back off so one blip does not
                    # burn the whole candidate/iteration budget in seconds.
                    fails += 1
                    if fails >= 6:
                        self.log("too many consecutive LLM failures; abandoning this target")
                        return found
                    time.sleep(min(30, 5 * fails))
                    continue
                fails = 0
                low = text.lower()
                if any(p in low for p in ("cannot comply", "can't comply",
                                          "against my", "ethical guidelines")):
                    self.log(f"refusal {model} it{it}")
                    continue
                messages.append({"role": "assistant", "content": text})
                code = _extract_python(text)
                if not code:
                    messages.append({"role": "user",
                                     "content": "Python code failed to create x.bin, please try again."})
                    continue
                work = self.xp0 / uuid.uuid4().hex[:8]
                work.mkdir(parents=True, exist_ok=True)
                ok2, err = _run_python(code, work)
                if not ok2:
                    messages.append({"role": "user",
                                     "content": f"Python code failed with error: {err}\n\nPlease try again."})
                    continue
                crashed, fout = False, ""
                for blob in _blobs(work)[:MAX_BLOBS]:
                    crashed, fout = run_blob(self.task, str(blob), self.log)
                    fout = L.filter_instrumented_lines(fout)
                    if crashed:
                        self._save_pov(pov_id, model, it, code, blob, fout)
                        break
                    # feed the non-crashing input to the background fuzzer
                    try:
                        (self.corpus / f"seed_{uuid.uuid4().hex[:8]}.bin").write_bytes(blob.read_bytes())
                    except OSError:
                        pass
                if crashed:
                    found = True
                    model_success += 1
                    messages.append({"role": "user", "content":
                        "Great job! You've successfully triggered the vulnerability. "
                        "Now create a different test case that triggers a different code "
                        "path. Please provide a new Python script that creates a different x.bin file."})
                    if model_success >= 1:
                        break
                else:
                    if it == 1:
                        msg = (f"Fuzzer output:\n{L.truncate_output(fout, 200)}\n\n"
                               "The test case did not trigger the vulnerability. Please "
                               "analyze the fuzzer output and try again with an improved "
                               "approach. Consider: 1. Different input formats 2. Edge "
                               "cases 3. The modified functions 4. Details 5. Step by step")
                    else:
                        msg = (f"Fuzzer output:\n{L.truncate_output(fout, 200)}\n\n"
                               "The test case did not trigger the vulnerability. Please "
                               "try again with a different approach.")
                    if it == max_iter - 1:
                        msg += ("\nThis is your last attempt. This task is very very "
                                "important to me. If you generate a successful blob, I "
                                "will tip you 2000 dollars.")
                    messages.append({"role": "user", "content": msg})
            if model_success >= 1:
                break
        return found

    def _save_pov(self, pov_id, model, it, code, blob, fout):
        d = self.out / "successful_povs"
        d.mkdir(parents=True, exist_ok=True)
        crash = L.extract_crash_output(fout)
        (d / f"pov_{pov_id}_{model}_{it}.py").write_text(code)
        (d / f"test_blob_{pov_id}_{model}_{it}.bin").write_bytes(Path(blob).read_bytes())
        (d / f"fuzzer_output_{pov_id}_{model}_{it}.txt").write_text(crash)
        meta = {"model": model, "iteration": it, "fuzzer_name": self.task.fuzzer,
                "sanitizer": self.task.sanitizer, "project_name": self.task.project}
        (d / f"pov_metadata_{pov_id}_{model}_{it}.json").write_text(json.dumps(meta, indent=2))
        self.povs.append(meta)
        self.log(f"POV SUCCESS {model} it{it}")


# --------------------------------------------------------------------------- #
# delta
# --------------------------------------------------------------------------- #
def run_delta(task: Task, llm: LLM, out_dir: Path, log: Callable[[str], None], bg=None) -> dict:
    run = Run(task, llm, out_dir, log)
    run.bg = bg
    diff = task.diff()
    if len(diff) > 50000:
        diff = L.process_large_diff(diff, None)
    prompt = L.create_commit_based_prompt(task.harness_src, diff, task.sanitizer, "c")
    # Re-run the strategy pass until a PoV is found or budget/time runs out, so
    # F(MS) uses the same budget ZBH does. Each pass is a fresh doPoV (new
    # conversation; temperature 1.0 gives variation). A pass that finds a crash
    # stops immediately (do_pov returns at the first PoV / has_successful_pov).
    passes = 0
    while not run._pov_exists() and not llm.budget.over():
        passes += 1
        run.do_pov(prompt, MAX_ITER_DELTA)
    log(f"delta passes={passes}")
    return {"strategy": "xs0_delta", "povs": run.povs,
            "diff_bytes": len(task.diff()), "passes": passes}


# --------------------------------------------------------------------------- #
# full
# --------------------------------------------------------------------------- #
def _rank(g: Graph, reachable: list[dict], llm: LLM, log) -> list[dict]:
    models, seen_m = [], set()
    for m in RANK_MODELS:
        if m not in seen_m:
            models.append(m)
            seen_m.add(m)
    for model in models:
        if llm.budget.over():
            return []
        picked: dict[str, dict] = {}
        for i in range(0, len(reachable), CHUNK):
            chunk = [c for c in reachable[i:i + CHUNK]
                     if not any(x in (c.get("FilePath", "") or "").lower()
                                for x in ("fuzz", "/test", "tests/"))]
            if not chunk:
                continue
            top_k = max(1, min(5, len(chunk) // 10))
            vulns = L.find_most_likely_vulnerable_functions(None, chunk, "c", model, top_k)
            for v in vulns:
                try:
                    if float(v.get("score", 0)) >= 5:
                        n = (v.get("name") or v.get("Name") or "").strip()
                        if n:
                            picked.setdefault(n, v)
                except (TypeError, ValueError):
                    pass
            if len(picked) >= top_k * 10:
                break
        if picked:
            log(f"ranked by {model}: {len(picked)}")
            return list(picked.values())
    return []


def run_full(task: Task, llm: LLM, out_dir: Path, log: Callable[[str], None], bg=None) -> dict:
    run = Run(task, llm, out_dir, log)
    run.bg = bg
    g = Graph(task)
    reachable = g.reachable()
    log(f"reachable={len(reachable)}")
    ranked = _rank(g, reachable, llm, log)
    if not ranked:
        return {"strategy": "xs1_c_full", "ranked": 0, "povs": []}
    reachable_vul = L.extract_vulnerable_functions(reachable, ranked, limit=10)
    log(f"candidates={len(reachable_vul)}")
    # Legacy runs candidates in a pool and terminates on the first success OR when
    # len<=10 (i.e. after the first candidate). We run sequentially, same effect:
    # stop at the first candidate that produces a PoV, or after processing the set.
    # Re-run the candidate sweep until a PoV or budget/time runs out, so F(MS)
    # uses the same budget ZBH does; each sweep re-processes all candidates with
    # fresh conversations. Stop at the first PoV.
    passes = 0
    while not run._pov_exists() and not llm.budget.over():
        passes += 1
        for vf in reachable_vul:
            if llm.budget.over() or run._pov_exists():
                break
            name = (vf.get("name") or vf.get("Name") or "").strip()
            path = g.call_path(name)
            cp_prompt = L.create_call_path_info_prompt(path, "c")
            body = g.body(name)
            single = [{"name": name, "body": body,
                       "score": vf.get("score"), "reason": vf.get("reason", "")}]
            initial = L.create_full_scan_prompt(task.harness_src, task.sanitizer, "c",
                                                cp_prompt, single, single)
            if run.do_pov(initial, MAX_ITER_FULL):
                break
    log(f"full passes={passes}")
    return {"strategy": "xs1_c_full", "ranked": len(ranked), "povs": run.povs,
            "passes": passes}
