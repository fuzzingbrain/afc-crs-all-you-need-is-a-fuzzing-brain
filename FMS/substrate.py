# SPDX-License-Identifier: Apache-2.0
"""Substrate for the F(MS) baseline: task, graph, fuzzer runner, LLM client.

F(MS) reproduces FuzzingBrain's two main C strategies (xs1_c_full, xs0_delta,
snapshot 4d7eee6c) as standalone scripts. The strategy *logic and prompts* are
the legacy ones (FMS/legacy_funcs.py). This module supplies what the legacy
scripts got from the competition infrastructure, but without building or static
analysis: prebuilt fuzzers and a pre-computed call graph from the artifact.

  - Task:  resolve an artifact task JSON ($ARTIFACT paths), harness source, diff.
  - Graph: reachable functions and per-target call paths from the prebuilt
           functions.json / callgraph.json (no analysis service).
  - Fuzzer: run a prebuilt binary on one blob in Docker; crash decision uses the
            legacy crash-indicator list (legacy_funcs is byte-for-byte).
  - LLM:   period-correct models (o3 + gpt-4.1), with cost tracking and budget.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

# Reuse FBv2's docker plumbing so prebuilt binaries that need $ORIGIN / vendored
# libs (systemd, binutils) load. This is infrastructure, not strategy.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fuzzingbrain.core.fuzzer_spec import (  # noqa: E402
    is_no_oom,
    libfuzzer_oom_flags,
    run_lib_docker_args,
    NO_OOM_MEMORY_MB,
)
from fuzzingbrain.core.docker_limits import docker_resource_args  # noqa: E402

ARTIFACT_ROOT = Path(__file__).resolve().parent.parent / "artifact"
DIFF_CACHE = Path(__file__).resolve().parent / "cache" / "diffs"

# Legacy crash indicators, copied verbatim (xs0_delta.py:1558 / xs1_c_full.py).
CRASH_INDICATORS = [
    "ERROR: AddressSanitizer:",
    "ERROR: MemorySanitizer:",
    "WARNING: MemorySanitizer:",
    "ERROR: ThreadSanitizer:",
    "ERROR: UndefinedBehaviorSanitizer:",
    "SEGV on unknown address",
    "Segmentation fault",
    "runtime error:",
    "AddressSanitizer: heap-buffer-overflow",
    "AddressSanitizer: heap-use-after-free",
    "UndefinedBehaviorSanitizer: undefined-behavior",
    "AddressSanitizer:DEADLYSIGNAL",
    "Java Exception: com.code_intelligence.jazzer",
    "ERROR: HWAddressSanitizer:",
    "WARNING: ThreadSanitizer:",
    "libfuzzer exit=1",
]


def _resolve(v: Any) -> Any:
    if isinstance(v, str):
        return v.replace("$ARTIFACT", str(ARTIFACT_ROOT))
    if isinstance(v, list):
        return [_resolve(x) for x in v]
    if isinstance(v, dict):
        return {k: _resolve(x) for k, x in v.items()}
    return v


@dataclass
class Task:
    tid: str                 # work_id, e.g. cu-delta-02
    mode: str                # "delta" | "full"
    project: str             # project_name, e.g. curl
    fuzzer: str              # harness name, e.g. curl_fuzzer_ws
    sanitizer: str
    docker_image: str
    fuzzer_path: Path        # prebuilt binary
    graph_dir: Path          # .../mongodb with functions.json + callgraph.json
    harness_src: str         # concatenated fuzzer_sources
    focus: str               # project_src_dir basename stem = project
    pov_count: int = 1        # distinct-bug target (stop rule), from the task

    @classmethod
    def load(cls, task_json: str | Path) -> "Task":
        t = _resolve(json.load(open(task_json)))
        fuzzer = t["fuzzers"][0]
        san = (t.get("sanitizers") or ["address"])[0]
        harness = ""
        for p in t.get("fuzzer_sources", {}).get(fuzzer, []):
            try:
                harness += Path(p).read_text(errors="replace") + "\n"
            except OSError:
                pass
        return cls(
            tid=t["work_id"],
            mode=t["scan_mode"],
            project=t["project_name"],
            fuzzer=fuzzer,
            sanitizer=san,
            docker_image=t["docker_image"],
            fuzzer_path=Path(t["prebuilt_fuzzers"][fuzzer]),
            graph_dir=Path(t["prebuild_dir"]) / "mongodb",
            harness_src=harness,
            focus=t["project_name"],
            pov_count=int(t.get("pov_count", 1) or 1),
        )

    def diff(self) -> str:
        p = DIFF_CACHE / f"{self.tid}.diff"
        return p.read_text(errors="replace") if p.exists() else ""


class Graph:
    """Reachable functions and call paths from the prebuilt call graph.

    Replaces the legacy analysis service. `reachable()` returns records shaped
    like the service's /v1/reachable response (Name/FilePath/SourceCode plus the
    lower-case aliases the legacy code also reads). `call_path()` returns the
    node list create_call_path_info_prompt expects (function/file/is_modified).
    """

    def __init__(self, task: Task):
        fj = json.load(open(task.graph_dir / "functions.json"))
        cj = json.load(open(task.graph_dir / "callgraph.json"))
        self._funcs = {f["name"]: f for f in fj}
        self._nodes = {n["function_name"]: n for n in cj}
        # Reachable = every function that appears as a call-graph node (the graph
        # is already the fuzzer-rooted reachable set).
        self._reachable_names = list(self._nodes.keys())

    def reachable(self) -> list[dict]:
        out = []
        for name in self._reachable_names:
            f = self._funcs.get(name)
            if not f:
                continue
            fp = f.get("file_path", "")
            out.append({
                "Name": name, "name": name,
                "FilePath": fp, "file": fp, "file_path": fp,
                "StartLine": f.get("start_line"), "start_line": f.get("start_line"),
                "EndLine": f.get("end_line"),
                "SourceCode": f.get("content", ""),
                "body": f.get("content", ""),
            })
        return out

    def body(self, name: str) -> str:
        f = self._funcs.get(name)
        return f.get("content", "") if f else ""

    def file_of(self, name: str) -> str:
        f = self._funcs.get(name)
        return f.get("file_path", "") if f else ""

    def call_path(self, target: str) -> list[dict]:
        """One path fuzzer-entry -> target, walking callers up from the target.

        The legacy service returns full call paths; here we reconstruct a single
        caller chain from the graph (enough for create_call_path_info_prompt,
        which only shows names/files/modified-flags). Entry is
        LLVMFuzzerTestOneInput; if no chain is found, just [entry, target].
        """
        entry = "LLVMFuzzerTestOneInput"
        chain, cur, seen = [target], target, {target}
        while cur != entry and len(chain) < 12:
            node = self._nodes.get(cur)
            callers = (node.get("callers") if node else None) or []
            nxt = next((c for c in callers if c not in seen), None)
            if nxt is None:
                break
            chain.append(nxt)
            seen.add(nxt)
            cur = nxt
        if chain[-1] != entry:
            chain.append(entry)
        chain.reverse()
        return [{"function": n, "file": self.file_of(n), "is_modified": False}
                for n in chain]


# --------------------------------------------------------------------------- #
# Fuzzer runner (prebuilt binary, Docker, legacy crash decision)
# --------------------------------------------------------------------------- #
def run_blob(task: Task, blob_path: str, log: Callable[[str], None]) -> tuple[bool, str]:
    """Run the prebuilt fuzzer on one blob. Returns (crashed, combined_output)."""
    fuzzer_dir = task.fuzzer_path.parent
    no_oom = is_no_oom(task.fuzzer)
    mem = NO_OOM_MEMORY_MB if no_oom else 4096
    vendor_args, ld = run_lib_docker_args(fuzzer_dir, "/out")
    stage = Path("/tmp") / f"fms_{uuid.uuid4().hex[:8]}"
    stage.mkdir(parents=True, exist_ok=True)
    shutil.copy(blob_path, stage / "x.bin")
    cmd = [
        "docker", "run", "--rm", "--platform", "linux/amd64",
        *docker_resource_args(memory_mb=mem, cpus=1),
        "-e", "FUZZING_ENGINE=libfuzzer",
        "-e", f"SANITIZER={task.sanitizer}",
        "-e", "ARCHITECTURE=x86_64",
        "-e", f"PROJECT_NAME={task.project}",
        "-e", "ASAN_OPTIONS=detect_leaks=0",
        *(["-e", f"LD_LIBRARY_PATH={ld}"] if ld else []),
        *vendor_args,
        "-v", f"{fuzzer_dir}:/out:ro",
        "-v", f"{stage}:/work",
        task.docker_image,
        f"/out/{task.fuzzer}",
        *libfuzzer_oom_flags(no_oom),
        "-timeout=30", "-timeout_exitcode=99", "-rss_limit_mb=0",
        "/work/x.bin",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        out = (r.stderr or "") + "\n" + (r.stdout or "")
        rc = r.returncode
    except subprocess.TimeoutExpired:
        return False, "Execution timed out"
    except Exception as e:  # noqa: BLE001
        return False, str(e)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    # Legacy crash decision (xs0_delta.py:run_fuzzer_with_input).
    if rc == 0 and "ABORTING" not in out:
        return False, out
    if rc != 0 or "ABORTING" in out:
        if any(ind in out for ind in CRASH_INDICATORS):
            return True, out
    return False, out


# --------------------------------------------------------------------------- #
# LLM client (period-correct models, cost + budget)
# --------------------------------------------------------------------------- #
@dataclass
class Budget:
    dollars: float
    deadline: float                     # epoch seconds
    spent: float = 0.0
    calls: int = 0

    def remaining_seconds(self) -> float:
        return self.deadline - time.time()

    def over(self) -> bool:
        return self.spent >= self.dollars or self.remaining_seconds() <= 0


class LLM:
    """Thin LLM client over FBv2's client, returning legacy (text, ok)."""

    # Period-correct mapping (paper: F(MS) and ZBH use the same models).
    RANK_MODELS = ["o3", "gpt-4.1"]
    POV_MODELS = ["gpt-4.1", "o3"]

    def __init__(self, budget: Budget, log: Callable[[str], None]):
        from fuzzingbrain.llms import LLMClient
        self._c = LLMClient()
        self.budget = budget
        self.log = log

    def __call__(self, messages: list[dict], model_name: str) -> tuple[str, bool]:
        if self.budget.over():
            return "", False
        try:
            resp = self._c.call(messages, model=model_name, temperature=1.0,
                                 max_tokens=8192, timeout=900)
        except Exception as e:  # noqa: BLE001
            self.log(f"llm error {model_name}: {str(e)[:160]}")
            return "", False
        cost = getattr(resp, "cost", 0.0) or 0.0
        self.budget.spent += cost
        self.budget.calls += 1
        return (resp.content or ""), bool(resp.content)


def bind_legacy(llm: LLM, log: Callable[[str], None]) -> None:
    """Wire legacy_funcs' log_message/call_llm to this run."""
    import FMS.legacy_funcs as L
    L._LLM = lambda messages, model: llm(messages, model)
    L._LOG = log


# --------------------------------------------------------------------------- #
# Background fuzzer (the legacy parallel libFuzzer path)
# --------------------------------------------------------------------------- #
class BackgroundFuzzer:
    """A libFuzzer campaign on the prebuilt binary, run alongside the strategy.

    Mirrors the legacy CRS's parallel libFuzzer that consumed the seed corpus the
    strategies dropped into ``<fuzzer>_seed_corpus``. Same Docker plumbing and
    crash indicators as run_blob. Crashes are picked up by a poller thread, each
    re-run once to capture a clean sanitizer report, and recorded as fuzzer PoVs.
    """

    def __init__(self, task: "Task", corpus_dir: Path, out_dir: Path,
                 log: Callable[[str], None]):
        self.task = task
        self.corpus = corpus_dir
        self.crashes = out_dir / "fuzzer_crashes"
        self.out = out_dir
        self.log = log
        self.corpus.mkdir(parents=True, exist_ok=True)
        self.crashes.mkdir(parents=True, exist_ok=True)
        self.proc: Optional[subprocess.Popen] = None
        self.name = f"fms_fuzz_{uuid.uuid4().hex[:8]}"
        self._seen: set[str] = set()
        self._stop = False
        self._thread = None
        self.povs: list[dict] = []
        self._sigs: set[str] = set()

    def _cmd(self) -> list[str]:
        fuzzer_dir = self.task.fuzzer_path.parent
        no_oom = is_no_oom(self.task.fuzzer)
        mem = NO_OOM_MEMORY_MB if no_oom else 4096
        vendor_args, ld = run_lib_docker_args(fuzzer_dir, "/fuzzers")
        return [
            "docker", "run", "--rm", "--name", self.name,
            "--platform", "linux/amd64",
            *docker_resource_args(memory_mb=mem, cpus=6),
            "-e", "FUZZING_ENGINE=libfuzzer",
            "-e", f"SANITIZER={self.task.sanitizer}",
            "-e", "ARCHITECTURE=x86_64",
            "-e", f"PROJECT_NAME={self.task.project}",
            "-e", "ASAN_OPTIONS=detect_leaks=0",
            *(["-e", f"LD_LIBRARY_PATH={ld}"] if ld else []),
            *vendor_args,
            "-v", f"{fuzzer_dir}:/fuzzers:ro",
            "-v", f"{self.corpus}:/corpus",
            "-v", f"{self.crashes}:/crashes",
            self.task.docker_image,
            f"/fuzzers/{self.task.fuzzer}",
            "/corpus", "-artifact_prefix=/crashes/",
            "-fork=6", "-ignore_crashes=1",
            *(libfuzzer_oom_flags(True) if no_oom else ["-rss_limit_mb=4096"]),
            "-timeout=30",
        ]

    def start(self) -> None:
        import threading
        self.proc = subprocess.Popen(self._cmd(), stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        self.log(f"background fuzzer started ({self.name})")
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()

    def _poll(self) -> None:
        while not self._stop:
            try:
                for f in sorted(self.crashes.iterdir()):
                    if not f.is_file() or f.name in self._seen:
                        continue
                    self._seen.add(f.name)
                    crashed, out = run_blob(self.task, str(f), self.log)
                    if not crashed:
                        continue
                    self._record(f, out)
            except Exception:  # noqa: BLE001
                pass
            time.sleep(10)

    def _record(self, crash_file: Path, out: str) -> None:
        import FMS.legacy_funcs as L
        crash = L.extract_crash_output(out)
        loc = _crash_site(crash)
        if loc in self._sigs:
            return
        self._sigs.add(loc)
        d = self.out / "successful_povs"
        d.mkdir(parents=True, exist_ok=True)
        cid = uuid.uuid4().hex[:8]
        (d / f"pov_{cid}_fuzzer.bin").write_bytes(crash_file.read_bytes())
        (d / f"fuzzer_output_{cid}_fuzzer.txt").write_text(crash)
        meta = {"source": "fuzzer", "fuzzer_name": self.task.fuzzer,
                "sanitizer": self.task.sanitizer, "project_name": self.task.project,
                "site": loc}
        (d / f"pov_metadata_{cid}_fuzzer.json").write_text(json.dumps(meta, indent=2))
        self.povs.append(meta)
        self.log(f"FUZZER POV {loc}")

    def stop(self) -> None:
        self._stop = True
        try:
            subprocess.run(["docker", "kill", self.name],
                          capture_output=True, timeout=30)
        except Exception:  # noqa: BLE001
            pass
        if self.proc:
            try:
                self.proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                self.proc.kill()
        if self._thread:
            self._thread.join(timeout=5)


def _crash_site(crash: str) -> str:
    """A crude crash signature: sanitizer class + first project frame."""
    import re
    cls = ""
    m = re.search(r"(?:ERROR|WARNING): \w*Sanitizer: ([a-z0-9-]+)", crash)
    if m:
        cls = m.group(1)
    fr = re.search(r"#\d+ 0x[0-9a-f]+ in \S+ (/?[^\s:]+:\d+)", crash)
    return f"{cls}@{fr.group(1).split('/')[-1]}" if fr else (cls or "unknown")
