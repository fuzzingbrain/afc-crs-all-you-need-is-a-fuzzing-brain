"""Directed seed generation for one logic group (one harness): FBv2, light and agentic.

    seed agent -> global fuzzer
    mapper -> finder (per function) -> verifier -+-> PoC agent -> shared PoC fuzzer
                                                 +-> fp-seed agent -> global corpus
    breaker (frontier) -> global corpus
    coverage refresh -> newly covered functions -> finder

* Two fuzzers run for the whole stage: the global one (fed by the seed agent,
  the breaker and the fp seeds) and one shared PoC fuzzer (fed by every PoC
  candidate, so it mutates around all of them). A crash monitor reproduces,
  signs and de-duplicates whatever they find.
* The function queue is the mapper's ranked list, then A: the functions the
  coverage build shows executed, refreshed every ``coverage_interval_s`` as the
  breaker and the fuzzers open up new ground.
* Bug-lane priority: verify and PoC before new finders, fp seeds last. One
  breaker lane keeps growing A. Every session goes through the AgentPool, so
  ``agents.max_sessions`` bounds the whole stage.
* VH lifecycle is FBv2's: pending_verify -> verifying -> rejected | pending_poc
  -> generating_poc -> poc_generated | poc_failed.
* A PoC agent's "crashed" counts only once the orchestrator has reproduced the
  crash itself, in the runner image, through the same crash monitor as the
  fuzzers: an agent cannot promote its own VH.
"""

from __future__ import annotations

import json
import logging
import queue
import shutil
import subprocess
import threading
import time
import zipfile
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from fbv3 import prompts
from fbv3.config import Task
from fbv3.fuzz import coverage, symbols
from fbv3.fuzz.fuzzer import CrashMonitor, Fuzzer, FuzzerSpec, is_afl_target
from fbv3.harness.smoke import parse_stats
from fbv3.runtime.pool import AgentPool
from fbv3.sandbox.workspace import Workspace, copy_runtime_bundle

logger = logging.getLogger(__name__)

PRIO_VERIFY, PRIO_POC, PRIO_FINDER, PRIO_FP = 0, 0, 1, 2
SAMPLE_S = 15.0
FN_SAMPLE_S = 120.0


@dataclass
class LogicGroup:
    """One harness to work on: what the harness stage produced, or a prebuilt."""

    name: str  # slug; the store's `lg`
    binary: str
    asan_out: Path
    coverage_out: Path | None = None
    harness_sources: list[Path] = field(default_factory=list)
    description: str = ""
    entries: tuple[str, ...] = ()
    sanitizer: str = "address"
    seed_corpus_zip: Path | None = None
    dict_file: str = ""  # container path under /out

    def names(self) -> list[str]:
        """Names that belong to the harness itself, not the library (for signatures)."""
        return list(dict.fromkeys([self.binary, *[p.stem for p in self.harness_sources]]))


def _jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def link_tree(src: Path, dst: Path) -> None:
    """``dst`` as a hard-linked copy of ``src`` (same filesystem), else a real copy.

    The project source is read-only for the agents and can be several GB, so
    each logic group's workspace links it instead of copying it.
    """
    if dst.is_dir() and any(dst.iterdir()):
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(dst, ignore_errors=True)
    if subprocess.run(["cp", "-al", str(src), str(dst)], capture_output=True).returncode != 0:
        shutil.copytree(src, dst, symlinks=True, ignore_dangling_symlinks=True)


class DirectedRun:
    """The directed stage for one logic group. ``run()`` returns its summary."""

    def __init__(self, task: Task, lg: LogicGroup, store, pool: AgentPool, *, run_id: str,
                 lg_root: Path, ws_image: str, runner_image: str, src_dir: Path,
                 llvm_dir: Path | None = None, deadline: float | None = None,
                 stop: threading.Event | None = None):
        self.task, self.lg, self.store, self.pool = task, lg, store, pool
        self.cfg = task.directed
        self.run_id, self.runner_image = run_id, runner_image
        self.src_dir, self.llvm_dir = src_dir, llvm_dir
        self.ws = Workspace(root=lg_root.resolve(), run_id=run_id)
        self.ws_image = ws_image
        self.stop_flag = stop or threading.Event()
        self.function_index = self.ws.path("functions/index.json")
        self._deadline = deadline or (time.monotonic() + self.cfg.duration_seconds)
        self._fuzzers: list[Fuzzer] = []
        self._monitor: CrashMonitor | None = None
        self._afl = False
        self._fn_rows: list[coverage.FunctionRow] = []
        self._queued_fns: set[str] = set()
        self._bugq: queue.PriorityQueue = queue.PriorityQueue()
        self._seq = 0
        self._lock = threading.Lock()
        self._stop_threads = threading.Event()
        self._t0 = time.monotonic()
        self._harness_src: dict[str, str] = {}

    # -- time and bookkeeping ----------------------------------------------------------

    def _left(self) -> float:
        if self.stop_flag.is_set():
            return 0.0
        return self._deadline - time.monotonic()

    def _enqueue(self, priority: int, fn, *args) -> None:
        with self._lock:
            self._seq += 1
            self._bugq.put((priority, self._seq, fn, args))

    def _ctx(self, **extra) -> dict:
        return {
            "container": self.ws.container, "ws_root": str(self.ws.root), "run_id": self.run_id,
            "target_bin": "/ws/out/address/" + self.lg.binary,
            "coverage_bin": "/ws/out/coverage/" + self.lg.binary,
            "union_corpus": "/ws/fuzz/global/corpus",
            "function_index": str(self.function_index),
            "harness_names": self.lg.names(), "project": self.task.project,
            "seed_corpus": str(self.ws.path("fuzz/global/corpus")),
            "poc_corpus": str(self.ws.path("fuzz/poc/corpus")),
            **extra,
        }

    def _session(self, role: str, *, system: str, task: str, subject: str = "", **ctx_extra):
        return self.pool.run(role, scope="directed", system=system, task=task,
                             tools=prompts.ROLE_TOOLS[role], ctx=self._ctx(**ctx_extra),
                             session_root=self.ws.path("sessions"),
                             subject=f"{self.lg.name}/{subject}" if subject else self.lg.name,
                             deadline=self._deadline)

    def _prompt(self, role: str, **kw) -> tuple[str, str]:
        return prompts.directed(role, harness_src=self._harness_src, target=self.lg.binary, **kw)

    def _targets_str(self) -> str:
        return ", ".join(self.lg.entries) or self.lg.binary

    def _record_seeds(self, result, role: str) -> int:
        seeds = _jsonl(result.out_dir / "seeds.jsonl") if result.session_id else []
        self.store.add_seeds(self.lg.name, result.session_id, role, seeds)
        return len(seeds)

    # -- setup ----------------------------------------------------------------------------

    def _prepare(self) -> None:
        self.ws.layout()
        for src in self.lg.harness_sources:
            if src.is_file():
                (self.ws.path("harness") / src.name).write_bytes(src.read_bytes())
                self._harness_src[src.name] = src.read_text(errors="replace")
        copy_runtime_bundle(self.lg.asan_out, self.ws.path("out/address"), self.lg.binary)
        if self.lg.coverage_out is not None:
            try:
                copy_runtime_bundle(self.lg.coverage_out, self.ws.path("out/coverage"), self.lg.binary)
            except FileNotFoundError:
                logger.warning("%s: the coverage build has no %s", self.lg.name, self.lg.binary)
        if self.llvm_dir is not None and self.llvm_dir.is_dir():
            dest = self.ws.path("out/llvm")
            dest.mkdir(parents=True, exist_ok=True)
            for tool in self.llvm_dir.iterdir():
                if tool.is_file() and not (dest / tool.name).exists():
                    shutil.copy2(tool, dest / tool.name)
        link_tree(self.src_dir, self.ws.path("src"))
        self._seed_corpus()
        self.ws.start(self.ws_image, memory_mb=self.task.limits.ws_memory_mb,
                      cpus=self.task.limits.ws_cpus, pids=self.task.limits.ws_pids)

    def _seed_corpus(self) -> None:
        """The corpus starts from the project's own seed corpus when it ships one."""
        corpus = self.ws.path("fuzz/global/corpus")
        corpus.mkdir(parents=True, exist_ok=True)
        zip_path = self.lg.seed_corpus_zip or (self.lg.asan_out / f"{self.lg.binary}_seed_corpus.zip")
        if not zip_path.is_file():
            return
        try:
            with zipfile.ZipFile(zip_path) as zf:
                for i, info in enumerate(zf.infolist()):
                    if info.is_dir() or i >= 2000:
                        continue
                    (corpus / f"projseed-{i:05d}").write_bytes(zf.read(info))
        except (zipfile.BadZipFile, OSError) as exc:
            logger.warning("%s: seed corpus %s unreadable: %s", self.lg.name, zip_path, exc)

    def _collect_coverage(self, timeout_s: int = 600) -> tuple[list[coverage.FunctionRow], str]:
        if not (self.ws.path("out/coverage") / self.lg.binary).is_file():
            return [], "no coverage build"
        return coverage.collect_functions(
            self.ws, coverage_binary="/ws/out/coverage/" + self.lg.binary,
            corpus_dir="/ws/fuzz/global/corpus", timeout_s=timeout_s)

    def _build_function_index(self) -> dict:
        rows, err = self._collect_coverage(timeout_s=self.task.agents.roles["mapper"].timeout_s)
        if err:
            # No coverage build (a prebuilt target, or the coverage build failed):
            # fall back to the ASan binary's symbols. Linked, not executed, so
            # there is no A set and the mapper's list drives the queue.
            logger.warning("%s: coverage index unavailable (%s); using the binary's symbols",
                           self.lg.name, err)
            rows, sym_err = symbols.linked_functions(self.ws, binary="/ws/out/address/" + self.lg.binary)
            if sym_err:
                logger.warning("%s: symbol index also unavailable: %s", self.lg.name, sym_err)
            self.store.emit("function_index", lg=self.lg.name, source="symbols", functions=len(rows),
                            coverage_error=err, symbol_error=sym_err or None)
        self._fn_rows = rows
        coverage.write_index(rows, self.function_index)
        return coverage.snapshot(rows, self.ws.path("coverage/snapshot_initial.json"))

    # -- fuzzers ----------------------------------------------------------------------------

    def _spec(self, name: str, fork: int) -> FuzzerSpec:
        return FuzzerSpec(
            name=f"{self.lg.name}-{name}", image=self.runner_image, build_out=self.ws.path("out/address"),
            binary=self.lg.binary, corpus=self.ws.path(f"fuzz/{name}/corpus"),
            crashes=self.ws.path(f"fuzz/{name}/crashes"), fork=fork, rss_limit_mb=self.cfg.rss_limit_mb,
            per_input_timeout_s=self.cfg.per_input_timeout_s,
            engine="afl" if self._afl else "libfuzzer", sanitizer=self.lg.sanitizer,
            memory_mb=self.cfg.fuzzer_memory_mb, cpus=self.cfg.fuzzer_cpus, dict_file=self.lg.dict_file)

    def _start_fuzzers(self) -> None:
        self._afl = is_afl_target(self.ws.path("out/address"), self.lg.binary)
        if self._afl:
            logger.info("%s: %s is an AFL build; driving it with /out/afl-fuzz", self.lg.name, self.lg.binary)
        self._monitor = CrashMonitor(
            lg=self.lg.name, store=self.store, image=self.runner_image,
            build_out=self.ws.path("out/address"), binary=self.lg.binary, harness_names=self.lg.names(),
            save_dir=self.ws.path("crashes"), run_id=self.run_id, afl=self._afl, on_new=self._on_crash)
        glob = Fuzzer(self._spec("global", self.cfg.global_fork), run_id=self.run_id)
        glob.start()
        self._fuzzers.append(glob)
        self._monitor.watch("global", glob.spec.crashes)
        if self.cfg.mode == "directed":
            poc = Fuzzer(self._spec("poc", self.cfg.poc_fork), run_id=self.run_id)
            poc.start()
            self._fuzzers.append(poc)
            self._monitor.watch("poc", poc.spec.crashes)
        self._monitor.start()

    def _on_crash(self, rec: dict) -> None:
        if self.cfg.stop_on_crashes and self._monitor and \
                self._monitor.new_crashes >= self.cfg.stop_on_crashes:
            logger.info("%s: %d distinct crashes found; stopping the stage", self.lg.name,
                        self._monitor.new_crashes)
            self.stop_flag.set()

    def _sampler(self) -> None:
        """Coverage over time, for comparing runs: libFuzzer's own counters often,
        llvm-cov function coverage occasionally (it costs a full corpus replay)."""
        log = self.ws.path("fuzz/global/fuzzer.log")
        corpus = self.ws.path("fuzz/global/corpus")
        last_fn = 0.0
        while not self._stop_threads.wait(SAMPLE_S):
            rec: dict = {}
            try:
                if log.is_file():
                    tail = "\n".join(log.read_text(errors="replace").splitlines()[-200:])
                    rec.update({k: v for k, v in parse_stats(tail, int(SAMPLE_S)).items()
                                if k in ("edges", "features", "exec_s")})
                rec["corpus"] = sum(1 for _ in corpus.iterdir()) if corpus.is_dir() else 0
            except OSError:
                pass
            if time.monotonic() - last_fn > FN_SAMPLE_S:
                rows, err = self._collect_coverage(timeout_s=400)
                if not err:
                    rec["functions_covered"] = sum(1 for r in rows if r.execution_count > 0)
                last_fn = time.monotonic()
            self.store.add_coverage(self.lg.name, round(time.monotonic() - self._t0, 1), **rec)

    # -- phase A: seeds, then the map --------------------------------------------------------

    def _seed_agent(self) -> None:
        system, task = self._prompt("seed", lg=self.lg.name, targets=self._targets_str(),
                                    description=self.lg.description or "(no description given)")
        res = self._session("seed", system=system, task=task, subject="seed")
        self._record_seeds(res, "seed")

    def _mapper(self) -> list[dict]:
        system, task = self._prompt("mapper", lg=self.lg.name, targets=self._targets_str(),
                                    description=self.lg.description or "(no description given)",
                                    max_functions=self.cfg.phase1_max_functions)
        res = self._session("mapper", system=system, task=task, subject="mapper")
        return _jsonl(res.out_dir / "functions.jsonl") if res.session_id else []

    def _fill_queue(self, mapped: list[dict]) -> None:
        """The mapper's ranked list first, then A (executed functions), most used first."""
        for fn in mapped:
            if fn["name"] not in self._queued_fns:
                self._queued_fns.add(fn["name"])
                self._enqueue(PRIO_FINDER, self._finder, fn)
        self._queue_covered()

    def _queue_covered(self, reason: str = "covered by the fuzzer") -> int:
        added = 0
        for row in sorted(self._fn_rows, key=lambda r: -r.execution_count):
            if row.execution_count <= 0 or row.name in self._queued_fns:
                continue
            if len(self._queued_fns) >= self.cfg.max_functions:
                break
            self._queued_fns.add(row.name)
            self._enqueue(PRIO_FINDER, self._finder,
                          {"name": row.name, "file": row.file, "start_line": row.start_line,
                           "end_line": row.end_line, "reason": reason})
            added += 1
        return added

    def _coverage_refresh(self) -> None:
        while not self._stop_threads.wait(self.cfg.coverage_interval_s):
            if self._left() < 200:
                return
            rows, err = self._collect_coverage()
            if err:
                continue
            self._fn_rows = rows
            coverage.write_index(rows, self.function_index)
            added = self._queue_covered("newly covered")
            if added:
                logger.info("%s: %d newly covered functions queued", self.lg.name, added)
                self.store.emit("coverage_refresh", lg=self.lg.name, new_functions=added,
                                covered=sum(1 for r in rows if r.execution_count > 0))

    # -- the bug lane ---------------------------------------------------------------------

    def _finder(self, fn: dict) -> None:
        if self._left() < 120:
            return
        system, task = self._prompt(
            "finder", name=fn["name"], file=fn.get("file", ""), start=fn.get("start_line", 0),
            end=fn.get("end_line", 0), call_path=fn.get("call_path") or "(from coverage)",
            reason=fn.get("reason") or "(covered)")
        res = self._session("finder", system=system, task=task, subject=fn["name"], function=fn)
        for raw in _jsonl(res.out_dir / "vhs.jsonl") if res.session_id else []:
            score = float(raw.get("finder_score", 0.5))
            vh_id = self.store.create_vh(
                self.lg.name, function_name=raw.get("function_name") or fn["name"],
                function_file=raw.get("function_file") or fn.get("file", ""),
                description=raw.get("description", ""), finder_score=score,
                important_controlflow=raw.get("important_controlflow", ""),
                sink_code=raw.get("sink_code", ""), sink_line=raw.get("sink_line", 0),
                finder_session=res.session_id)
            if score < self.cfg.verify_threshold:
                self.store.move_vh(vh_id, "rejected", session=res.session_id,
                                   reason=f"finder score {score} below the verify threshold")
                continue
            self._enqueue(PRIO_VERIFY, self._verify, vh_id)

    def _verify(self, vh_id: str) -> None:
        if self._left() < 120:
            return
        vh = self.store.get_vh(vh_id)
        if not self.store.move_vh(vh_id, "verifying", frm=("pending_verify",), reason="verifier started"):
            return
        system, task = self._prompt(
            "verifier", function_name=vh["function_name"], function_file=vh["function_file"],
            description=vh["description"], controlflow=vh["important_controlflow"] or "(none given)",
            finder_score=vh["finder_score"], sink_code=vh["sink_code"] or "(not given)",
            sink_line=vh["sink_line"])
        res = self._session("verifier", system=system, task=task, subject=vh["function_name"], vh_id=vh_id)
        verdict = _json(res.out_dir / "verdict.json") if res.session_id else {}
        score = float(verdict.get("score", 0.0))
        self.store.update_vh(
            vh_id, verifier_session=res.session_id, score=score, evidence=verdict.get("evidence", ""),
            verification_notes=verdict.get("verification_notes", ""),
            poc_guidance=verdict.get("poc_guidance", ""),
            description=verdict.get("description") or vh["description"],
            important_controlflow=verdict.get("important_controlflow") or vh["important_controlflow"])
        if not verdict:
            self.store.move_vh(vh_id, "rejected", session=res.session_id,
                               reason=f"the verifier submitted no verdict (session {res.status})")
            return
        if score >= self.cfg.poc_threshold:
            self.store.move_vh(vh_id, "pending_poc", session=res.session_id, reason=f"verifier score {score}")
            self._enqueue(PRIO_POC, self._poc, vh_id, 0)
        else:
            self.store.move_vh(vh_id, "rejected", session=res.session_id,
                               reason=f"verifier score {score} below the PoC threshold")
            self._enqueue(PRIO_FP, self._fp_seed, vh_id)

    def _poc(self, vh_id: str, attempt: int) -> None:
        if self._left() < 150:
            self.store.move_vh(vh_id, "poc_failed", frm=("pending_poc", "generating_poc"),
                               reason="out of time before the PoC attempt")
            return
        vh = self.store.get_vh(vh_id)
        if attempt == 0:
            self.store.move_vh(vh_id, "generating_poc", frm=("pending_poc",), reason="PoC agent started")
        pocs_dir = self.ws.path(f"state/vh/{vh_id}/pocs")
        pocs_dir.mkdir(parents=True, exist_ok=True)
        previous = ""
        if attempt:
            previous = (f"\n## Earlier attempt\nAttempt {attempt} did not produce this VH's crash. Try a "
                        "different shape of input, and use reach_probe to see where it stops.\n")
        system, task = self._prompt(
            "poc", function_name=vh["function_name"], function_file=vh["function_file"],
            description=vh["description"], controlflow=vh["important_controlflow"] or "(none)",
            evidence=vh["evidence"] or "(none)", poc_guidance=vh["poc_guidance"] or "(none)",
            previous=previous)
        res = self._session("poc", system=system, task=task, subject=vh["function_name"], vh_id=vh_id,
                            pocs_dir=str(pocs_dir))
        self.store.update_vh(vh_id, poc_sessions=[*vh["poc_sessions"], res.session_id])
        crash = self._confirm_poc(vh_id, res, pocs_dir)
        if crash is not None:
            self.store.update_vh(vh_id, poc_status="crashed", poc_blob=crash["artifact"],
                                 crash_id=crash["crash_id"])
            self.store.move_vh(vh_id, "poc_generated", session=res.session_id,
                               reason=f"reproduced {crash['signature']}: {crash['describe']}")
            return
        if attempt + 1 < self.cfg.max_poc_attempts and self._left() > 200 and not self.stop_flag.is_set():
            self._enqueue(PRIO_POC, self._poc, vh_id, attempt + 1)
        else:
            self.store.move_vh(vh_id, "poc_failed", frm=("generating_poc", "pending_poc"),
                               session=res.session_id, reason="PoC attempts exhausted")

    def _confirm_poc(self, vh_id: str, res, pocs_dir: Path) -> dict | None:
        """Reproduce the agent's candidates ourselves; the agent's claim alone is not a PoC.

        Every candidate is checked, not only the one it submitted, and the
        submitted blob first: a session that ran out of turns after crashing
        still produced a PoC.
        """
        if self._monitor is None or not res.session_id:
            return None
        claimed = _json(res.out_dir / "poc_result.json").get("blob", "")
        blobs: list[Path] = []
        for name in [claimed] + sorted(str(p) for p in pocs_dir.glob("*.bin")):
            if not name:
                continue
            p = Path(name)
            if not p.is_absolute():
                p = pocs_dir / p.name
            elif str(p).startswith("/ws/"):
                p = self.ws.to_host(str(p))
            if p.is_file() and p not in blobs:
                blobs.append(p)
        for blob in blobs[:12]:
            rec = self._monitor.handle("poc_agent", blob, vh_id=vh_id)
            if rec is not None:
                return rec
        return None

    def _fp_seed(self, vh_id: str) -> None:
        if self._left() < 120 or not self.cfg.mode == "directed":
            return
        vh = self.store.get_vh(vh_id)
        system, task = self._prompt(
            "fp_seed", function_name=vh["function_name"], description=vh["description"],
            controlflow=vh["important_controlflow"] or "(none)",
            notes=vh["verification_notes"] or "(none)", evidence=vh["evidence"] or "(none)")
        res = self._session("fp_seed", system=system, task=task, subject=vh["function_name"], vh_id=vh_id)
        self.store.update_vh(vh_id, fp_seed_session=res.session_id)
        self._record_seeds(res, "fp_seed")

    def _breaker(self) -> None:
        if self._left() < 200:
            return
        system, task = self._prompt("breaker", lg=self.lg.name, targets=self._targets_str(),
                                    description=self.lg.description or "(no description given)")
        res = self._session("breaker", system=system, task=task, subject="breaker")
        self._record_seeds(res, "breaker")

    # -- the scheduler -------------------------------------------------------------------

    def _schedule(self) -> None:
        """One pool, two lanes. The frontier lane keeps a breaker running to grow A;
        the bug lane drains the priority queue under a per-role cap, so verify and
        PoC never starve behind a crowd of finders (and the reverse)."""
        slots = {"finder": max(1, self.cfg.finder_slots), "verifier": max(1, self.cfg.verifier_slots),
                 "poc": max(1, self.cfg.poc_slots), "fp_seed": max(1, self.cfg.fp_seed_slots)}
        sem = {r: threading.Semaphore(n) for r, n in slots.items()}
        role_of = {self._finder: "finder", self._verify: "verifier", self._poc: "poc",
                   self._fp_seed: "fp_seed"}
        breaker_slots = 1 if self.cfg.breaker else 0
        breaker_sem = threading.Semaphore(max(breaker_slots, 1))
        pool = ThreadPoolExecutor(max_workers=sum(slots.values()) + max(breaker_slots, 1),
                                  thread_name_prefix=f"fbv3-{self.lg.name}")
        refresh = threading.Thread(target=self._coverage_refresh, daemon=True,
                                   name=f"cov-{self.lg.name}")
        refresh.start()
        rounds, inflight = 0, set()

        def done(fut: Future, release) -> None:
            release()
            if fut.exception() is not None:
                logger.warning("%s: task failed: %s", self.lg.name, fut.exception())

        try:
            while self._left() > 150:
                if breaker_slots and (self.cfg.breaker_max_rounds == 0
                                      or rounds < self.cfg.breaker_max_rounds):
                    if breaker_sem.acquire(blocking=False):
                        if self._left() > 200:
                            fut = pool.submit(self._breaker)
                            fut.add_done_callback(lambda f: done(f, breaker_sem.release))
                            inflight.add(fut)
                            rounds += 1
                        else:
                            breaker_sem.release()
                progressed, deferred = False, []
                while True:
                    try:
                        item = self._bugq.get_nowait()
                    except queue.Empty:
                        break
                    _, _, fn, args = item
                    role = role_of.get(fn, "finder")
                    if sem[role].acquire(blocking=False):
                        fut = pool.submit(fn, *args)
                        fut.add_done_callback(lambda f, r=role: done(f, sem[r].release))
                        inflight.add(fut)
                        progressed = True
                    else:
                        deferred.append(item)
                for item in deferred:
                    self._bugq.put(item)
                inflight = {f for f in inflight if not f.done()}
                if not progressed:
                    time.sleep(2.0)
            self._stop_threads.set()
            for fut in list(inflight):  # let what is in flight finish its current step
                try:
                    fut.result(timeout=max(1.0, self._left() + 300))
                except Exception as exc:  # noqa: BLE001
                    logger.warning("%s: task failed while draining: %s", self.lg.name, exc)
        finally:
            self._stop_threads.set()
            pool.shutdown(wait=False, cancel_futures=True)

    # -- run ------------------------------------------------------------------------------

    def run(self) -> dict:
        summary = {"lg": self.lg.name, "binary": self.lg.binary, "mode": self.cfg.mode,
                   "root": str(self.ws.root)}
        sampler = None
        try:
            self._prepare()
            summary["coverage_initial"] = self._build_function_index()
            if self.cfg.mode in ("directed", "legacy"):
                self._seed_agent()
            self._start_fuzzers()
            sampler = threading.Thread(target=self._sampler, daemon=True, name=f"sample-{self.lg.name}")
            sampler.start()
            if self.cfg.mode == "directed":
                self._fill_queue(self._mapper())
                summary["functions_queued_initially"] = len(self._queued_fns)
                self._schedule()
            else:
                while self._left() > 5:  # baseline / legacy: just let the fuzzer work
                    time.sleep(min(30.0, max(1.0, self._left())))
        finally:
            summary.update(self._finish())
        return summary

    def _finish(self) -> dict:
        self._stop_threads.set()
        for fuzzer in self._fuzzers:
            try:
                fuzzer.stop()
            except Exception as exc:  # noqa: BLE001
                logger.warning("%s: stopping fuzzer %s: %s", self.lg.name, fuzzer.spec.name, exc)
        if self._monitor is not None:
            self._monitor.stop()
        rows, err = self._collect_coverage()
        final = {}
        if not err:
            final = coverage.snapshot(rows, self.ws.path("coverage/snapshot_final.json"))
        self.ws.stop()
        vhs = self.store.vhs(self.lg.name)
        crashes = self.store.crashes(self.lg.name)
        report = {
            "functions_analysed": len(self._queued_fns),
            "vhs": len(vhs),
            "vhs_by_status": {s: sum(1 for v in vhs if v["status"] == s) for s in {v["status"] for v in vhs}},
            "pocs": sum(1 for v in vhs if v["poc_status"] == "crashed"),
            "crashes": len(crashes),
            "crash_signatures": [c["signature_short"] for c in crashes],
            "seeds": self.store.seed_count(self.lg.name),
            "coverage_final": final,
            "elapsed_s": round(time.monotonic() - self._t0, 1),
        }
        (self.ws.root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        self.store.emit("lg_finished", lg=self.lg.name, **{k: report[k] for k in
                                                            ("vhs", "pocs", "crashes", "functions_analysed")})
        return report
