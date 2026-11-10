"""One FBv3 run: preflight, then the stages, then the result.

    discovery -> harness -> directed

Everything a run produces lives under one directory: the store
(``fbv3.sqlite`` + ``events.jsonl``), one workspace per logic group, every
agent session's prompts / trajectory / tool calls, and ``result.json``.

A run always leaves a ``result.json`` behind -- on success, on a crash, and on
Ctrl-C -- and always removes the containers it labelled.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from fbv3 import report
from fbv3.config import Prebuilt, Task
from fbv3.directed.loop import DirectedRun, LogicGroup
from fbv3.harness.integrate import IntegrateStage
from fbv3.harness.pipeline import HarnessStage
from fbv3.runtime import auth
from fbv3.runtime.pool import AgentPool
from fbv3.sandbox import docker, image
from fbv3.sandbox.workspace import Workspace
from fbv3.store import Store

logger = logging.getLogger(__name__)


class PreflightError(RuntimeError):
    pass


@dataclass
class Preflight:
    ok: bool
    checks: list[tuple[str, bool, str]]

    def text(self) -> str:
        return "\n".join(f"  [{'ok ' if good else 'FAIL'}] {name}: {detail}"
                         for name, good, detail in self.checks)


def preflight(task: Task, *, build_image: bool = True) -> Preflight:
    """Everything that must hold before a run spends an agent session."""
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, fn) -> None:
        try:
            checks.append((name, True, fn() or "ok"))
        except Exception as exc:  # noqa: BLE001 -- every failure is reported, none raises
            checks.append((name, False, f"{type(exc).__name__}: {exc}"))

    def docker_ok() -> str:
        proc = docker.run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=60)
        if proc.returncode != 0:
            raise PreflightError(proc.stderr.decode()[-200:] or "docker is not usable")
        return "server " + proc.stdout.decode().strip()

    check("docker", docker_ok)
    if "integrate" in task.stages:
        def tree_ok() -> str:
            p = Path(task.source_dir)
            if not p.is_dir():
                raise PreflightError(f"source_dir {p} is not a directory")
            n = sum(1 for _ in p.rglob("*.c")) + sum(1 for _ in p.rglob("*.cc")) \
                + sum(1 for _ in p.rglob("*.cpp")) + sum(1 for _ in p.rglob("*.cxx"))
            if n == 0:
                raise PreflightError(f"{p} holds no C/C++ sources")
            return f"{p} ({n} C/C++ source files)"

        check("source tree", tree_ok)
    images = [("builder image", task.builder_image), ("runner image", task.runner_image)]
    if "integrate" in task.stages:
        images.append(("toolchain image", task.integrate.base_image))
    for name, tag in images:
        if not tag:
            continue
        check(name, lambda t=tag: f"{t} present" if docker.image_exists(t)
              else (_ for _ in ()).throw(PreflightError(f"{t} is not pulled: docker pull {t}")))
    if build_image:
        check("workspace image", lambda: image.ensure_image())
    for backend, line in sorted(_logins(task).items()):
        checks.append((f"{backend} login", line[0], line[1]))
    for p in task.prebuilt:
        check(f"prebuilt {p.name}", lambda p=p: _check_prebuilt(p))
    return Preflight(all(good for _, good, _ in checks), checks)


def _logins(task: Task) -> dict[str, tuple[bool, str]]:
    out: dict[str, tuple[bool, str]] = {}
    for backend in sorted(task.backends_used()):
        try:
            out[backend] = (True, auth.CHECKS[backend]())
        except Exception as exc:  # noqa: BLE001
            out[backend] = (False, str(exc))
    return out


def _check_prebuilt(p: Prebuilt) -> str:
    out = Path(p.asan_out)
    if not (out / p.binary).is_file():
        raise PreflightError(f"{out / p.binary} does not exist")
    if p.source_dir and not Path(p.source_dir).is_dir():
        raise PreflightError(f"source_dir {p.source_dir} does not exist")
    missing = [s for s in p.harness_sources if not Path(s).is_file()]
    if missing:
        raise PreflightError(f"harness source(s) not found: {missing}")
    return f"{p.binary} ok"


class Runner:
    def __init__(self, task: Task, *, out_dir: Path | None = None):
        self.task = task
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.run_dir = Path(out_dir or task.output or f"runs/{task.name}-{stamp}").resolve()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.run_dir)
        self.pool = AgentPool(task.agents, self.store)
        self.stop = threading.Event()
        self.run_id = ""
        self.shared: Workspace | None = None
        self._t0 = time.monotonic()
        self._groups: list[dict] = []
        self._stages: list[str] = []

    # -- plumbing ---------------------------------------------------------------------

    def _handle_signals(self) -> None:
        def handler(signum, _frame):
            logger.warning("signal %s: stopping; the result will still be written", signum)
            self.stop.set()
            self.pool.stopped.set()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, handler)
            except ValueError:
                pass  # not the main thread (embedded use): the caller owns the signals

    def _source(self) -> Path:
        """The project source every agent reads, on the host."""
        assert self.shared is not None
        src_dir = Path(self.task.source_dir) if self.task.source_dir else None
        if src_dir is None:
            src_dir = next((Path(p.source_dir) for p in self.task.prebuilt if p.source_dir), None)
        if src_dir is not None:
            from fbv3.directed.loop import link_tree

            link_tree(src_dir, self.shared.path("src"))
        elif self.task.builder_image:
            self.shared.extract_source(self.task.builder_image)
        return self.shared.path("src")

    def _ws_image_for(self, ws_image: str) -> str:
        """Agents work in the image their commands have to run in.

        A plain source tree is explored and built in the toolchain image, which
        has clang and the OSS-Fuzz conventions; otherwise the small analysis
        image is enough.
        """
        if "integrate" in self.task.stages:
            return self.task.integrate.base_image
        return ws_image

    def _logic_groups(self, harnesses) -> list[LogicGroup]:
        groups: list[LogicGroup] = []
        want = self.task.directed.sanitizer
        for h in harnesses:
            if not h.usable:
                continue
            san = want if want in h.builds else "address"
            if san != want:
                logger.warning("%s has no %s build, so the directed stage fuzzes the address one",
                               h.target, want)
            groups.append(LogicGroup(
                name=h.target, binary=h.binary, asan_out=Path(h.builds[san]),
                coverage_out=Path(h.builds["coverage"]) if "coverage" in h.builds else None,
                harness_sources=[Path(h.source_path)] if h.source_path else [],
                description=h.notes, sanitizer=san))
        for p in self.task.prebuilt:
            groups.append(LogicGroup(
                name=p.name, binary=p.binary, asan_out=Path(p.asan_out),
                coverage_out=Path(p.coverage_out) if p.coverage_out else None,
                harness_sources=[Path(s) for s in p.harness_sources],
                description=p.description, entries=tuple(p.entries), sanitizer=p.sanitizer))
        return groups

    # -- the run -----------------------------------------------------------------------

    def run(self) -> dict:
        task = self.task
        self.run_id = self.store.start_run(task.name, task.to_dict())
        self._handle_signals()
        status, end_reason, error = "completed", "", ""
        logger.info("run %s in %s", self.run_id[:12], self.run_dir)
        try:
            ws_image = image.ensure_image(self.run_dir / "logs" / "ws_image_build.log")
            self.shared = Workspace(root=self.run_dir / "shared", run_id=self.run_id).layout()
            src = self._source()
            # llvm-cov and llvm-symbolizer must match the clang that built the
            # targets, and they come out of that image. An integrated tree has
            # no project image, so they come from the toolchain image instead:
            # without them the directed stage loses its function index, both
            # from coverage and from the symbol fallback, and says so only in a
            # warning while appearing to run normally.
            tools_image = task.builder_image or (
                task.integrate.base_image if "integrate" in task.stages else "")
            llvm = self.shared.extract_llvm_tools(tools_image) if tools_image else None
            harnesses = []
            integration = None
            needs_container = bool({"integrate", "discovery", "harness"} & set(task.stages))
            if needs_container:
                # The exploration container matches the build: an agent told the
                # build may fetch must be able to try that while exploring.
                self.shared.start(self._ws_image_for(ws_image), memory_mb=task.limits.ws_memory_mb,
                                  cpus=task.limits.ws_cpus, pids=task.limits.ws_pids,
                                  network=("integrate" in task.stages
                                           and task.integrate.allow_network))
                targets = list(task.targets)
                if "integrate" in task.stages and not self.stop.is_set():
                    self._stages.append("integrate")
                    integration = IntegrateStage(task, self.store, self.pool, self.shared,
                                                 run_id=self.run_id, run_dir=self.run_dir).run(
                        targets[0] if targets else None)
                    if not integration.usable:
                        end_reason = "the source tree could not be made to build a fuzz target"
                        logger.error("%s", end_reason)
                        integration = None
                    else:
                        logger.info("integrated: %s via %s", integration.binary,
                                    integration.harness_path)
                        harnesses = [integration]
                stage = HarnessStage(task, self.store, self.pool, self.shared,
                                     run_id=self.run_id, run_dir=self.run_dir,
                                     integration=integration)
                if "discovery" in task.stages and not targets:
                    self._stages.append("discovery")
                    targets = stage.discover()
                    logger.info("discovery proposed: %s", ", ".join(t.function for t in targets) or "(none)")
                if "harness" in task.stages and targets and not self.stop.is_set() and (
                        integration is not None or task.builder_image):
                    self._stages.append("harness")
                    improved = stage.run(targets)
                    harnesses = [h for h in improved if h.usable] or harnesses
                    for h in harnesses:
                        logger.info("harness %s: %s (%s)", h.target, h.status, h.binary or "no binary")
                self.shared.stop()
            if "directed" in task.stages and not self.stop.is_set():
                self._stages.append("directed")
                groups = self._logic_groups(harnesses)
                if not groups:
                    end_reason = "no usable fuzz target for the directed stage"
                for lg in groups:
                    if self.stop.is_set():
                        end_reason = "stopped"
                        break
                    logger.info("directed stage on %s (%s)", lg.name, lg.binary)
                    directed = DirectedRun(
                        task, lg, self.store, self.pool, run_id=self.run_id,
                        lg_root=self.run_dir / "lg" / lg.name, ws_image=ws_image,
                        runner_image=task.runner_image or task.builder_image, src_dir=src,
                        llvm_dir=llvm, stop=self.stop)
                    self._groups.append(directed.run())
            if self.stop.is_set():
                status, end_reason = "cancelled", end_reason or "stopped by a signal"
        except Exception as exc:  # noqa: BLE001 -- recorded, then re-raised after the result
            status, error = "error", f"{type(exc).__name__}: {exc}"
            logger.exception("run failed")
        finally:
            summary = self._finish(status, end_reason, error)
        return summary

    def _finish(self, status: str, end_reason: str, error: str) -> dict:
        try:
            if self.shared is not None:
                self.shared.stop()
        except Exception:  # noqa: BLE001
            pass
        docker.kill_run_containers(self.run_id)
        self.store.end_run(status, end_reason, error)
        pocs = report.package(self.store, self.run_dir)
        summary = report.summarize(self.store, status=status, end_reason=end_reason, stages=self._stages,
                                   logic_groups=self._groups, elapsed_s=time.monotonic() - self._t0)
        summary["error"] = error
        summary["packaged"] = pocs
        summary["run_dir"] = str(self.run_dir)
        report.write_result(summary, self.run_dir)
        self.store.close()
        return summary
