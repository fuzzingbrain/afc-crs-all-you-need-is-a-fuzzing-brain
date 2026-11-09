"""Teach a plain C/C++ source tree to build a fuzz target.

The harness stage borrows a project's own OSS-Fuzz build. This stage comes
before it and removes that requirement: an agent writes the ``build.sh``
(reusing the project's own integration when the tree has one) plus a first
harness, and what it produces -- a build script, a harness path, an ASan build
and a coverage build -- is exactly what the later stages need. So any source
tree becomes an input, and nothing downstream changes.

The gate is the same idea as the harness stage's, with one addition that
matters more than all the others: **a coverage build must show the project's
own functions**. ``llvm-cov`` reports only the translation units that were
instrumented, so if build.sh compiled the library without ``$CFLAGS`` -- or
linked a system package -- the project's files are simply absent. That build
succeeds, fuzzes fast and finds nothing, which is indistinguishable from a
library with no bugs; it is the one failure this stage must never pass.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from fbv3 import prompts
from fbv3.build.workspace_build import build_workspace
from fbv3.config import Target, Task
from fbv3.fuzz import coverage
from fbv3.harness.pipeline import HarnessOutcome, gate
from fbv3.runtime.pool import AgentPool
from fbv3.sandbox import docker
from fbv3.sandbox.workspace import Workspace

logger = logging.getLogger(__name__)


@dataclass
class Integration(HarnessOutcome):
    """A harness outcome that also carries how the tree is built."""

    build_sh: str = ""
    harness_path: str = ""
    source_dir: str = ""


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


class _OneOff:
    """A throwaway container, shaped like a Workspace for ``coverage`` to use."""

    def __init__(self, image: str, cov_out: Path, run_id: str = ""):
        self.image, self.cov_out, self.run_id = image, Path(cov_out).resolve(), run_id
        self.prof = Path(tempfile.mkdtemp(prefix="fbv3-prof-"))
        self.corpus = Path(tempfile.mkdtemp(prefix="fbv3-corpus-"))

    def exec(self, argv, *, timeout: int = 900, **_) -> subprocess.CompletedProcess:
        cmd = ["docker", "run", "--rm", "--entrypoint", argv[0],
               *docker.label_args(self.run_id, "probe"), "--user", docker.uid_gid(),
               "-e", "HOME=/tmp", "--network", "none", *docker.resource_args(4096, 2.0),
               "-v", f"{self.cov_out}:/cov:ro", "-v", f"{self.prof}:/ws/coverage",
               "-v", f"{self.corpus}:/corpus:ro", self.image, *argv[1:]]
        return docker.run(cmd, timeout=timeout)

    def cleanup(self) -> None:
        shutil.rmtree(self.prof, ignore_errors=True)
        shutil.rmtree(self.corpus, ignore_errors=True)


def instrumented_functions(*, image: str, cov_out: Path, binary: str, run_id: str = "",
                           timeout_s: int = 900) -> tuple[list, str]:
    """(project functions llvm-cov knows about, error).

    Empty with no error means the build is not instrumented: the library's
    translation units never reached the coverage mapping.
    """
    one = _OneOff(image, cov_out, run_id)
    try:
        return coverage.collect_functions(one, coverage_binary=f"/cov/{binary}",
                                          corpus_dir="/corpus", timeout_s=timeout_s)
    finally:
        one.cleanup()


class IntegrateStage:
    def __init__(self, task: Task, store, pool: AgentPool, ws: Workspace, *, run_id: str, run_dir: Path):
        self.task, self.store, self.pool, self.ws = task, store, pool, ws
        self.run_id, self.run_dir = run_id, run_dir
        self.cfg = task.integrate

    # -- helpers -------------------------------------------------------------------------

    def _ctx(self, slug: str) -> dict:
        return {
            "container": self.ws.container, "ws_root": str(self.ws.root), "run_id": self.run_id,
            "source_dir": self.task.source_dir, "base_image": self.cfg.base_image,
            "language": self.task.language, "builds_dir": str(self.ws.path(f"builds/{slug}")),
            "allow_network": self.cfg.allow_network, "build_timeout_s": self.cfg.build_timeout_s,
            "build_memory_mb": self.cfg.build_memory_mb, "build_cpus": self.cfg.build_cpus,
            "sanitizers": list(self.task.harness.sanitizers),
            "smoke_seconds": self.task.harness.smoke_seconds,
            "min_edges": self.task.harness.min_edges, "min_exec_s": self.task.harness.min_exec_s,
        }

    def _session(self, system: str, task: str, slug: str):
        return self.pool.run("integrator", scope="integrate", system=system, task=task,
                             tools=prompts.ROLE_TOOLS["integrator"], ctx=self._ctx(slug),
                             session_root=self.ws.path("sessions"), subject=slug)

    # -- the gate -------------------------------------------------------------------------

    def _check(self, slug: str, sub: dict) -> tuple[dict, str]:
        """(record, feedback). Feedback empty means the candidate passed."""
        build_out = Path(sub["build_dir"]) / "out"
        binary = sub["binary"]
        if not (build_out / binary).is_file():
            return {"stage": "binary"}, ("The submitted build has no fuzz target at "
                                         f"$OUT/{binary}. Rebuild and check what build.sh wrote.")

        # The decisive check: a coverage build must know the project's own code.
        cov_dir = self.ws.path(f"builds/{slug}/coverage")
        cov = build_workspace(
            base_image=self.cfg.base_image, source_dir=Path(self.task.source_dir),
            build_sh=sub["build_sh"], harness_files={sub["harness_path"]: sub["harness_code"]},
            build_dir=cov_dir, sanitizer="coverage", engine="libfuzzer",
            language=self.task.language, run_id=self.run_id, timeout_s=self.cfg.build_timeout_s,
            memory_mb=self.cfg.build_memory_mb, cpus=self.cfg.build_cpus,
            allow_network=self.cfg.allow_network, expected_binary=binary)
        if not cov.ok:
            return ({"stage": "coverage_build", "error": cov.error},
                    "The same build.sh must also work for a coverage build (SANITIZER=coverage), "
                    "which the bug-hunting stage needs. It failed:\n" + cov.feedback()[:2500])

        rows, err = instrumented_functions(image=self.cfg.base_image, cov_out=Path(cov.out_dir),
                                           binary=cov.binary, run_id=self.run_id)
        if err:
            return ({"stage": "coverage_export", "error": err},
                    "The coverage build produced no usable coverage data: " + err[:1200])
        files = sorted({r.file for r in rows})
        if not rows:
            return ({"stage": "instrumentation", "functions": 0},
                    "The library is NOT instrumented. A coverage build of your build.sh contains none "
                    "of the project's own functions, which means its translation units were compiled "
                    "without $CFLAGS -- or build.sh linked a prebuilt or system copy of the library "
                    "instead of building it from source. The build works and the fuzzer runs, but the "
                    "sanitizer never checks the library's memory, so no bug in it can ever be found. "
                    "Pass $CFLAGS/$CXXFLAGS into the library's own compilation "
                    "(CC=$CC CFLAGS=\"$CFLAGS\" ./configure, cmake -DCMAKE_C_FLAGS=\"$CFLAGS\", "
                    "make CFLAGS=\"$CFLAGS\") and link the static library you just built.")

        # Then the ordinary harness gate: static principles + our own smoke run.
        shutil.rmtree(self.ws.path("out/address"), ignore_errors=True)
        self.ws.path("out/address").mkdir(parents=True, exist_ok=True)
        shutil.copytree(build_out, self.ws.path("out/address"), dirs_exist_ok=True, symlinks=True)
        g = gate(self.ws, self.task, code=sub["harness_code"],
                 binary_container=f"/ws/out/address/{binary}", harness_names=[binary])
        record = {"stage": "gate", "functions": len(rows), "files": len(files),
                  "coverage_out": cov.out_dir, "coverage_binary": cov.binary, "gate": g}
        if g.get("infra"):
            return ({"stage": "infra", "error": g["infra"]},
                    "INFRA: the smoke run could not start (" + g["infra"] + "). Nothing is wrong with "
                    "your build as far as this tells us; it will be retried.")
        errors = [f for f in g["findings"] if f["severity"] == "error"]
        if errors:
            return record, ("The first harness has a defect the checks reject:\n"
                            + "\n".join(f"{f['principle']}: {f['message']}" for f in errors))
        verdict = g["smoke"]["verdict"]
        if verdict == "no_run":
            return record, ("The fuzz target does not run at all, so the link is wrong even though the "
                            "build succeeded:\n" + g["smoke"].get("output_tail", "")[-1500:])
        if verdict == "dead":
            return record, (f"The build is instrumented ({len(rows)} functions over {len(files)} files), "
                            "but fuzzing the harness barely covers anything: "
                            f"{g['smoke'].get('edges')} edges. The harness is not reaching the library's "
                            "logic -- check that the input actually drives the entry point.")
        return record, ""

    # -- the stage -------------------------------------------------------------------------

    def run(self, target: Target | None = None) -> Integration:
        slug = "integrate"
        self.ws.path(f"builds/{slug}").mkdir(parents=True, exist_ok=True)
        out = Integration(target=slug, status="failed")
        previous = ""
        for round_no in range(1, self.cfg.max_rounds + 1):
            out.rounds = round_no
            system, task = prompts.integrator(
                project=self.task.project, function=target.function if target else "",
                entries=target.entries if target else (),
                description=target.description if target else "",
                allow_network=self.cfg.allow_network)
            res = self._session(system, task + previous, slug)
            sub = _read_json(res.out_dir / "build.json") if res.session_id else {}
            if not sub:
                sub = _read_json(res.out_dir / "last_build.json") if res.session_id else {}
                if sub:
                    sub["notes"] = "(the session ended without submit_build; this is its last build)"
            if not sub.get("ok"):
                self.store.add_harness_round(slug, round_no, build_ok=0, verdict="no_build",
                                             generator_session=res.session_id)
                previous = ("\n\n## The previous attempt\nIt ended without a working build (session "
                            f"{res.status}). Build early and often: call build_project as soon as you "
                            "have a plausible script, and read the compiler errors.")
                continue
            record, feedback = self._check(slug, sub)
            verdict = "accept" if not feedback else record.get("stage", "rejected")
            self.store.add_harness_round(slug, round_no, build_ok=1, verdict=verdict,
                                          binary=sub["binary"], overlay=sub["harness_path"],
                                          gate=record, generator_session=res.session_id)
            if not feedback:
                src = self.ws.path(f"builds/{slug}") / Path(sub["harness_path"]).name
                src.write_text(sub["harness_code"])
                (self.ws.path(f"builds/{slug}") / "build.sh").write_text(sub["build_sh"])
                out.status = "integrated"
                out.binary, out.harness_path = sub["binary"], sub["harness_path"]
                out.build_sh, out.source_path = sub["build_sh"], str(src)
                out.overlay, out.notes = sub["harness_path"], sub.get("notes", "")
                out.source_dir = self.task.source_dir
                out.builds = {"address": str(Path(sub["build_dir"]) / "out"),
                              "coverage": record["coverage_out"]}
                self.store.set_harness(slug, out.status, binary=out.binary, overlay=out.harness_path,
                                       source_path=out.source_path, builds=out.builds,
                                       rounds=round_no, notes=out.notes)
                self.store.emit("integrated", project=self.task.project, binary=out.binary,
                                functions=record.get("functions"), files=record.get("files"))
                logger.info("integrated %s: %s (%s instrumented functions in %s files)",
                            self.task.project, out.binary, record.get("functions"),
                            record.get("files"))
                return out
            logger.info("integrate round %d rejected at %s", round_no, record.get("stage"))
            previous = (f"\n\n## The previous attempt (round {round_no})\n{feedback}\n\n"
                        f"### Its build.sh\n```sh\n{sub['build_sh']}\n```\n"
                        f"### Its harness ({sub['harness_path']})\n```c\n{sub['harness_code']}\n```")
        self.store.set_harness(slug, "failed", rounds=out.rounds,
                               notes="no build passed the gate")
        return out
