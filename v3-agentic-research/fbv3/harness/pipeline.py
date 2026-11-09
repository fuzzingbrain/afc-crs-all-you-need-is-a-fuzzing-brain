"""Agentic harness generation (AGF, rewritten as agent sessions).

Per target:

    research    (researcher agent)   API contract, protocol, input format -> report.md
    round k:
      generate  (harness agent)      writes the harness, builds it with the
                                     project's build, fixes compile errors,
                                     smoke-fuzzes it, fixes reachability, submits
      gate      (deterministic)      re-build check + static principle checks +
                                     an independent smoke run (P4: dead / slow /
                                     crash / ok) -- never an agent's own report
      review    (reviewer agent)     checks P1-P5 against the API, runs inputs on
                                     the candidate; accept | request_fix
      -> accept: done; otherwise the gate's / reviewer's findings are the next
         round's feedback
    final       coverage build (for the directed stage's function index) and
                any extra sanitizer builds

In AGF the agent-backed path only had a build gate and P3/P4 were never
enforced; here every round goes through the same gate and the same principle
text, and the reviewer is an agent that can run the harness.
"""

from __future__ import annotations

import json
import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from fbv3 import prompts
from fbv3.build.builder import build_harness
from fbv3.config import Target, Task
from fbv3.harness.principles import static_findings
from fbv3.harness.smoke import run_env, smoke
from fbv3.runtime.pool import AgentPool
from fbv3.sandbox.workspace import Workspace

logger = logging.getLogger(__name__)


@dataclass
class HarnessOutcome:
    target: str
    status: str  # accepted | accepted_unreviewed | gate_only | failed
    overlay: str = ""
    binary: str = ""
    source_path: str = ""
    builds: dict[str, str] = field(default_factory=dict)  # sanitizer -> host out dir
    rounds: int = 0
    notes: str = ""

    @property
    def usable(self) -> bool:
        return self.status != "failed" and "address" in self.builds


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def gate(ws: Workspace, task: Task, *, code: str, binary_container: str, harness_names: list[str]) -> dict:
    """The deterministic gate on a built candidate: static checks + independent smoke run."""
    hc = task.harness
    findings = [f.to_dict() for f in static_findings(code, hc.sanitizers, task.language)]
    errors = [f for f in findings if f["severity"] == "error"]
    have_sym = (ws.path("out/llvm") / "llvm-symbolizer").is_file()

    def run(script: str, timeout: int) -> tuple[int, str]:
        r = ws.exec(["bash", "-lc", script], timeout=timeout, env=run_env(have_sym))
        return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")

    sm = smoke(run, binary=binary_container, work_dir="/ws/logs", seconds=hc.smoke_seconds,
               min_edges=hc.min_edges, min_exec_s=hc.min_exec_s, harness_names=harness_names)
    passed = not errors and sm["verdict"] in ("ok", "slow")
    # A crash at smoke time is either a harness bug or a real shallow bug: the
    # reviewer decides, so it does not fail the gate on its own.
    reviewable = not errors and sm["verdict"] in ("ok", "slow", "crash")
    return {"passed": passed, "reviewable": reviewable, "findings": findings, "smoke": sm}


def _gate_text(g: dict) -> str:
    sm = g["smoke"]
    lines = [f"smoke run ({sm.get('seconds')}s): {sm['verdict']} -- edges {sm.get('edges')}, "
             f"exec/s {sm.get('exec_s')}" + (f"; {sm['detail']}" if sm.get("detail") else "")]
    for f in g["findings"]:
        lines.append(f"{f['principle']} [{f['severity']}] line {f['line']}: {f['message']}")
    return "\n".join(lines)


def _feedback_from_gate(g: dict) -> str:
    out = ["The deterministic gate rejected the harness:", _gate_text(g)]
    sm = g["smoke"]
    if sm["verdict"] == "dead":
        out.append("P4: fuzzing barely reaches the target. Find which check rejects the inputs (read the "
                   "target's first checks, run inputs with run_harness) and derive the input so it passes.")
    elif sm["verdict"] == "no_run":
        out.append("The fuzz target did not run at all:\n" + sm.get("output_tail", "")[-2000:])
    return "\n".join(out)


def _feedback_from_review(review: dict) -> str:
    lines = ["The reviewer requested changes:"]
    for v in review.get("violations") or []:
        tag = "BLOCKING" if v.get("blocking") else "non-blocking"
        lines.append(f"- {v.get('principle', '?')} ({tag}) lines {v.get('lines', '?')}: {v.get('description', '')}"
                     + (f" -- consequence: {v['consequence']}" if v.get("consequence") else ""))
    if review.get("feedback"):
        lines.append("\nFeedback:\n" + review["feedback"])
    return "\n".join(lines)


class HarnessStage:
    def __init__(self, task: Task, store, pool: AgentPool, ws: Workspace, *, run_id: str, run_dir: Path,
                 integration=None):
        self.task, self.store, self.pool, self.ws = task, store, pool, ws
        self.run_id, self.run_dir = run_id, run_dir
        # When the tree was integrated in this run, every build goes through the
        # build.sh the integrator wrote instead of a project image's own.
        self.integration = integration

    # -- helpers -------------------------------------------------------------------------

    def _ctx(self, target: Target, slug: str, **extra) -> dict:
        hc = self.task.harness
        integrated = {}
        if self.integration is not None:
            integrated = {"source_dir": self.integration.source_dir,
                          "build_sh": self.integration.build_sh,
                          "harness_path": self.integration.harness_path,
                          "base_image": self.task.integrate.base_image,
                          "allow_network": self.task.integrate.allow_network}
        return {
            "container": self.ws.container, "ws_root": str(self.ws.root), "run_id": self.run_id,
            "builder_image": self.task.builder_image, "language": self.task.language,
            "builds_dir": str(self.ws.path(f"builds/{slug}")), "overlay_hint": target.overlay,
            "expected_binary": target.binary, "sanitizers": list(hc.sanitizers),
            "smoke_seconds": hc.smoke_seconds, "min_edges": hc.min_edges, "min_exec_s": hc.min_exec_s,
            "build_timeout_s": hc.build_timeout_s, "build_memory_mb": hc.build_memory_mb,
            "build_cpus": hc.build_cpus, "harness_names": [target.binary] if target.binary else [],
            **integrated,
            **extra,
        }

    def _session(self, role: str, target: Target, slug: str, system: str, task: str, **ctx_extra):
        return self.pool.run(role, scope="harness", system=system, task=task,
                             tools=prompts.ROLE_TOOLS[role], ctx=self._ctx(target, slug, **ctx_extra),
                             session_root=self.ws.path("sessions"), subject=slug)

    # -- discovery -------------------------------------------------------------------------

    def discover(self) -> list[Target]:
        n = self.task.discovery.max_targets
        system, task = prompts.discoverer(project=self.task.project, max_targets=n)
        res = self.pool.run("discoverer", scope="discovery", system=system, task=task,
                            tools=prompts.ROLE_TOOLS["discoverer"], ctx=self._ctx(Target("discovery"), "discovery"),
                            session_root=self.ws.path("sessions"), subject="discovery")
        path = res.out_dir / "targets.jsonl" if res.session_id else None
        targets: list[Target] = []
        if path and path.is_file():
            for line in path.read_text().splitlines():
                if line.strip():
                    t = json.loads(line)
                    targets.append(Target(function=t["function"], description=t.get("description", ""),
                                          entries=tuple(t.get("entries") or ()), overlay=t.get("overlay", "")))
        seen, out = set(), []
        for t in targets:
            if t.slug() not in seen:
                seen.add(t.slug())
                out.append(t)
        self.store.emit("discovery", targets=[t.function for t in out[:n]], session=res.session_id,
                        status=res.status)
        return out[:n]

    # -- one target ----------------------------------------------------------------------------

    def research(self, target: Target, slug: str) -> str:
        system, task = prompts.researcher(project=self.task.project, function=target.function,
                                          description=target.description, entries=target.entries)
        res = self._session("researcher", target, slug, system, task)
        report = res.out_dir / "report.md" if res.session_id else None
        if report and report.is_file():
            text = report.read_text()
            (self.ws.path(f"builds/{slug}") / "research.md").write_text(text)
            return text
        return ""

    def run_target(self, target: Target) -> HarnessOutcome:
        slug = target.slug()
        hc = self.task.harness
        self.ws.path(f"builds/{slug}").mkdir(parents=True, exist_ok=True)
        research = self.research(target, slug) if hc.research else ""
        previous = ""
        best: dict | None = None  # the last candidate that passed the gate
        outcome = HarnessOutcome(slug, "failed")
        for round_no in range(1, hc.max_rounds + 1):
            outcome.rounds = round_no
            system, task = prompts.harness(
                project=self.task.project, function=target.function, description=target.description,
                entries=target.entries, overlay=target.overlay, research=research, previous=previous,
                sanitizers=hc.sanitizers, language=self.task.language)
            gen = self._session("harness", target, slug, system, task)
            sub = _read_json(gen.out_dir / "harness.json") if gen.session_id else {}
            if not sub:
                last = _read_json(gen.out_dir / "last_build.json") if gen.session_id else {}
                if last.get("ok"):
                    sub = {"overlay": last["overlay"], "binary": last["binary"], "build_dir": last["build_dir"],
                           "code": last["code"], "notes": "(the session ended without submit_harness; "
                                                          "this is its last successful build)"}
            if not sub:
                self.store.add_harness_round(slug, round_no, build_ok=0, verdict="no_build",
                                             generator_session=gen.session_id)
                previous = ("## Previous round\nThe previous session ended without a successful build "
                            f"(status {gen.status}). Build early and often; submit what builds.\n")
                continue
            # Never trust the submission's claims: check the binary exists and holds this code.
            build_out = Path(sub["build_dir"]) / "out"
            binary = sub["binary"]
            code = sub["code"]
            if not (build_out / binary).is_file():
                self.store.add_harness_round(slug, round_no, build_ok=0, verdict="missing_binary",
                                             generator_session=gen.session_id)
                previous = "## Previous round\nThe submitted build has no fuzz target binary. Rebuild.\n"
                continue
            src_path = self.ws.path(f"builds/{slug}") / f"round{round_no}{Path(sub['overlay']).suffix or '.c'}"
            src_path.write_text(code)
            names = [binary, Path(sub["overlay"]).stem]
            g = gate(self.ws, self.task, code=code, binary_container=self.ws.to_container(build_out / binary),
                     harness_names=names)
            cand = {"overlay": sub["overlay"], "binary": binary, "build_out": str(build_out), "code": code,
                    "source_path": str(src_path), "notes": sub.get("notes", ""), "gate": g}
            if g["passed"]:
                best = cand
            review: dict = {}
            verdict = "gate_failed"
            if g["reviewable"] and hc.review:
                rsys, rtask = prompts.reviewer(
                    project=self.task.project, function=target.function, description=target.description,
                    overlay=sub["overlay"], binary=self.ws.to_container(build_out / binary), code=code,
                    notes=sub.get("notes", ""), findings=json.dumps(g["findings"], indent=1),
                    gate=_gate_text(g), round_no=round_no, sanitizers=hc.sanitizers)
                rev = self._session("reviewer", target, slug, rsys, rtask,
                                    target_bin=self.ws.to_container(build_out / binary), harness_names=names)
                review = _read_json(rev.out_dir / "review.json") if rev.session_id else {}
                verdict = review.get("verdict") or "no_review"
                reviewer_session = rev.session_id
            elif g["reviewable"]:
                verdict = "accept" if g["passed"] else "gate_failed"
                reviewer_session = ""
            else:
                reviewer_session = ""
            self.store.add_harness_round(
                slug, round_no, overlay=sub["overlay"], binary=binary, source_path=str(src_path), build_ok=1,
                gate=g, review=review, verdict=verdict, generator_session=gen.session_id,
                reviewer_session=reviewer_session)
            if verdict == "accept" and (g["passed"] or g["smoke"]["verdict"] == "crash"):
                best = cand
                outcome.status = "accepted" if hc.review else "gate_only"
                break
            if verdict == "no_review" and g["passed"]:
                outcome.status = "accepted_unreviewed"
                break
            fb = _feedback_from_review(review) if verdict == "request_fix" else _feedback_from_gate(g)
            previous = (f"## Previous round ({round_no})\n{fb}\n\n### Previous code ({sub['overlay']})\n"
                        f"```c\n{code}\n```\n")
        else:
            if best is not None:
                outcome.status = "gate_only"
        if best is None:
            self.store.set_harness(slug, "failed", rounds=outcome.rounds, notes="no candidate passed the gate")
            return outcome
        return self._finalise(target, slug, best, outcome)

    def _finalise(self, target: Target, slug: str, best: dict, outcome: HarnessOutcome) -> HarnessOutcome:
        hc = self.task.harness
        final = self.ws.path(f"final/{slug}")
        final.mkdir(parents=True, exist_ok=True)
        builds: dict[str, str] = {}
        addr = final / "address"
        shutil.rmtree(addr, ignore_errors=True)
        shutil.copytree(best["build_out"], addr, symlinks=True)
        builds["address"] = str(addr)
        for san in ["coverage", *[s for s in hc.sanitizers if s != "address"]]:
            res = self._build_final(best, san, final / f"_{san}")
            if res.ok:
                builds[san] = res.out_dir
            else:
                logger.warning("final %s build of %s failed: %s", san, slug, res.error)
                self.store.emit("final_build_failed", target=slug, sanitizer=san, error=res.error)
        src = final / Path(best["overlay"]).name
        src.write_text(best["code"])
        outcome.overlay, outcome.binary, outcome.source_path = best["overlay"], best["binary"], str(src)
        outcome.builds, outcome.notes = builds, best.get("notes", "")
        self.store.set_harness(slug, outcome.status, overlay=best["overlay"], binary=best["binary"],
                               source_path=str(src), builds=builds, rounds=outcome.rounds, notes=outcome.notes)
        return outcome

    def _build_final(self, best: dict, sanitizer: str, build_dir: Path):
        """The coverage / extra-sanitizer build, by whichever mechanism built the candidate."""
        hc = self.task.harness
        if self.integration is not None:
            from fbv3.build.workspace_build import build_workspace

            return build_workspace(
                base_image=self.task.integrate.base_image,
                source_dir=Path(self.integration.source_dir), build_sh=self.integration.build_sh,
                harness_files={self.integration.harness_path: best["code"]}, build_dir=build_dir,
                sanitizer=sanitizer, engine=self.task.engine, language=self.task.language,
                run_id=self.run_id, timeout_s=self.task.integrate.build_timeout_s,
                memory_mb=self.task.integrate.build_memory_mb, cpus=self.task.integrate.build_cpus,
                allow_network=self.task.integrate.allow_network, expected_binary=best["binary"])
        return build_harness(builder_image=self.task.builder_image, overlay=best["overlay"],
                             source=best["code"], build_dir=build_dir, sanitizer=sanitizer,
                             engine=self.task.engine, language=self.task.language, run_id=self.run_id,
                             timeout_s=hc.build_timeout_s, memory_mb=hc.build_memory_mb,
                             cpus=hc.build_cpus, expected_binary=best["binary"])

    def run(self, targets: list[Target], deadline: float | None = None) -> list[HarnessOutcome]:
        out = []
        for t in targets:
            if deadline is not None and time.monotonic() > deadline:
                break
            try:
                out.append(self.run_target(t))
            except Exception as exc:  # noqa: BLE001 -- one target's failure must not end the run
                logger.exception("harness stage failed for %s", t.slug())
                self.store.set_harness(t.slug(), "failed", notes=f"{type(exc).__name__}: {exc}")
                out.append(HarnessOutcome(t.slug(), "failed", notes=str(exc)))
        return out
