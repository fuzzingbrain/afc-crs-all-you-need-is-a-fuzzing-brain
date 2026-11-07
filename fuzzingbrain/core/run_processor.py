# SPDX-License-Identifier: Apache-2.0
"""
Run processing: everything between reading the task and the final summary.

    1. workspace: repo/, fuzz-tooling/, diff/ (delta), sanitised
    2. build + index (the analyzer)
    3. harnesses registered (one row each, with a binary per sanitizer and
       the harness source), the graph registered against them
    4. preflight (core/preflight.py): every check that can fail before money
       is spent; results/preflight.json
    5. one worker per harness, then wait for poc_target / budget / timeout
    6. runs row closed, final summary from the database
"""

import json
import os
import shutil
import subprocess
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .logging import logger, final_summary, WorkerColors, get_log_dir
from .config import Config
from .workspace_guard import (
    assert_workspace_clean,
    format_banner,
    sanitize_workspace,
)


@dataclass
class RunPaths:
    """Where a run's inputs are laid out (filled in by WorkspaceSetup)."""

    run_id: str
    project_name: str
    workspace_path: str = ""
    src_path: str = ""
    fuzz_tooling_path: str = ""
    is_fuzz_tooling_provided: bool = False


class WorkspaceSetup:
    """Lays out the run's output directory: repo/, fuzz-tooling/, results/, logs/."""

    def __init__(self, config: Config, run: RunPaths):
        self.config = config
        self.run = run

    def setup(self) -> Tuple[bool, str]:
        """Create the run directory (resolved from `output` by the entry point)."""
        try:
            run_workspace = Path(self.config.workspace)
            run_workspace.mkdir(parents=True, exist_ok=True)
            (run_workspace / "results" / "pocs").mkdir(parents=True, exist_ok=True)
            (run_workspace / "results" / "patches").mkdir(parents=True, exist_ok=True)
            (run_workspace / "logs").mkdir(exist_ok=True)

            self.run.workspace_path = str(run_workspace)
            self.run.src_path = str(run_workspace / "repo")
            logger.info(f"Workspace: {run_workspace}")
            return True, str(run_workspace)
        except Exception as e:
            logger.error(f"Failed to setup workspace: {e}")
            return False, str(e)

    @staticmethod
    def _git(repo: Path, *args: str, timeout: int = 120) -> None:
        """Run git in `repo`; a failure raises, so a wrong revision is never scanned."""
        r = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")

    @staticmethod
    def resolve_ref(repo: Path, ref: str) -> str:
        """A commit id for ref: itself, or the remote branch of that name.

        A fresh clone has only the default branch locally, and
        `checkout --detach <remote branch>` refuses the name.
        """
        for cand in (ref, f"origin/{ref}"):
            r = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"{cand}^{{commit}}"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        raise RuntimeError(f"{ref!r} is not a commit, branch or tag of the source")

    def clone_repository(self) -> Tuple[bool, str]:
        """Put the source in repo/: clone repo_url, or copy repo_path, then check out.

        full scans check out target_commit; delta scans check out delta_commit
        (default HEAD) and need base_commit's history for the diff, so neither
        is a shallow clone when a commit is named.
        """
        repo_path = Path(self.run.src_path)
        if repo_path.exists():
            return False, f"{repo_path} already exists"

        if self.config.scan_mode == "delta":
            checkout = self.config.delta_commit
            need_history = True
        else:
            checkout = self.config.target_commit
            need_history = bool(checkout)

        try:
            if self.config.repo_path:
                # Copy, never link: checkout, remove_git and the build all write
                # to this tree, and none of that may reach the user's directory.
                logger.info(f"Copying {self.config.repo_path} to {repo_path}")
                shutil.copytree(self.config.repo_path, repo_path, symlinks=True)
            else:
                logger.info(f"Cloning {self.config.repo_url} to {repo_path}")
                clone = ["git", "clone"]
                if not need_history:
                    clone += ["--depth", "1"]
                r = subprocess.run(
                    clone + [self.config.repo_url, str(repo_path)],
                    capture_output=True, text=True,
                    timeout=600 if need_history else 300,
                )
                if r.returncode != 0:
                    return False, f"git clone failed: {r.stderr.strip()}"

            if checkout:
                sha = self.resolve_ref(repo_path, checkout)
                self._git(repo_path, "checkout", "--detach", sha)
                logger.info(f"Checked out {checkout} ({sha[:12]})")
            if self.config.scan_mode == "delta":
                # Fail here, not at diff time, when the base is not in history.
                self.resolve_ref(repo_path, self.config.base_commit)
            return True, "Ready"
        except subprocess.TimeoutExpired:
            return False, "timed out fetching the source"
        except Exception as e:
            return False, str(e)

    def setup_fuzz_tooling(self) -> Tuple[bool, str]:
        """Put the OSS-Fuzz style tooling in fuzz-tooling/.

        Prebuilt binaries need none: build/out/ under it is created when they
        are placed. Otherwise a local fuzz_tooling_path wins over the URL.
        """
        fuzz_tooling_path = Path(self.run.workspace_path) / "fuzz-tooling"
        self.run.fuzz_tooling_path = str(fuzz_tooling_path)

        if self.config.is_prebuilt:
            fuzz_tooling_path.mkdir(parents=True, exist_ok=True)
            self.run.is_fuzz_tooling_provided = False
            return True, "Not needed (prebuilt binaries)"

        try:
            if self.config.fuzz_tooling_path:
                logger.info(f"Copying fuzz-tooling from {self.config.fuzz_tooling_path}")
                shutil.copytree(
                    self.config.fuzz_tooling_path, fuzz_tooling_path, symlinks=True
                )
            else:
                url, ref = self.config.fuzz_tooling_url, self.config.fuzz_tooling_ref
                logger.info(f"Cloning fuzz-tooling from {url}" + (f" @ {ref}" if ref else ""))
                r = subprocess.run(
                    ["git", "clone", "--depth", "1", url, str(fuzz_tooling_path)],
                    capture_output=True, text=True, timeout=300,
                )
                if r.returncode != 0:
                    return False, f"fuzz-tooling clone failed: {r.stderr.strip()}"
                if ref:
                    # Fetch then check out, so a branch, tag or commit all work.
                    self._git(fuzz_tooling_path, "fetch", "--depth", "1", "origin", ref)
                    self._git(fuzz_tooling_path, "checkout", "-f", "FETCH_HEAD")
        except subprocess.TimeoutExpired:
            return False, "timed out fetching fuzz-tooling"
        except Exception as e:
            return False, str(e)

        project = self.config.ossfuzz_project_name or self.run.project_name
        if not (fuzz_tooling_path / "projects" / project).is_dir():
            return False, f"fuzz-tooling has no projects/{project}"
        self.run.is_fuzz_tooling_provided = True
        return True, "Ready"


# ------------------------------------------------------------- harnesses

_SOURCE_SUFFIXES = (".cc", ".cpp", ".c", ".cxx", ".c++")


def _harness_name_candidates(name: str) -> List[str]:
    """curl_fuzzer_ws -> [curl_fuzzer_ws, curl_fuzzer]: one source, many binaries."""
    out = [name]
    parts = name.split("_")[:-1]
    while parts:
        stem = "_".join(parts)
        if "fuzz" not in stem and "harness" not in stem:
            break
        out.append(stem)
        parts = parts[:-1]
    return out


def find_harness_source(
    name: str, workspace: Path, project: str, reported: Optional[str] = None
) -> Optional[str]:
    """The harness's source on disk: the build's report, else a search of the
    repo and the OSS-Fuzz project directory. None when there is none."""
    if reported:
        p = Path(reported)
        if not p.is_absolute():
            p = workspace / p
        if p.is_file():
            return str(p.resolve())
    roots = [workspace / "repo", workspace / "fuzz-tooling" / "projects" / project]
    for root in roots:
        if not root.is_dir():
            continue
        for stem in _harness_name_candidates(name):
            for suffix in _SOURCE_SUFFIXES:
                for hit in sorted(root.rglob(f"{stem}{suffix}")):
                    if hit.is_file():
                        return str(hit.resolve())
    return None


def register_harnesses(store, config: Config, run_id: str, analyze_result) -> list:
    """One harnesses row per harness the run works on, with its binaries.

    The build is authoritative for what exists. A name in config.fuzzers that
    did not build, a harness missing a sanitizer's binary, or a harness with
    no source anywhere stops the run: each would otherwise be a worker that
    silently does nothing (or feeds its agents an empty harness).
    """
    from .dispatcher import HarnessUnit

    built: Dict[str, Dict[str, str]] = {}
    reported: Dict[str, str] = {}
    for fi in analyze_result.fuzzers:
        built.setdefault(fi.name, {})[fi.sanitizer] = fi.binary_path
        if fi.source_path and fi.name not in reported:
            reported[fi.name] = fi.source_path

    names = list(config.fuzzers) or sorted(built)
    errors = []
    missing = [n for n in names if n not in built]
    if missing:
        errors.append(f"fuzzers {missing} are not among the built harnesses {sorted(built)}")
    project = config.ossfuzz_project_name or config.project_name
    workspace = Path(config.workspace)
    units = []
    for name in names:
        if name not in built:
            continue
        bins = built[name]
        lacking = [s for s in config.sanitizers if s not in bins]
        if lacking:
            errors.append(f"harness {name!r} has no {lacking} binary")
            continue
        sources = config.fuzzer_sources.get(name) or []
        source = sources[0] if sources else find_harness_source(
            name, workspace, project, reported.get(name)
        )
        if not source:
            errors.append(
                f"no source found for harness {name!r}; name it in fuzzer.sources"
            )
            continue
        if not config.fuzzer_sources.get(name):
            # The worker reads the harness for its agents from fuzzer_sources:
            # an entry found here travels with the assignment.
            config.fuzzer_sources[name] = [source]
        binaries = {s: bins[s] for s in config.sanitizers}
        hid = store.add_harness(run_id, name, source, binaries)
        units.append(HarnessUnit(str(hid), name, binaries, list(config.sanitizers)))
    if errors:
        raise RuntimeError("; ".join(errors))
    if not units:
        raise RuntimeError("no harness to run")
    return units


def register_graph(store, run_id: str, graph: dict, units: list) -> None:
    if not graph:
        return
    by_name = {u.name: u.harness_id for u in units}
    reach = {
        by_name[h]: (int(v[0]), int(v[1]))
        for h, v in (graph.get("harnesses") or {}).items()
        if h in by_name
    }
    store.register_graph(
        run_id,
        commit=graph.get("commit") or "",
        path=graph["path"],
        content_sha256=graph["content_sha256"],
        n_functions=int(graph.get("n_functions") or 0),
        n_edges=int(graph.get("n_edges") or 0),
        n_indirect_edges=int(graph.get("n_indirect_edges") or 0),
        harness_reach=reach,
    )


# ------------------------------------------------------------- the run

# wait_for_completion's status -> (runs.status, runs.end_reason)
_RUN_END = {
    "poc_target_reached": ("completed", "poc_target"),
    "timeout": ("completed", "timeout"),
    "budget_exceeded": ("completed", "budget"),
}


class RunProcessor:
    def __init__(self, config: Config, store):
        self.config = config
        self.store = store
        self.run_id = str(config.run_id)
        self.paths = RunPaths(run_id=self.run_id, project_name=config.project_name)
        self.project = config.ossfuzz_project_name or config.project_name

    # ---------------------------------------------------------- workspace

    def _prepare_workspace(self) -> None:
        setup = WorkspaceSetup(self.config, self.paths)
        for step, fn in (
            ("Workspace", setup.setup),
            ("Source", setup.clone_repository),
            ("Fuzz-tooling", setup.setup_fuzz_tooling),
        ):
            logger.info(f"{step}...")
            ok, msg = fn()
            if not ok:
                raise RuntimeError(f"{step} setup failed: {msg}")
        if self.config.scan_mode == "delta":
            self._write_diff()

        workspace = Path(self.paths.workspace_path)
        # The checked-out revision, before remove_git takes the history away:
        # preflight compares it with the commit the task named.
        self.head_commit = self._git_head(workspace / "repo")
        want = self.config.delta_commit if self.config.scan_mode == "delta" else self.config.target_commit
        self.want_commit = (
            WorkspaceSetup.resolve_ref(workspace / "repo", want)
            if want and (workspace / "repo" / ".git").exists() else None
        )
        report = sanitize_workspace(
            workspace,
            remove_git=self.config.remove_git,
            diff_ready=(workspace / "diff" / "ref.diff").exists()
            if self.config.scan_mode == "delta"
            else True,
        )
        for line in format_banner(
            report, remove_git=self.config.remove_git, confined_to=f"{workspace.name}/repo"
        ):
            logger.info(line)
        assert_workspace_clean(workspace, require_no_git=self.config.remove_git)

    @staticmethod
    def _git_head(repo: Path) -> Optional[str]:
        if not (repo / ".git").exists():
            return None
        r = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=30,
        )
        return r.stdout.strip() if r.returncode == 0 else None

    def _write_diff(self) -> None:
        workspace = Path(self.paths.workspace_path)
        diff_file = workspace / "diff" / "ref.diff"
        if diff_file.exists():
            return
        diff_file.parent.mkdir(parents=True, exist_ok=True)
        # HEAD is delta_commit, checked out above; the base may be a remote branch.
        delta = self.config.delta_commit or "HEAD"
        base = WorkspaceSetup.resolve_ref(workspace / "repo", self.config.base_commit)
        r = subprocess.run(
            ["git", "diff", f"{base}..HEAD", "--", ".",
             ":!.aixcc", ":!*/.aixcc"],
            cwd=str(workspace / "repo"), capture_output=True, text=True, timeout=300,
        )
        if r.returncode != 0:
            raise RuntimeError(f"git diff failed: {r.stderr.strip()}")
        if not r.stdout.strip():
            raise RuntimeError(f"no changes between {self.config.base_commit} and {delta}")
        diff_file.write_text(r.stdout)
        logger.info(f"Diff: {self.config.base_commit[:12]}..{delta[:12]}")

    # ------------------------------------------------------------ analyzer

    def _analyze(self):
        from ..analyzer import AnalyzeRequest, AnalyzeResult
        from ..analyzer.tasks import run_analyzer

        log_dir = get_log_dir()
        request = AnalyzeRequest(
            run_id=self.run_id,
            workspace_path=self.paths.workspace_path,
            project_name=self.project,
            sanitizers=self.config.sanitizers,
            language="c",
            ossfuzz_project_name=self.config.ossfuzz_project_name,
            log_dir=str(log_dir) if log_dir else None,
            graph_path=self.config.graph,
            fuzzer_sources=self.config.fuzzer_sources,
            build_coverage=self.config.wants_coverage,
            prebuilt_fuzzers=self.config.prebuilt_binaries,
        )
        logger.info(f"Analyzer: sanitizers={self.config.sanitizers} (this may take a while)")
        result = AnalyzeResult.from_dict(run_analyzer(request.to_dict()))
        if not result.success:
            raise RuntimeError(f"Code Analyzer failed: {result.error_msg}")
        logger.info(
            f"Analyzer: {len(result.fuzzers)} binaries, {result.reachable_functions_count} "
            f"functions, build {result.build_duration_seconds:.0f}s"
        )
        if result.coverage_fuzzer_path:
            from ..tools.coverage import set_coverage_fuzzer_path

            set_coverage_fuzzer_path(result.coverage_fuzzer_path)
        return result

    # ---------------------------------------------------------------- run

    def process(self) -> dict:
        logger.info(f"Processing run {self.run_id}")
        try:
            self._prepare_workspace()

            from .fuzzer_spec import runner_image

            if not self.config.docker_image:
                self.config.docker_image = runner_image(
                    Path(self.paths.fuzz_tooling_path), self.project
                )
                logger.info(f"Runner image: {self.config.docker_image}")

            analyze_result = self._analyze()
            try:
                return self._run(analyze_result)
            finally:
                from ..llms import LLMClient
                from ..analyzer.tasks import stop_analysis_server

                LLMClient.close_all()
                stop_analysis_server(self.paths.workspace_path)
        except Exception as e:
            logger.exception(f"Run failed: {e}")
            try:
                self.store.end_run(self.run_id, "error", error=traceback.format_exc())
            except Exception as db_err:
                logger.error(f"Could not close the run row: {db_err}")
            try:
                write_result(Path(self.paths.workspace_path), self.store, self.run_id, "error", None, 0)
            except Exception as w_err:
                logger.error(f"Could not write result.json: {w_err}")
            return {"run_id": self.run_id, "status": "error", "message": str(e)}

    def _run(self, analyze_result) -> dict:
        units = register_harnesses(self.store, self.config, self.run_id, analyze_result)
        register_graph(self.store, self.run_id, analyze_result.graph, units)
        logger.info("Harnesses: " + ", ".join(f"{u.name} {sorted(u.binaries)}" for u in units))

        from .preflight import run_preflight

        report = run_preflight(
            self.config, units, analyze_result,
            head_commit=getattr(self, "head_commit", None),
            want_commit=getattr(self, "want_commit", None),
            out_dir=Path(self.paths.workspace_path),
        )
        if not report["ok"]:
            raise RuntimeError("preflight failed: " + "; ".join(report["failures"]))

        from .infrastructure import InfrastructureManager
        from .dispatcher import WorkerDispatcher

        log_dir = get_log_dir()
        infra = InfrastructureManager(
            redis_url=self.config.redis_url,
            concurrency=self.config.concurrency.celery_workers,
            run_id=self.run_id,
        )
        if not infra.start(log_dir=str(log_dir) if log_dir else None):
            raise RuntimeError("Failed to start infrastructure (Redis/Celery)")
        try:
            dispatcher = WorkerDispatcher(
                self.run_id, self.config, self.store, units,
                analyze_result=analyze_result, celery_queue=infra.queue_name,
            )
            jobs = dispatcher.dispatch()
            self.store.run_dispatched(self.run_id)
            for j in jobs:
                logger.info(f"  worker {j['worker_id'][:8]}  {j['fuzzer']}  {j['sanitizers']}")

            result = dispatcher.wait_for_completion(timeout_minutes=self.config.timeout_minutes)
            status, end_reason = _RUN_END[result["status"]]
            self.store.end_run(self.run_id, status, end_reason=end_reason)

            summary = final_summary(
                self.store, self.run_id, self.project, end_reason,
                elapsed_minutes=result.get("elapsed_minutes", 0),
                budget_limit=self.config.budget_limit,
                use_color=sys.stdout.isatty(),
            )
            os.system("stty sane 2>/dev/null")
            sys.stdout.write("\n" + summary + "\n\033[0m")
            sys.stdout.flush()
            if log_dir:
                with open(Path(log_dir) / "fuzzingbrain.log", "a", encoding="utf-8") as f:
                    f.write("\n" + WorkerColors.strip(summary) + "\n")
            write_result(
                Path(self.paths.workspace_path), self.store, self.run_id,
                status, end_reason, result.get("elapsed_minutes", 0),
            )
            return {
                "run_id": self.run_id,
                "status": result["status"],
                "message": f"{end_reason}: {result.get('poc_count', 0)} distinct bug(s), "
                           f"{result['completed']}/{result['total']} workers completed",
                "workspace": self.paths.workspace_path,
                "fuzzers": [u.name for u in units],
                "elapsed_minutes": result.get("elapsed_minutes", 0),
                "poc_count": result.get("poc_count", 0),
            }
        except KeyboardInterrupt:
            self.store.end_run(self.run_id, "cancelled")
            raise
        finally:
            infra.stop()


def write_result(out_dir: Path, store, run_id: str, status: str, end_reason, elapsed_minutes) -> Path:
    """<output>/result.json: what a batch script reads back (no log scraping)."""
    summary = store.run_summary(run_id)
    doc = {
        "run_id": run_id,
        "status": status,
        "end_reason": end_reason,
        "elapsed_minutes": round(float(elapsed_minutes or 0), 2),
        "cost": round(float(summary["cost"] or 0), 4),
        "crashes": [
            {"signature": c.signature, "vuln_type": c.vuln_type, "package": c.package_path}
            for c in store.crashes(run_id)
        ],
        "workers": [
            {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in w.items()}
            for w in summary["workers"]
        ],
    }
    path = Path(out_dir) / "result.json"
    path.write_text(json.dumps(doc, indent=2) + "\n")
    return path


def process_run(config: Config, store) -> dict:
    return RunProcessor(config, store).process()
