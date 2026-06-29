# SPDX-License-Identifier: Apache-2.0
"""High-level, multi-workspace build orchestration.

Turns bench bugs into built fuzzers end to end — derive the spec, materialize an
isolated workspace, build it — and drives *many* of them concurrently, each in
its own workspace (so a slow git-sync-deps or a long ninja for one bug never
blocks the others). Sits on top of :mod:`fuzzingbrain.builder.engine`.

    from fuzzingbrain.builder.orchestrator import build_bug, build_bugs

    result = build_bug(bug_dir, workspace, oss_fuzz)
    results = build_bugs(bug_dirs, root_dir, oss_fuzz, max_workers=6)

The spec-derivation and workspace-materialization steps are injectable
(``derive_spec`` / ``materialize``) so the orchestration can be tested without a
network clone or docker.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Iterable, List, Optional

from .engine import BuildJob, BuildResult, run_build


def _default_derive_spec(bug_dir, *, with_description: bool = True):
    from ..importers.bench import spec_from_bench_bug

    return spec_from_bench_bug(bug_dir, with_description=with_description)


def _default_materialize(spec, workspace, oss_fuzz, *, clone_repo: bool, overwrite: bool):
    from ..importers.external_harness import build_workspace

    return build_workspace(
        spec, workspace, oss_fuzz, clone_repo=clone_repo, overwrite=overwrite
    )


def plan(
    bug_dir: str | Path,
    workspace: str | Path,
    oss_fuzz: str | Path,
    sanitizer: str = "address",
    *,
    log_path: Optional[Path] = None,
    with_description: bool = True,
    clone_repo: bool = True,
    overwrite: bool = True,
    derive_spec: Optional[Callable] = None,
    materialize: Optional[Callable] = None,
) -> BuildJob:
    """Derive the spec, materialize ``workspace``, and return the :class:`BuildJob`.

    Separated from execution so a caller can inspect or batch jobs before running.
    """
    derive_spec = derive_spec or _default_derive_spec
    materialize = materialize or _default_materialize
    bug_dir = Path(bug_dir)
    workspace = Path(workspace)

    spec = derive_spec(bug_dir, with_description=with_description)
    materialize(spec, workspace, oss_fuzz, clone_repo=clone_repo, overwrite=overwrite)
    return BuildJob(
        fuzz_tooling_path=workspace / "fuzz-tooling",
        project=spec.project,
        src_path=workspace / "repo",
        sanitizer=sanitizer,
        log_path=log_path if log_path is not None else workspace / "build.log",
        label=bug_dir.name,
    )


def build_bug(
    bug_dir: str | Path,
    workspace: str | Path,
    oss_fuzz: str | Path,
    sanitizer: str = "address",
    *,
    on_line: Optional[Callable[[str], None]] = None,
    **plan_kwargs,
) -> BuildResult:
    """Materialize + build a single bug, returning its :class:`BuildResult`."""
    job = plan(bug_dir, workspace, oss_fuzz, sanitizer, **plan_kwargs)
    return run_build(job, on_line=on_line)


def build_bugs(
    bug_dirs: Iterable[str | Path],
    root_dir: str | Path,
    oss_fuzz: str | Path,
    sanitizer: str = "address",
    *,
    max_workers: Optional[int] = None,
    on_result: Optional[Callable[[BuildResult], None]] = None,
    **plan_kwargs,
) -> List[BuildResult]:
    """Build many bugs concurrently, each in its own workspace under ``root_dir``.

    Every bug runs its full materialize→build pipeline in a worker thread, so
    clones and docker builds overlap across bugs. A bug whose workspace setup or
    build raises is reported as a failed :class:`BuildResult`, never sinking the
    batch. Results come back in input order; ``on_result`` fires as each lands.
    """
    bug_dirs = [Path(b) for b in bug_dirs]
    if not bug_dirs:
        return []
    root_dir = Path(root_dir)
    if max_workers is None or max_workers < 1:
        max_workers = min(len(bug_dirs), max(1, (os.cpu_count() or 2) - 1))

    def _one(bug_dir: Path) -> BuildResult:
        workspace = root_dir / bug_dir.name
        try:
            job = plan(
                bug_dir, workspace, oss_fuzz, sanitizer,
                log_path=workspace / "build.log", **plan_kwargs,
            )
        except Exception as exc:  # noqa: BLE001 — workspace setup failure is a result
            return BuildResult(
                bug_dir.name, sanitizer, False,
                message=f"workspace setup failed: {exc}",
            )
        return run_build(job)

    results: List[Optional[BuildResult]] = [None] * len(bug_dirs)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_index = {pool.submit(_one, b): i for i, b in enumerate(bug_dirs)}
        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            results[idx] = future.result()
            if on_result:
                on_result(results[idx])  # type: ignore[arg-type]
    return [r for r in results if r is not None]
