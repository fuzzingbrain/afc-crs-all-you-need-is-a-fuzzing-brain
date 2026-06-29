# SPDX-License-Identifier: Apache-2.0
"""Cohesive OSS-Fuzz build engine.

ONE place that drives ``infra/helper.py build_fuzzers``, normalizes its output,
collects the produced fuzzer binaries, and returns a structured result. It holds
no per-workspace state, so it is safe to drive many isolated workspaces (or many
sanitizers) concurrently — see :func:`build_many`.

This consolidates the helper.py invocation that used to be copy-pasted across
``core/fuzzer_builder.py`` and ``worker/builder.py``: both now delegate here, so
there is a single source of truth for *how a fuzzer is built*.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, List, Optional

# 30 minutes — the historical per-build cap shared by both former builders.
DEFAULT_BUILD_TIMEOUT_S = 1800

# Non-fuzzer artifacts helper.py leaves in build/out/<project>.
_SKIP_FILES = {
    "llvm-symbolizer", "sancov", "clang", "clang++",
    "llvm-cov", "llvm-profdata", "llvm-ar",
}
_SKIP_EXTS = {
    ".bin", ".log", ".dict", ".options", ".bc", ".json", ".o", ".a", ".so",
    ".h", ".c", ".cpp", ".cc", ".py", ".sh", ".txt", ".md", ".zip", ".tar", ".gz",
}

# Callback fed each normalized output line (for live streaming). Optional.
LineSink = Callable[[str], None]


@dataclass
class BuildResult:
    """Outcome of one ``build_fuzzers`` invocation."""

    project: str
    sanitizer: str
    ok: bool
    fuzzers: List[str] = field(default_factory=list)
    message: str = ""
    returncode: Optional[int] = None
    duration_s: float = 0.0
    log_path: Optional[Path] = None
    output_tail: str = ""

    @property
    def fuzzer_count(self) -> int:
        return len(self.fuzzers)


@dataclass
class BuildJob:
    """One isolated build: a workspace (its own ``fuzz-tooling`` + mounted src)
    plus the sanitizer to build with. Distinct jobs that point at distinct
    ``fuzz_tooling_path``/``project`` can run fully in parallel (multi-workspace),
    because helper.py keys its image tag and ``build/out`` dir on the project and
    the build context lives under that workspace's ``fuzz-tooling``.
    """

    fuzz_tooling_path: Path
    project: str
    src_path: Path
    sanitizer: str = "address"
    engine: str = "libfuzzer"
    log_path: Optional[Path] = None
    timeout_s: int = DEFAULT_BUILD_TIMEOUT_S
    label: str = ""  # free-form tag (e.g. bug id) echoed back via the result

    def __post_init__(self) -> None:
        self.fuzz_tooling_path = Path(self.fuzz_tooling_path)
        self.src_path = Path(self.src_path)
        if self.log_path is not None:
            self.log_path = Path(self.log_path)


def truncate_output(text: str, head: int = 10, tail: int = 20) -> str:
    """Keep the first ``head`` and last ``tail`` lines of long build output."""
    lines = text.splitlines()
    if len(lines) <= head + tail:
        return text
    omitted = len(lines) - head - tail
    return "\n".join(lines[:head] + [f"... ({omitted} lines omitted) ..."] + lines[-tail:])


def collect_fuzzers(fuzz_tooling_path: Path, project: str) -> List[str]:
    """List the fuzzer binaries helper.py produced in ``build/out/<project>``."""
    out_dir = Path(fuzz_tooling_path) / "build" / "out" / project
    if not out_dir.exists():
        return []
    fuzzers: List[str] = []
    for f in sorted(out_dir.iterdir()):
        if f.is_dir() or f.name in _SKIP_FILES or f.suffix.lower() in _SKIP_EXTS:
            continue
        if not os.access(f, os.X_OK):
            continue
        fuzzers.append(f.name)
    return fuzzers


def helper_command(job: BuildJob) -> List[str]:
    """The exact ``helper.py build_fuzzers`` argv for a job (also handy in tests)."""
    return [
        "python3",
        str(job.fuzz_tooling_path / "infra" / "helper.py"),
        "build_fuzzers",
        "--sanitizer", job.sanitizer,
        "--engine", job.engine,
        job.project,
        str(job.src_path.absolute()),
    ]


def run_build(job: BuildJob, on_line: Optional[LineSink] = None) -> BuildResult:
    """Run a single ``build_fuzzers`` invocation to completion.

    ``on_line`` (if given) receives every normalized output line as it arrives —
    use it to stream to a console for an interactive single build; leave it unset
    for parallel builds (whose interleaved output would be unreadable) and read
    the per-job log file instead. Carriage returns from docker progress bars are
    rewritten to newlines so logs and consoles stay legible.
    """
    started = time.monotonic()
    helper = job.fuzz_tooling_path / "infra" / "helper.py"
    if not helper.is_file():
        return BuildResult(
            job.project, job.sanitizer, False,
            message=f"helper.py not found: {helper}", log_path=job.log_path,
        )

    cmd = helper_command(job)
    output: List[str] = []
    log_f = open(job.log_path, "w", encoding="utf-8") if job.log_path else None
    proc: Optional[subprocess.Popen] = None
    try:
        if log_f:
            log_f.write("Build Command: " + " ".join(cmd) + "\n" + "=" * 80 + "\n\n")
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            cwd=str(job.fuzz_tooling_path),
        )
        proc_stdout = proc.stdout
        assert proc_stdout is not None

        # Drain stdout on a reader thread so the timeout is a real wall-clock
        # deadline: iterating proc.stdout directly blocks until the child exits,
        # which would let a silently-hung build run forever. We join the reader
        # with the deadline and kill the child if it overruns.
        def _drain() -> None:
            for raw_line in proc_stdout:
                line = raw_line.replace("\r", "\n")
                if on_line:
                    on_line(line)
                if log_f:
                    log_f.write(line)
                output.append(line)

        reader = threading.Thread(target=_drain, daemon=True)
        reader.start()
        reader.join(timeout=job.timeout_s)
        if reader.is_alive():
            proc.kill()
            reader.join(timeout=10)
            return BuildResult(
                job.project, job.sanitizer, False,
                message=f"Build timed out ({job.timeout_s}s)",
                duration_s=time.monotonic() - started, log_path=job.log_path,
                output_tail=truncate_output("".join(output[-50:])),
            )
        proc.wait(timeout=10)  # reader hit EOF -> child has exited (or is exiting)
        rc = proc.returncode
        if log_f:
            log_f.write("\n" + "=" * 80 + f"\nExit code: {rc}\n")
        duration = time.monotonic() - started
        if rc != 0:
            return BuildResult(
                job.project, job.sanitizer, False,
                message=f"Build failed (code {rc})", returncode=rc,
                duration_s=duration, log_path=job.log_path,
                output_tail=truncate_output("".join(output[-50:])),
            )
        return BuildResult(
            job.project, job.sanitizer, True,
            fuzzers=collect_fuzzers(job.fuzz_tooling_path, job.project),
            message="Build successful", returncode=0,
            duration_s=duration, log_path=job.log_path,
        )
    except Exception as exc:  # noqa: BLE001 — surface any failure as a result
        if proc is not None and proc.poll() is None:
            proc.kill()
        return BuildResult(
            job.project, job.sanitizer, False, message=str(exc),
            duration_s=time.monotonic() - started, log_path=job.log_path,
            output_tail=truncate_output("".join(output[-50:])),
        )
    finally:
        if log_f and not log_f.closed:
            log_f.close()


def build_many(
    jobs: Iterable[BuildJob],
    max_workers: Optional[int] = None,
    on_result: Optional[Callable[[BuildResult], None]] = None,
) -> List[BuildResult]:
    """Build many isolated jobs concurrently and return results in job order.

    Each job is an independent helper.py/docker invocation against its own
    ``fuzz-tooling`` workspace, so distinct projects/workspaces parallelize
    cleanly. ``max_workers`` defaults to ``cpu_count - 1`` (capped at the job
    count); docker itself serializes where it must. ``on_result`` fires as each
    job finishes (for progress reporting). A job that raises is reported as a
    failed :class:`BuildResult`, never as an exception out of this call.
    """
    jobs = list(jobs)
    if not jobs:
        return []
    if max_workers is None or max_workers < 1:
        max_workers = min(len(jobs), max(1, (os.cpu_count() or 2) - 1))

    results: List[Optional[BuildResult]] = [None] * len(jobs)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_index = {pool.submit(run_build, job): i for i, job in enumerate(jobs)}
        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            try:
                results[idx] = future.result()
            except Exception as exc:  # noqa: BLE001 — defensive; run_build catches its own
                job = jobs[idx]
                results[idx] = BuildResult(
                    job.project, job.sanitizer, False, message=str(exc),
                    log_path=job.log_path,
                )
            if on_result:
                on_result(results[idx])  # type: ignore[arg-type]
    return [r for r in results if r is not None]
