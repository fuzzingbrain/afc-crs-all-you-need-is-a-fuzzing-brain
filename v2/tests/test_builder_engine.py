# SPDX-License-Identifier: Apache-2.0
"""Behavioral tests for the cohesive build engine (fuzzingbrain.builder).

A fake ``helper.py`` stands in for OSS-Fuzz so the engine's contract — argv,
output normalization, timeout, exit-code handling, fuzzer collection, and the
parallel multi-workspace driver — is exercised without docker. The fake's
behavior is driven by the build args it receives so each test shapes its own
outcome.
"""

import os
import stat
import time
from pathlib import Path

import pytest

from fuzzingbrain.builder import (
    BuildJob,
    build_many,
    collect_fuzzers,
    helper_command,
    run_build,
    truncate_output,
)


def _make_workspace(tmp_path: Path, project: str, helper_body: str) -> tuple[Path, Path]:
    """Create a workspace with a fake infra/helper.py and an empty repo."""
    ws = tmp_path / project
    tooling = ws / "fuzz-tooling"
    (tooling / "infra").mkdir(parents=True)
    (tooling / "infra" / "helper.py").write_text(helper_body)
    repo = ws / "repo"
    repo.mkdir()
    return tooling, repo


# A fake helper that, on `build_fuzzers`, emits a line (with a CR to test
# normalization), drops an executable fuzzer in build/out/<project>, plus some
# non-fuzzer noise, then exits with a code taken from an env knob.
_FAKE_HELPER = r'''
import os, sys, stat
from pathlib import Path
args = sys.argv[1:]
# args: build_fuzzers --sanitizer <s> --engine libfuzzer <project> <src>
project = args[args.index("--engine") + 2]
out = Path("build") / "out" / project
out.mkdir(parents=True, exist_ok=True)
# progress line uses \r like docker pulls do
sys.stdout.write("pulling layer\rstep 1/2\n")
sys.stdout.write("step 2/2 done\n")
sys.stdout.flush()
if os.environ.get("FAKE_RC", "0") == "0":
    fz = out / (project + "_fuzzer")
    fz.write_text("#!/bin/sh\n")
    fz.chmod(fz.stat().st_mode | stat.S_IEXEC)
    (out / "llvm-symbolizer").write_text("x")            # skip: known non-fuzzer
    (out / (project + "_fuzzer.o")).write_text("x")      # skip: extension
    (out / "seed.txt").write_text("x")                   # skip: extension
else:
    sys.stdout.write("ERROR: build broke\n")
sys.exit(int(os.environ.get("FAKE_RC", "0")))
'''


def test_helper_command_shape():
    job = BuildJob(fuzz_tooling_path="/ws/fuzz-tooling", project="proj",
                   src_path="/ws/repo", sanitizer="memory")
    cmd = helper_command(job)
    assert cmd[0] == "python3" and cmd[-1].endswith("/repo")
    assert cmd[2] == "build_fuzzers"
    assert cmd[cmd.index("--sanitizer") + 1] == "memory"      # sanitizer threaded
    assert cmd[cmd.index("--engine") + 1] == "libfuzzer"
    assert cmd[-2] == "proj"                                   # project before src


def test_run_build_success_collects_only_real_fuzzers(tmp_path):
    tooling, repo = _make_workspace(tmp_path, "alpha", _FAKE_HELPER)
    job = BuildJob(fuzz_tooling_path=tooling, project="alpha", src_path=repo)
    result = run_build(job)
    assert result.ok and result.returncode == 0
    # exactly the executable, not llvm-symbolizer / .o / .txt
    assert result.fuzzers == ["alpha_fuzzer"]
    assert result.fuzzer_count == 1
    assert result.duration_s >= 0


def test_run_build_streams_normalized_lines(tmp_path):
    tooling, repo = _make_workspace(tmp_path, "beta", _FAKE_HELPER)
    seen: list[str] = []
    run_build(BuildJob(fuzz_tooling_path=tooling, project="beta", src_path=repo),
              on_line=seen.append)
    joined = "".join(seen)
    assert "\r" not in joined                  # carriage returns rewritten
    assert "step 1/2" in joined and "step 2/2 done" in joined


def test_run_build_writes_log_file(tmp_path):
    tooling, repo = _make_workspace(tmp_path, "gamma", _FAKE_HELPER)
    log = tmp_path / "build.log"
    run_build(BuildJob(fuzz_tooling_path=tooling, project="gamma",
                       src_path=repo, log_path=log))
    text = log.read_text()
    assert "Build Command:" in text and "Exit code: 0" in text


def test_run_build_failure_surfaces_tail_and_no_fuzzers(tmp_path, monkeypatch):
    tooling, repo = _make_workspace(tmp_path, "delta", _FAKE_HELPER)
    monkeypatch.setenv("FAKE_RC", "3")
    result = run_build(BuildJob(fuzz_tooling_path=tooling, project="delta", src_path=repo))
    assert not result.ok and result.returncode == 3
    assert "ERROR: build broke" in result.output_tail
    assert result.fuzzers == []                # a failed build collects nothing


def test_run_build_missing_helper_is_a_clean_failure(tmp_path):
    ws = tmp_path / "nohelper" / "fuzz-tooling"
    ws.mkdir(parents=True)
    result = run_build(BuildJob(fuzz_tooling_path=ws, project="x", src_path=tmp_path))
    assert not result.ok and "helper.py not found" in result.message


def test_run_build_times_out(tmp_path):
    slow = "import time\ntime.sleep(30)\n"
    tooling, repo = _make_workspace(tmp_path, "slow", slow)
    job = BuildJob(fuzz_tooling_path=tooling, project="slow", src_path=repo, timeout_s=1)
    start = time.monotonic()
    result = run_build(job)
    assert not result.ok and "timed out" in result.message
    assert time.monotonic() - start < 15          # killed promptly, not after 30s


def test_collect_fuzzers_filters_noise(tmp_path):
    out = tmp_path / "fuzz-tooling" / "build" / "out" / "proj"
    out.mkdir(parents=True)
    good = out / "proj_fuzzer"
    good.write_text("x"); good.chmod(good.stat().st_mode | stat.S_IEXEC)
    notexec = out / "data_fuzzer"; notexec.write_text("x")          # not executable
    for noise in ("llvm-symbolizer", "a.o", "b.so", "c.json"):
        p = out / noise; p.write_text("x"); p.chmod(p.stat().st_mode | stat.S_IEXEC)
    (out / "subdir").mkdir()
    got = collect_fuzzers(tmp_path / "fuzz-tooling", "proj")
    assert got == ["proj_fuzzer"]               # only the executable real fuzzer


def test_build_many_runs_isolated_workspaces_in_parallel(tmp_path):
    # Three independent workspaces; the fake sleeps briefly so a serial run would
    # take ~3x a single build. Parallel should finish close to one build's time.
    sleepy = _FAKE_HELPER.replace(
        'out.mkdir(parents=True, exist_ok=True)',
        'out.mkdir(parents=True, exist_ok=True)\nimport time as _t; _t.sleep(0.6)')
    jobs = []
    for name in ("p1", "p2", "p3"):
        tooling, repo = _make_workspace(tmp_path, name, sleepy)
        jobs.append(BuildJob(fuzz_tooling_path=tooling, project=name, src_path=repo))
    start = time.monotonic()
    results = build_many(jobs, max_workers=3)
    elapsed = time.monotonic() - start
    assert [r.project for r in results] == ["p1", "p2", "p3"]   # order preserved
    assert all(r.ok and r.fuzzers == [f"{r.project}_fuzzer"] for r in results)
    assert elapsed < 1.6        # parallel (~0.6s), not serial (~1.8s)


def test_build_many_isolates_a_single_failure(tmp_path, monkeypatch):
    ok_tooling, ok_repo = _make_workspace(tmp_path, "okp", _FAKE_HELPER)
    # second job points at a workspace with no helper -> fails, must not sink others
    bad_tooling = tmp_path / "badp" / "fuzz-tooling"
    bad_tooling.mkdir(parents=True)
    jobs = [
        BuildJob(fuzz_tooling_path=ok_tooling, project="okp", src_path=ok_repo),
        BuildJob(fuzz_tooling_path=bad_tooling, project="badp", src_path=tmp_path),
    ]
    results = build_many(jobs, max_workers=2)
    assert results[0].ok and results[0].fuzzers == ["okp_fuzzer"]
    assert not results[1].ok                     # failure contained to its own job


def test_build_many_empty_is_noop():
    assert build_many([]) == []


def test_truncate_output_keeps_head_and_tail():
    text = "\n".join(str(i) for i in range(100))
    out = truncate_output(text, head=10, tail=20)
    assert out.splitlines()[0] == "0" and out.splitlines()[-1] == "99"
    assert "70 lines omitted" in out
    # short text is returned verbatim
    assert truncate_output("a\nb\nc") == "a\nb\nc"


# --- high-level multi-workspace orchestration (builder.orchestrator) ----------

import types  # noqa: E402

from fuzzingbrain.builder.orchestrator import (  # noqa: E402
    build_bug,
    build_bugs,
    plan,
)


def _fake_spec(project: str):
    return types.SimpleNamespace(project=project)


def _fake_materialize_factory(helper_body: str):
    """A materialize() stand-in that lays down a fake-helper workspace instead of
    cloning + rendering, so orchestration is testable without network/docker."""

    def _materialize(spec, workspace, oss_fuzz, *, clone_repo, overwrite):
        ws = Path(workspace)
        (ws / "fuzz-tooling" / "infra").mkdir(parents=True, exist_ok=True)
        (ws / "fuzz-tooling" / "infra" / "helper.py").write_text(helper_body)
        (ws / "repo").mkdir(parents=True, exist_ok=True)
        return ws

    return _materialize


def test_plan_wires_spec_and_workspace_into_job(tmp_path):
    job = plan(
        tmp_path / "bugA", tmp_path / "ws", tmp_path / "oss", "memory",
        derive_spec=lambda b, with_description: _fake_spec("projA"),
        materialize=_fake_materialize_factory(_FAKE_HELPER),
    )
    assert job.project == "projA" and job.sanitizer == "memory"
    assert job.fuzz_tooling_path == tmp_path / "ws" / "fuzz-tooling"
    assert job.src_path == tmp_path / "ws" / "repo"
    assert job.label == "bugA"
    assert (tmp_path / "ws" / "fuzz-tooling" / "infra" / "helper.py").exists()


def test_build_bug_end_to_end_with_fakes(tmp_path):
    result = build_bug(
        tmp_path / "bugB", tmp_path / "ws", tmp_path / "oss",
        derive_spec=lambda b, with_description: _fake_spec("projB"),
        materialize=_fake_materialize_factory(_FAKE_HELPER),
    )
    assert result.ok and result.fuzzers == ["projB_fuzzer"]


def test_build_bugs_builds_each_in_its_own_workspace_in_parallel(tmp_path):
    bugs = [tmp_path / f"bug{i}" for i in range(3)]
    results = build_bugs(
        bugs, tmp_path / "root", tmp_path / "oss", max_workers=3,
        derive_spec=lambda b, with_description: _fake_spec(b.name),
        materialize=_fake_materialize_factory(_FAKE_HELPER),
    )
    assert [r.project for r in results] == ["bug0", "bug1", "bug2"]   # input order
    assert all(r.ok and r.fuzzers == [f"{r.project}_fuzzer"] for r in results)
    for i in range(3):                                                 # isolated dirs
        assert (tmp_path / "root" / f"bug{i}" / "fuzz-tooling").is_dir()


def test_build_bugs_contains_a_materialize_failure(tmp_path):
    def _materialize(spec, workspace, oss_fuzz, *, clone_repo, overwrite):
        if spec.project == "bad":
            raise RuntimeError("clone exploded")
        return _fake_materialize_factory(_FAKE_HELPER)(
            spec, workspace, oss_fuzz, clone_repo=clone_repo, overwrite=overwrite)

    results = build_bugs(
        [tmp_path / "good", tmp_path / "bad"], tmp_path / "root", tmp_path / "oss",
        derive_spec=lambda b, with_description: _fake_spec(b.name),
        materialize=_materialize,
    )
    assert results[0].ok                                  # healthy bug unaffected
    assert not results[1].ok and "workspace setup failed" in results[1].message
