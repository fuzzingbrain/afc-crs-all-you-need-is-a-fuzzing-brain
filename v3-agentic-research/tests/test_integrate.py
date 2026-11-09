"""The integrate stage: an agent-written build.sh makes any tree an input.

The gate here has one check the harness gate does not, and it is the one that
matters most: a build that compiled the library without the sanitizer flags
succeeds, fuzzes fast and finds nothing. These tests pin that down, plus what
the stage hands downstream so the later stages need no special case.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fbv3.build import workspace_build
from fbv3.config import Target, Task
from fbv3.fuzz.coverage import FunctionRow
from fbv3.harness import integrate
from fbv3.runtime.session import SessionResult
from fbv3.store import Store

HARNESS = """
#include <stdint.h>
#include "mylib.h"
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return mylib_parse(d, n, 0, 0); }
"""
GOOD_SH = """#!/bin/bash -eu
$CC $CFLAGS -I. -c mylib.c -o mylib.o
ar rcs libmylib.a mylib.o
$CC $CFLAGS -I. -c fuzz/h.c -o h.o
$CXX $CXXFLAGS h.o libmylib.a $LIB_FUZZING_ENGINE -o $OUT/mylib_fuzzer
"""


class FakePool:
    def __init__(self, root: Path):
        self.root, self.files, self.status = root, {}, {}
        self.calls, self.prompts, self.min_runtimes = [], [], []
        self.stopped = __import__("threading").Event()
        self._n = 0

    def run(self, role, *, scope, system, task, tools, ctx, session_root, subject="", deadline=None,
            min_runtime=0.0):
        self.min_runtimes.append((role, min_runtime))
        self._n += 1
        sid = f"{role}-{self._n}"
        self.calls.append(role)
        self.prompts.append((role, system, task))
        d = Path(session_root) / sid
        (d / "out").mkdir(parents=True, exist_ok=True)
        payload = self.files.get(role)
        if callable(payload):
            payload = payload(self._n)
        for name, content in (payload or {}).items():
            (d / "out" / name).write_text(content if isinstance(content, str) else json.dumps(content))
        return SessionResult(sid, role, "claude", self.status.get(role, "completed"), session_dir=str(d))


class FakeWorkspace:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.container = "fake"
        self.smoke = ("#2 INITED cov: 21 ft: 22 exec/s: 0 rss: 33Mb\n"
                      "#512 NEW cov: 400 ft: 430 exec/s: 9000 rss: 35Mb\n")

    def layout(self):
        for n in ("builds", "sessions", "out/address", "logs", "out/llvm"):
            (self.root / n).mkdir(parents=True, exist_ok=True)
        return self

    def path(self, rel: str) -> Path:
        return self.root / rel

    def to_container(self, host) -> str:
        return "/ws/" + str(Path(host).resolve().relative_to(self.root.resolve()))

    def exec(self, argv, *, timeout=600, env=None, workdir="/ws", stdin=None):
        import subprocess

        return subprocess.CompletedProcess(argv, 0, self.smoke.encode(), b"")


def submission(tmp_path, *, binary="mylib_fuzzer", build_sh=GOOD_SH, ok=True, write_binary=True):
    out = tmp_path / "ws" / "builds" / "integrate" / "i01" / "out"
    out.mkdir(parents=True, exist_ok=True)
    if write_binary:
        (out / binary).write_bytes(b"\x7fELF")
    return {"build.json": {"ok": ok, "binary": binary, "build_dir": str(out.parent),
                           "harness_path": "fuzz/h.c", "harness_code": HARNESS,
                           "build_sh": build_sh, "notes": "static lib, flags via CFLAGS"}}


def make(tmp_path, monkeypatch, *, functions=3, cov_ok=True, **cfg):
    task = Task.from_dict({"name": "t", "project": "mylib", "stages": ["integrate", "directed"],
                           "source_dir": str(tmp_path / "src"),
                           "targets": [{"function": "mylib_parse"}], "integrate": cfg})
    (tmp_path / "src").mkdir(exist_ok=True)
    store = Store(tmp_path / "run")
    store.start_run("t", {})
    ws = FakeWorkspace(tmp_path / "ws").layout()
    pool = FakePool(tmp_path / "ws" / "sessions")

    built = []

    def fake_build(**kw):
        built.append(kw)
        out = Path(kw["build_dir"]) / "out"
        out.mkdir(parents=True, exist_ok=True)
        if cov_ok:
            (out / kw.get("expected_binary", "mylib_fuzzer")).write_bytes(b"\x7fELF")
            return workspace_build.BuildResult(True, kw["sanitizer"], str(out),
                                               binary=kw.get("expected_binary", "mylib_fuzzer"))
        return workspace_build.BuildResult(False, kw["sanitizer"], str(out),
                                           error="configure: error: no toolchain")

    monkeypatch.setattr(integrate, "build_workspace", fake_build)
    rows = [FunctionRow(f"f{i}", "/src/mylib.c", i, i + 5, 0) for i in range(functions)]
    monkeypatch.setattr(integrate, "instrumented_functions",
                        lambda **kw: (rows, "") if functions >= 0 else ([], "export failed"))
    stage = integrate.IntegrateStage(task, store, pool, ws, run_id="r1", run_dir=tmp_path / "run")
    return stage, pool, store, ws, built


# -- the decisive check ------------------------------------------------------------------------


def test_an_uninstrumented_library_is_rejected_with_the_reason(tmp_path, monkeypatch):
    """The build works, the fuzzer runs, and no bug in the library can be found."""
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, functions=0, max_rounds=1)
    pool.files["integrator"] = submission(tmp_path)
    out = stage.run(Target("mylib_parse"))
    assert out.status == "failed" and not out.usable
    assert store.harness_rounds("integrate")[0]["verdict"] == "instrumentation"
    # and the agent is told exactly what to change
    assert len(pool.prompts) == 1  # max_rounds=1, so no retry here
    rounds = store.harness_rounds("integrate")
    assert json.loads(rounds[0]["gate"])["functions"] == 0


def test_the_reason_reaches_the_next_round(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, functions=0, max_rounds=2)
    pool.files["integrator"] = submission(tmp_path)
    stage.run(Target("mylib_parse"))
    second = pool.prompts[1][2]
    assert "library is NOT instrumented" in second
    assert "$CFLAGS" in second and "./configure" in second
    assert GOOD_SH.strip().splitlines()[1] in second  # its own build.sh comes back with it


def test_an_instrumented_build_passes_and_carries_both_builds(tmp_path, monkeypatch):
    stage, pool, store, ws, built = make(tmp_path, monkeypatch, functions=12)
    pool.files["integrator"] = submission(tmp_path)
    out = stage.run(Target("mylib_parse"))
    assert out.status == "integrated" and out.usable
    assert out.binary == "mylib_fuzzer" and out.harness_path == "fuzz/h.c"
    assert set(out.builds) == {"address", "coverage"}  # the directed stage needs both
    assert out.build_sh == GOOD_SH and out.source_dir == str(tmp_path / "src")
    assert Path(out.source_path).read_text() == HARNESS
    assert [k["sanitizer"] for k in built] == ["coverage"]
    assert store.harnesses()[0]["status"] == "integrated"


def test_a_coverage_build_that_fails_is_reported_not_passed(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, cov_ok=False, max_rounds=2)
    pool.files["integrator"] = submission(tmp_path)
    out = stage.run(Target("mylib_parse"))
    assert out.status == "failed"
    assert store.harness_rounds("integrate")[0]["verdict"] == "coverage_build"
    assert "SANITIZER=coverage" in pool.prompts[1][2]


def test_a_dead_harness_is_sent_back(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, max_rounds=2)
    ws.smoke = "#2 INITED cov: 2 ft: 2 exec/s: 9000 rss: 33Mb\n"
    pool.files["integrator"] = submission(tmp_path)
    stage.run(Target("mylib_parse"))
    assert "barely covers anything" in pool.prompts[1][2]


def test_a_target_that_cannot_run_is_sent_back(tmp_path, monkeypatch):
    """A link that succeeds but produces an unrunnable binary is not a build."""
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, max_rounds=2)
    ws.smoke = "error while loading shared libraries: libmylib.so.1: cannot open shared object file\n"
    pool.files["integrator"] = submission(tmp_path)
    stage.run(Target("mylib_parse"))
    assert "does not run at all" in pool.prompts[1][2]
    assert "shared libraries" in pool.prompts[1][2]


def test_a_submission_without_a_binary_is_not_believed(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, max_rounds=1)
    # The agent reported a successful build, but $OUT has no such file.
    pool.files["integrator"] = submission(tmp_path, write_binary=False)
    assert stage.run(Target("mylib_parse")).status == "failed"
    assert store.harness_rounds("integrate")[0]["verdict"] == "binary"


def test_a_session_that_never_built_gets_told_to_build_early(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, max_rounds=2)
    pool.files["integrator"] = {}
    out = stage.run(Target("mylib_parse"))
    assert out.status == "failed"
    assert [r["verdict"] for r in store.harness_rounds("integrate")] == ["no_build", "no_build"]
    assert "Build early and often" in pool.prompts[1][2]


def test_the_last_build_is_used_when_the_session_ends_early(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, functions=5, max_rounds=1)
    sub = submission(tmp_path)["build.json"]
    pool.status["integrator"] = "max_turns"
    pool.files["integrator"] = {"last_build.json": sub}
    out = stage.run(Target("mylib_parse"))
    assert out.status == "integrated"


# -- what the stage tells the agent -------------------------------------------------------------


def test_the_prompt_names_the_entry_point_and_the_network_rule(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, functions=4)
    pool.files["integrator"] = submission(tmp_path)
    stage.run(Target("mylib_parse", "parses a buffer", entries=("mylib_parse2",)))
    _, system, task = pool.prompts[0]
    assert "mylib_parse" in task and "parses a buffer" in task and "mylib_parse2" in task
    assert "NO network" in system
    assert "existing integration first" in system  # reuse OSS-Fuzz when the tree has it


def test_network_may_be_allowed_explicitly(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, functions=4, allow_network=True)
    pool.files["integrator"] = submission(tmp_path)
    stage.run(Target("mylib_parse"))
    assert "may use the network" in pool.prompts[0][1]


def test_the_stage_runs_without_a_named_target(tmp_path, monkeypatch):
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, functions=4)
    pool.files["integrator"] = submission(tmp_path)
    assert stage.run(None).status == "integrated"
    assert "No entry point was named" in pool.prompts[0][2]


# -- the builder's own refusals ------------------------------------------------------------------


def test_the_builder_refuses_a_harness_path_outside_the_tree(tmp_path):
    res = workspace_build.build_workspace(
        base_image="img", source_dir=tmp_path, build_sh="true",
        harness_files={"../escape.c": "x"}, build_dir=tmp_path / "b")
    assert not res.ok and "relative to the source tree" in res.error


def test_the_builder_needs_a_tree_and_a_harness(tmp_path):
    res = workspace_build.build_workspace(base_image="img", source_dir=tmp_path / "nope",
                                          build_sh="true", harness_files={"h.c": "x"},
                                          build_dir=tmp_path / "b")
    assert not res.ok and "does not exist" in res.error
    res = workspace_build.build_workspace(base_image="img", source_dir=tmp_path, build_sh="true",
                                          harness_files={}, build_dir=tmp_path / "b")
    assert not res.ok and "no harness source" in res.error


@pytest.mark.parametrize("stages,ok", [(["integrate", "directed"], True), (["harness"], False)])
def test_a_plain_tree_needs_no_project_image(tmp_path, stages, ok):
    from fbv3.config import ConfigError

    data = {"name": "t", "project": "p", "stages": stages, "targets": [{"function": "f"}]}
    if ok:
        data["source_dir"] = str(tmp_path)
        assert Task.from_dict(data).builder_image == ""
    else:
        with pytest.raises(ConfigError, match="builder_image"):
            Task.from_dict(data)


def test_a_vanished_container_is_not_blamed_on_the_harness(tmp_path, monkeypatch):
    """A workspace container can be OOM-killed or cleaned away mid-run."""
    stage, pool, store, ws, _ = make(tmp_path, monkeypatch, functions=8, max_rounds=2)
    ws.smoke = "Error: No such container: fbv3-ws-5d4910024f\n"
    pool.files["integrator"] = submission(tmp_path)
    stage.run(Target("mylib_parse"))
    assert store.harness_rounds("integrate")[0]["verdict"] == "infra"
    second = pool.prompts[1][2]
    assert "INFRA:" in second and "Nothing is wrong with your build" in second
    assert "barely covers anything" not in second  # not blamed for reachability either


def test_an_integrated_run_takes_its_llvm_tools_from_the_toolchain_image(tmp_path, monkeypatch):
    """Without them the directed stage silently loses its whole function index."""
    from fbv3 import run as runmod

    task = Task.from_dict({"name": "t", "project": "p", "stages": ["integrate", "directed"],
                           "source_dir": str(tmp_path), "output": str(tmp_path / "run")})
    asked = []
    monkeypatch.setattr(runmod.Workspace, "layout", lambda self: self)
    monkeypatch.setattr(runmod.Workspace, "start", lambda self, *a, **k: "c")
    monkeypatch.setattr(runmod.Workspace, "stop", lambda self: None)
    monkeypatch.setattr(runmod.Workspace, "extract_llvm_tools",
                        lambda self, image: asked.append(image))
    monkeypatch.setattr(runmod.Runner, "_source", lambda self: tmp_path)
    monkeypatch.setattr(runmod.image, "ensure_image", lambda *a, **k: "ws:test")
    monkeypatch.setattr(runmod.IntegrateStage, "run",
                        lambda self, target: integrate.Integration("integrate", "failed"))
    monkeypatch.setattr(runmod.docker, "kill_run_containers", lambda rid: 0)
    runmod.Runner(task).run()
    assert asked == [task.integrate.base_image]
