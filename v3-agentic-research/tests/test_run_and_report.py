"""Preflight, the result file, and the crash package.

A run must always leave a readable result behind, and a crash must arrive with
the input that caused it.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from fbv3 import report, run as runmod
from fbv3.config import Task
from fbv3.store import Store


def task(tmp_path, **kw) -> Task:
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    (out / "fuzz").write_bytes(b"\x7fELF")
    data = {"name": "t", "project": "zlib", "stages": ["directed"],
            "prebuilt": [{"name": "fuzz", "binary": "fuzz", "asan_out": str(out)}]}
    data.update(kw)
    return Task.from_dict(data)


# -- preflight ---------------------------------------------------------------------------------


@pytest.fixture()
def stub(monkeypatch):
    """Docker and both logins succeed unless a test says otherwise."""
    state = {"images": {"img", "runner"}, "logins": {"claude": "claude: max", "codex": "codex: ChatGPT"},
             "docker": (0, b"27.0", b"")}

    def fake_run(argv, *, timeout, input=None):
        if argv[:2] == ["docker", "version"]:
            rc, so, se = state["docker"]
            return subprocess.CompletedProcess(argv, rc, so, se)
        if argv[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0 if argv[3] in state["images"] else 1, b"", b"")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(runmod.docker, "run", fake_run)
    monkeypatch.setattr(runmod.image, "ensure_image", lambda *a, **k: "fbv3-ws:test")

    def login(backend):
        value = state["logins"].get(backend)
        if value is None:
            raise runmod.auth.SubscriptionError(f"{backend} is not logged in")
        return value

    monkeypatch.setattr(runmod.auth, "CHECKS", {b: (lambda b=b: login(b)) for b in ("claude", "codex")})
    return state


def test_preflight_passes_when_everything_is_in_place(tmp_path, stub):
    pre = runmod.preflight(task(tmp_path, builder_image="img", runner_image="runner"))
    assert pre.ok, pre.text()
    assert "claude: max" in pre.text() and "codex: ChatGPT" in pre.text()


def test_preflight_fails_on_a_missing_image(tmp_path, stub):
    pre = runmod.preflight(task(tmp_path, builder_image="nope"))
    assert not pre.ok and "docker pull nope" in pre.text()


def test_preflight_fails_when_a_backend_is_not_logged_in(tmp_path, stub):
    stub["logins"].pop("codex")
    pre = runmod.preflight(task(tmp_path))
    assert not pre.ok and "codex is not logged in" in pre.text()


def test_preflight_fails_without_docker(tmp_path, stub):
    stub["docker"] = (1, b"", b"Cannot connect to the Docker daemon")
    pre = runmod.preflight(task(tmp_path))
    assert not pre.ok and "Cannot connect" in pre.text()


def test_preflight_checks_the_prebuilt_paths(tmp_path, stub):
    t = task(tmp_path)
    t.prebuilt[0].binary = "missing"
    pre = runmod.preflight(t)
    assert not pre.ok and "does not exist" in pre.text()
    t = task(tmp_path)
    t.prebuilt[0].harness_sources = ("/nope/h.c",)
    assert "not found" in runmod.preflight(t).text()


def test_preflight_only_checks_the_backends_a_task_uses(tmp_path, stub):
    stub["logins"].pop("codex")
    t = task(tmp_path, runner_image="runner", agents={"fallback": False, "roles": {
        r: {"backend": "claude"} for r in ("discoverer", "researcher", "harness", "reviewer", "seed",
                                           "mapper", "breaker", "finder", "verifier", "poc", "fp_seed")}})
    assert runmod.preflight(t).ok


# -- the result file ---------------------------------------------------------------------------


def filled_store(tmp_path):
    store = Store(tmp_path)
    store.start_run("zlib", {"project": "zlib"})
    store.set_harness("compress2", "accepted", binary="fuzz", overlay="/src/x.c", rounds=2,
                      builds={"address": "/a", "coverage": "/c"}, source_path="/src.c")
    vh = store.create_vh("compress2", function_name="deflate", finder_score=0.75, description="oob")
    store.move_vh(vh, "pending_poc")
    store.update_vh(vh, poc_status="crashed", evidence="see deflate.c:40")
    store.move_vh(vh, "poc_generated")
    store.create_vh("compress2", function_name="other")
    art = tmp_path / "crash.bin"
    art.write_bytes(b"\xff\xd8crash")
    store.add_crash("compress2", "key", "sig1", crash_class="heap-buffer-overflow", source="global",
                    vh_id=vh, artifact=str(art), top_frames=[["deflate", "deflate.c", "40"]],
                    output_tail="==1==ERROR: AddressSanitizer: heap-buffer-overflow")

    class R:
        session_id, role, backend, status = "s1", "finder", "codex", "completed"
        turns, duration_s, error = 5, 60.0, ""
        usage, session_dir = {}, "/tmp/s1"

    store.record_session(R(), "directed", "compress2")
    return store, vh


def test_the_summary_covers_every_part_of_a_run(tmp_path):
    store, vh = filled_store(tmp_path)
    s = report.summarize(store, status="completed", stages=["harness", "directed"],
                         logic_groups=[{"lg": "compress2", "vhs": 2, "pocs": 1, "crashes": 1,
                                        "functions_analysed": 7, "seeds": 12}], elapsed_s=600)
    assert s["status"] == "completed" and s["elapsed_minutes"] == 10.0
    assert s["distinct_bugs"] == 1 and s["vhs"] == {"total": 2, "by_status": {"pending_verify": 1,
                                                                             "poc_generated": 1},
                                                    "with_poc": 1}
    assert s["harnesses"][0]["builds"] == ["address", "coverage"]
    assert s["crashes"][0]["signature"] == "sig1" and s["crashes"][0]["where"] == "deflate"
    assert s["sessions"]["by_backend"] == {"codex": 1} and s["sessions"]["agent_minutes"] == 1.0


def test_the_package_keeps_the_input_and_writes_a_note(tmp_path):
    store, vh = filled_store(tmp_path)
    packaged = report.package(store, tmp_path)
    assert len(packaged) == 1
    blob = tmp_path / "results" / "pocs" / "compress2-sig1.bin"
    assert blob.read_bytes() == b"\xff\xd8crash"
    note = (tmp_path / "results" / "compress2-sig1.md").read_text()
    assert "heap-buffer-overflow" in note and "deflate" in note
    assert "see deflate.c:40" in note  # the verifier's evidence travels with the crash


def test_a_crash_whose_artifact_vanished_is_skipped(tmp_path):
    store = Store(tmp_path)
    store.start_run("t", {})
    store.add_crash("lg", "k", "sig", artifact=str(tmp_path / "gone.bin"))
    assert report.package(store, tmp_path) == []


def test_the_result_file_is_written_and_read_back(tmp_path):
    store, _ = filled_store(tmp_path)
    s = report.summarize(store, status="completed", elapsed_s=1)
    path = report.write_result(s, tmp_path)
    assert json.loads(path.read_text())["run_id"] == s["run_id"]
    assert report.load(tmp_path)["run_id"] == s["run_id"]


def test_a_run_without_a_result_file_is_summarized_from_the_store(tmp_path):
    store, _ = filled_store(tmp_path)
    store.close()
    loaded = report.load(tmp_path)
    assert loaded["vhs"]["total"] == 2 and loaded["distinct_bugs"] == 1


def test_loading_an_empty_directory_gives_nothing(tmp_path):
    assert report.load(tmp_path) == {}


def test_render_mentions_the_crashes_and_the_failures(tmp_path):
    store, _ = filled_store(tmp_path)
    s = report.summarize(store, status="completed", stages=["directed"], elapsed_s=60)
    s["sessions"]["by_status"]["timeout"] = 2
    text = report.render(s)
    assert "1 distinct bug" in text and "heap-buffer-overflow" in text
    assert "session failures: timeout 2" in text
    s["crashes"] = []
    assert "no crashes" in report.render(s)


# -- the runner --------------------------------------------------------------------------------


def test_a_run_writes_a_result_even_when_a_stage_explodes(tmp_path, stub, monkeypatch):
    t = task(tmp_path, output=str(tmp_path / "run"))
    monkeypatch.setattr(runmod.Workspace, "layout", lambda self: self)
    monkeypatch.setattr(runmod.Runner, "_source", lambda self: tmp_path / "src")

    def explode(*a, **k):
        raise RuntimeError("the workspace container died")

    monkeypatch.setattr(runmod, "DirectedRun", explode)
    summary = runmod.Runner(t).run()
    assert summary["status"] == "error" and "container died" in summary["error"]
    assert (tmp_path / "run" / "result.json").is_file()
    assert json.loads((tmp_path / "run" / "result.json").read_text())["status"] == "error"


def test_a_stopped_run_is_recorded_as_cancelled(tmp_path, stub, monkeypatch):
    t = task(tmp_path, output=str(tmp_path / "run2"))
    monkeypatch.setattr(runmod.Workspace, "layout", lambda self: self)
    monkeypatch.setattr(runmod.Runner, "_source", lambda self: tmp_path / "src")
    runner = runmod.Runner(t)
    runner.stop.set()
    summary = runner.run()
    assert summary["status"] == "cancelled"
    assert summary["run_dir"] == str(tmp_path / "run2")


def test_the_directed_stage_needs_a_target(tmp_path, stub, monkeypatch):
    t = Task.from_dict({"name": "t", "project": "p", "stages": ["harness", "directed"],
                        "builder_image": "img", "targets": [{"function": "f"}]})
    t.output = str(tmp_path / "run3")
    monkeypatch.setattr(runmod.Workspace, "layout", lambda self: self)
    monkeypatch.setattr(runmod.Workspace, "start", lambda self, *a, **k: "c")
    monkeypatch.setattr(runmod.Workspace, "stop", lambda self: None)
    monkeypatch.setattr(runmod.Workspace, "extract_llvm_tools", lambda self, image: None)
    monkeypatch.setattr(runmod.Runner, "_source", lambda self: tmp_path / "src")
    monkeypatch.setattr(runmod.HarnessStage, "run", lambda self, targets, deadline=None: [])
    summary = runmod.Runner(t).run()
    assert summary["status"] == "completed"
    assert "no usable fuzz target" in summary["end_reason"]


def test_viewing_a_directory_with_no_run_creates_nothing(tmp_path):
    assert report.load(tmp_path) == {}
    assert list(tmp_path.iterdir()) == []


def test_the_logic_group_fuzzes_the_sanitizer_that_was_asked_for(tmp_path, stub):
    from fbv3.harness.pipeline import HarnessOutcome

    t = Task.from_dict({"name": "t", "project": "p", "stages": ["harness", "directed"],
                        "builder_image": "img", "runner_image": "runner",
                        "targets": [{"function": "f"}],
                        "harness": {"sanitizers": ["address", "undefined"]},
                        "directed": {"sanitizer": "undefined"}})
    runner = runmod.Runner(t, out_dir=tmp_path / "run")
    h = HarnessOutcome("t1", "accepted", binary="fuzz", source_path="/s.c",
                       builds={"address": "/a", "undefined": "/u", "coverage": "/c"})
    lg = runner._logic_groups([h])[0]
    assert lg.sanitizer == "undefined" and str(lg.asan_out) == "/u"
    assert str(lg.coverage_out) == "/c"  # the index still comes from the coverage build


def test_a_missing_sanitizer_build_falls_back_and_says_so(tmp_path, stub, caplog):
    from fbv3.harness.pipeline import HarnessOutcome

    t = Task.from_dict({"name": "t", "project": "p", "stages": ["directed"],
                        "prebuilt": [{"name": "f", "binary": "f", "asan_out": str(tmp_path)}],
                        "directed": {"sanitizer": "memory"}})
    runner = runmod.Runner(t, out_dir=tmp_path / "run2")
    h = HarnessOutcome("t1", "accepted", binary="fuzz", builds={"address": "/a"})
    with caplog.at_level("WARNING"):
        lg = runner._logic_groups([h])[0]
    assert lg.sanitizer == "address" and "fuzzes the address one" in caplog.text


def test_the_report_carries_the_reasoning_not_just_the_counts(tmp_path):
    """``render`` answers "did it find anything" and nothing else. The reasoning
    is the product -- a rejected hypothesis is a finding about the code too --
    and it was reachable only by opening the SQLite file by hand."""
    store, vh = filled_store(tmp_path)
    store.add_harness_round("compress2", 1, verdict="reject", build_ok=1, binary="fuzz",
                            gate={"smoke": {"verdict": "ok", "edges": 812, "exec_s": 5141},
                                  "findings": [{"principle": "P2", "severity": "high", "line": 7,
                                                "message": "the length is not derived from the input"}]},
                            review={"violations": [{"principle": "P1", "blocking": True,
                                                    "lines": "42-50", "description": "NUL truncation",
                                                    "consequence": "half the input space is dead"}]})
    rejected = store.create_vh("compress2", function_name="late", finder_score=0.5,
                               description="missing bound on ImgNum")
    store.update_vh(rejected, score=0.12, verifier_session="v1",
                    verification_notes="the IsStealth throw at fx.c:2427 aborts translation first")
    store.move_vh(rejected, "rejected", reason="verifier score 0.12 below the PoC threshold")

    summary = report.summarize(store, status="completed", stages=["harness", "directed"],
                               logic_groups=[{"lg": "compress2", "seeds": 12, "functions_analysed": 7,
                                              "functions_queued": 40,
                                              "coverage_initial": {"functions_covered": 169,
                                                                   "functions_total": 1000},
                                              "coverage_final": {"functions_covered": 441}}],
                               elapsed_s=600)
    md = report.markdown(store, summary, tmp_path)

    assert "1 crash(es) reproduced" in md
    # the harness, round by round, with the gate and the reviewer in their own words
    assert "**round 1**, reject, build ok, smoke ok, 812 edges" in md
    assert "P2 [high] line 7: the length is not derived from the input" in md
    assert "P1 [blocking] lines 42-50: NUL truncation" in md
    assert "half the input space is dead" in md
    # every hypothesis, including the one nothing crashed for
    assert "### late — rejected" in md
    assert "missing bound on ImgNum" in md
    assert "the IsStealth throw at fx.c:2427 aborts translation first" in md
    assert "verifier score 0.12 below the PoC threshold" in md
    # the crash, with the input a human can replay
    assert "heap-buffer-overflow" in md and "crash.bin" in md
    assert "AddressSanitizer" in md
    # and what it cost
    assert "coverage: 169 -> 441 of 1000 functions" in md
    assert "| finder | 1 | codex | 0 | 1.0 |" in md


def test_the_report_is_written_next_to_the_run(tmp_path):
    store, _vh = filled_store(tmp_path)
    summary = report.summarize(store, status="completed", stages=["directed"], elapsed_s=1)
    path = report.write_markdown(store, summary, tmp_path)
    assert path == tmp_path / "report.md" and path.read_text().startswith("# zlib")


def test_a_crash_with_no_stack_trace_still_says_where_it_came_from(tmp_path):
    """libyaml's stack overflow prints nothing: the fault lands inside ASan's
    own interceptor with the stack gone, so there are no frames to name it.
    "segv at ?" throws away the one thing that locates it -- the hypothesis the
    input was generated for."""
    store = Store(tmp_path)
    store.start_run("libyaml", {"project": "libyaml"})
    store.set_harness("yaml_parser_load", "accepted", binary="libyaml_fuzzer")
    vh = store.create_vh("yaml_parser_load", function_name="yaml_parser_load_sequence",
                         function_file="/src/libyaml/src/loader.c", sink_line=360,
                         finder_score=0.5, description="unbounded recursion")
    art = tmp_path / "crash-deep"
    art.write_bytes(b"[" * 1000)
    store.add_crash("yaml_parser_load", "segv", "sig9", crash_class="segv", source="poc_agent",
                    vh_id=vh, artifact=str(art), top_frames=[],
                    output_tail="Running: /input\n")
    summary = report.summarize(store, status="completed", stages=["directed"],
                               logic_groups=[{"lg": "yaml_parser_load"}], elapsed_s=600)
    md = report.markdown(store, summary, tmp_path)

    assert "### segv at yaml_parser_load_sequence" in md
    assert "died on a fatal signal without printing a report" in md
    assert "**yaml_parser_load_sequence**" in md and "loader.c:360" in md


def test_a_crash_report_names_its_frames_the_way_a_human_reads_them(tmp_path):
    """A frame is (function, file, line). Joining them as if they were strings
    is a TypeError, and the only run that had crashes was recorded before the
    markdown report existed, so nothing caught it until the report was
    regenerated for that run."""
    store, vh = filled_store(tmp_path)
    summary = report.summarize(store, status="completed", stages=["directed"],
                               logic_groups=[{"lg": "compress2"}], elapsed_s=600)
    md = report.markdown(store, summary, tmp_path)
    assert "### heap-buffer-overflow at deflate (deflate.c:40)" in md


def test_a_run_recorded_before_a_column_existed_is_still_readable(tmp_path):
    """The report is how a finished run is read. A run whose SQLite predates a
    schema change must not take it down -- `fbv3 view --write` on the only run
    with a PoC died on the missing `cycle` column."""
    store = Store(tmp_path)
    store.start_run("old", {})
    store.add_crash("lg", "key", "sig1", crash_class="segv", source="global",
                    top_frames=[["f", "f.c", "1"]])
    store._db.execute("ALTER TABLE crashes DROP COLUMN cycle")
    store._db.commit()
    rows = store.crashes()
    assert len(rows) == 1 and rows[0]["cycle"] == [] and rows[0]["top_frames"] == [["f", "f.c", "1"]]
