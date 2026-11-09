"""The directed loop: the VH chain, the thresholds, and who may promote a VH.

Agent sessions, the workspace container and the fuzzers are stubbed; what is
under test is the orchestration FBv2 gets right and a naive port gets wrong:
the finder's threshold, the verifier's threshold, the fp-seed branch, the PoC
attempt limit, and the rule that only a crash the orchestrator reproduced
itself turns a VH into a PoC.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from fbv3.config import Task
from fbv3.directed.loop import DirectedRun, LogicGroup
from fbv3.fuzz.coverage import FunctionRow
from fbv3.runtime.session import SessionResult
from fbv3.store import Store


class FakePool:
    """Scripted sessions: ``files[role]`` is written into the session's out dir."""

    def __init__(self, root: Path):
        self.root = root
        self.files: dict[str, dict[str, object]] = {}
        self.status: dict[str, str] = {}
        self.calls: list[tuple[str, str]] = []
        self.prompts: list[tuple[str, str, str]] = []
        self.min_runtimes: list[tuple[str, float]] = []
        self.stopped = __import__("threading").Event()
        self._n = 0

    def run(self, role, *, scope, system, task, tools, ctx, session_root, subject="", deadline=None,
            min_runtime=0.0):
        self.min_runtimes.append((role, min_runtime))
        self._n += 1
        sid = f"{role}-{self._n}"
        self.calls.append((role, subject))
        self.prompts.append((role, system, task))
        d = Path(session_root) / sid
        (d / "out").mkdir(parents=True, exist_ok=True)
        payload = self.files.get(role)
        if callable(payload):  # a session that also leaves files of its own behind
            payload = payload(d / "out")
        for name, content in (payload or {}).items():
            path = d / "out" / name
            if name.endswith(".jsonl"):
                path.write_text("".join(json.dumps(r) + "\n" for r in content))
            else:
                path.write_text(json.dumps(content))
        return SessionResult(sid, role, "claude", self.status.get(role, "completed"), session_dir=str(d))


class FakeMonitor:
    """Reproduces only the blobs listed in ``crashing``."""

    def __init__(self, crashing=()):
        self.crashing = set(crashing)
        self.handled: list[tuple[str, str]] = []
        self.new_crashes = 0
        self.skipped: dict[str, int] = {}

    def handle(self, source, art, vh_id=None, output=None):
        self.handled.append((source, Path(art).name))
        if Path(art).name not in self.crashing:
            return None
        self.new_crashes += 1
        return {"crash_id": "c1", "new": True, "signature": "abcd1234", "key": "k",
                "crash_class": "heap-buffer-overflow", "describe": "wpng_byte at wpng.c:712",
                "artifact": str(art)}

    def stop(self):
        pass


def make(tmp_path, **directed) -> tuple[DirectedRun, FakePool, Store]:
    task = Task.from_dict({
        "name": "t", "project": "zlib", "stages": ["directed"],
        "prebuilt": [{"name": "fuzz", "binary": "fuzz", "asan_out": str(tmp_path / "out")}],
        "directed": {"duration_seconds": 3600, **directed},
    })
    store = Store(tmp_path / "run")
    store.start_run("t", {})
    pool = FakePool(tmp_path / "run")
    lg = LogicGroup(name="fuzz", binary="fuzz", asan_out=tmp_path / "out",
                    harness_sources=[], description="d", entries=("compress2",))
    run = DirectedRun(task, lg, store, pool, run_id="r1", lg_root=tmp_path / "lg",
                      ws_image="img", runner_image="img", src_dir=tmp_path / "src")
    run.ws.layout()
    run._harness_src = {"h.c": "int LLVMFuzzerTestOneInput(const uint8_t*d, size_t n){return 0;}"}
    run._deadline = time.monotonic() + 3600
    return run, pool, store


FN = {"name": "deflate", "file": "/src/zlib/deflate.c", "start_line": 10, "end_line": 90, "reason": "r"}
VH_ROW = {"function_name": "deflate", "description": "oob", "finder_score": 0.75,
          "important_controlflow": "c", "sink_code": "memcpy()", "sink_line": 42}


def queued(run) -> list:
    items = []
    while not run._bugq.empty():
        items.append(run._bugq.get_nowait())
    return items


# -- the finder --------------------------------------------------------------------------------


def test_the_finder_creates_vhs_and_queues_a_verification(tmp_path):
    run, pool, store = make(tmp_path)
    pool.files["finder"] = {"vhs.jsonl": [VH_ROW]}
    run._finder(FN)
    vhs = store.vhs("fuzz")
    assert len(vhs) == 1 and vhs[0]["status"] == "pending_verify"
    assert vhs[0]["sink_line"] == 42 and vhs[0]["finder_session"] == "finder-1"
    assert [item[0] for item in queued(run)] == [0]  # the verify priority


def test_a_low_scoring_vh_is_rejected_without_a_session(tmp_path):
    run, pool, store = make(tmp_path, verify_threshold=0.5)
    pool.files["finder"] = {"vhs.jsonl": [dict(VH_ROW, finder_score=0.25), VH_ROW]}
    run._finder(FN)
    statuses = sorted(v["status"] for v in store.vhs("fuzz"))
    assert statuses == ["pending_verify", "rejected"]
    assert len(queued(run)) == 1  # only the one above the threshold costs a verifier


def test_the_finder_prompt_carries_the_function_and_the_whole_harness(tmp_path):
    run, pool, _ = make(tmp_path)
    pool.files["finder"] = {"vhs.jsonl": []}
    run._finder(FN)
    role, system, task = pool.prompts[0]
    assert "deflate" in task and "sed -n '10,90p'" in task
    assert run._harness_src["h.c"] in system


# -- the verifier ------------------------------------------------------------------------------


def verdict(score, **kw):
    return {"verdict.json": {"score": score, "evidence": "e", "verification_notes": "n",
                             "poc_guidance": "g", **kw}}


def test_an_accepted_vh_goes_to_the_poc_queue(tmp_path):
    run, pool, store = make(tmp_path, poc_threshold=0.5)
    vh = store.create_vh("fuzz", function_name="deflate")
    pool.files["verifier"] = verdict(0.8)
    run._verify(vh)
    row = store.get_vh(vh)
    assert row["status"] == "pending_poc" and row["score"] == 0.8 and row["poc_guidance"] == "g"
    assert [i[0] for i in queued(run)] == [0]


def test_a_rejected_vh_goes_to_the_fp_seed_lane(tmp_path):
    """FBv2's lesson: a near miss is still worth fuzzing, at the lowest priority."""
    run, pool, store = make(tmp_path, poc_threshold=0.5)
    vh = store.create_vh("fuzz", function_name="deflate")
    pool.files["verifier"] = verdict(0.3)
    run._verify(vh)
    assert store.get_vh(vh)["status"] == "rejected"
    items = queued(run)
    assert [i[0] for i in items] == [2]  # the fp-seed priority, behind every bug task


def test_a_verifier_that_submits_nothing_rejects_the_vh(tmp_path):
    run, pool, store = make(tmp_path)
    vh = store.create_vh("fuzz", function_name="deflate")
    pool.status["verifier"] = "timeout"
    run._verify(vh)
    assert store.get_vh(vh)["status"] == "rejected"
    assert "no verdict" in store.vh_events(vh)[-1]["reason"]


def test_the_verifier_may_correct_the_hypothesis(tmp_path):
    run, pool, store = make(tmp_path)
    vh = store.create_vh("fuzz", function_name="deflate", description="old", important_controlflow="old")
    pool.files["verifier"] = verdict(0.9, description="actually an underflow", important_controlflow="new")
    run._verify(vh)
    row = store.get_vh(vh)
    assert row["description"] == "actually an underflow" and row["important_controlflow"] == "new"


def test_a_vh_is_verified_once(tmp_path):
    run, pool, store = make(tmp_path)
    vh = store.create_vh("fuzz", function_name="deflate")
    pool.files["verifier"] = verdict(0.1)
    run._verify(vh)
    run._verify(vh)  # a duplicate queue entry must not spend a second session
    assert len(pool.calls) == 1


# -- the PoC agent -----------------------------------------------------------------------------


def seed_poc(run, vh_id: str, names: list[str]) -> Path:
    d = run.ws.path(f"state/vh/{vh_id}/pocs")
    d.mkdir(parents=True, exist_ok=True)
    for n in names:
        (d / n).write_bytes(b"A")
    return d


def test_a_poc_counts_only_when_we_reproduce_it_ourselves(tmp_path):
    """The agent claims a crash; the VH moves only because the monitor saw one."""
    run, pool, store = make(tmp_path)
    vh = store.create_vh("fuzz", function_name="deflate")
    store.move_vh(vh, "pending_poc")
    pool.files["poc"] = {"poc_result.json": {"status": "crashed", "blob": "a-v1.bin"}}
    run._monitor = FakeMonitor(crashing=[])  # nothing reproduces
    seed_poc(run, vh, ["a-v1.bin"])
    run._poc(vh, attempt=0)
    row = store.get_vh(vh)
    assert row["status"] != "poc_generated"
    assert row["poc_status"] is None


def test_a_reproduced_crash_promotes_the_vh_with_the_crash_record(tmp_path):
    run, pool, store = make(tmp_path)
    vh = store.create_vh("fuzz", function_name="deflate")
    store.move_vh(vh, "pending_poc")
    pool.files["poc"] = {"poc_result.json": {"status": "crashed", "blob": "a-v2.bin"}}
    run._monitor = FakeMonitor(crashing=["a-v2.bin"])
    seed_poc(run, vh, ["a-v1.bin", "a-v2.bin"])
    run._poc(vh, attempt=0)
    row = store.get_vh(vh)
    assert row["status"] == "poc_generated" and row["poc_status"] == "crashed"
    assert row["crash_id"] == "c1" and "abcd1234" in store.vh_events(vh)[-1]["reason"]


def test_a_crash_the_agent_did_not_submit_still_counts(tmp_path):
    """A session that ran out of turns after crashing has still produced a PoC."""
    run, pool, store = make(tmp_path)
    vh = store.create_vh("fuzz", function_name="deflate")
    store.move_vh(vh, "pending_poc")
    pool.status["poc"] = "max_turns"
    run._monitor = FakeMonitor(crashing=["b-v3.bin"])
    seed_poc(run, vh, ["b-v1.bin", "b-v3.bin"])
    run._poc(vh, attempt=0)
    assert store.get_vh(vh)["status"] == "poc_generated"


def test_a_container_path_from_the_agent_is_resolved(tmp_path):
    run, pool, store = make(tmp_path)
    vh = store.create_vh("fuzz", function_name="deflate")
    store.move_vh(vh, "pending_poc")
    d = seed_poc(run, vh, ["c-v1.bin"])
    pool.files["poc"] = {"poc_result.json": {"status": "crashed",
                                             "blob": run.ws.to_container(d / "c-v1.bin")}}
    run._monitor = FakeMonitor(crashing=["c-v1.bin"])
    run._poc(vh, attempt=0)
    assert store.get_vh(vh)["status"] == "poc_generated"


def test_poc_attempts_are_limited_then_the_vh_fails(tmp_path):
    run, pool, store = make(tmp_path, max_poc_attempts=2)
    vh = store.create_vh("fuzz", function_name="deflate")
    store.move_vh(vh, "pending_poc")
    run._monitor = FakeMonitor(crashing=[])
    run._poc(vh, attempt=0)
    assert store.get_vh(vh)["status"] == "generating_poc"
    assert [i[3] for i in queued(run)] == [(vh, 1)]  # one retry queued
    run._poc(vh, attempt=1)
    assert store.get_vh(vh)["status"] == "poc_failed"
    assert queued(run) == []  # and no third attempt


def test_a_poc_out_of_time_fails_without_a_session(tmp_path):
    run, pool, store = make(tmp_path)
    vh = store.create_vh("fuzz", function_name="deflate")
    store.move_vh(vh, "pending_poc")
    run._deadline = time.monotonic() + 10
    run._poc(vh, attempt=0)
    assert store.get_vh(vh)["status"] == "poc_failed"
    assert pool.calls == []


def test_the_poc_prompt_carries_the_verifier_guidance(tmp_path):
    run, pool, store = make(tmp_path)
    vh = store.create_vh("fuzz", function_name="deflate")
    store.move_vh(vh, "pending_poc")
    store.update_vh(vh, poc_guidance="set the length to 0xffff", evidence="see deflate.c:40")
    run._monitor = FakeMonitor()
    run._poc(vh, attempt=0)
    _, _, task = pool.prompts[0]
    assert "0xffff" in task and "deflate.c:40" in task


# -- the queue ---------------------------------------------------------------------------------


def test_covered_functions_are_queued_most_used_first(tmp_path):
    run, _, _ = make(tmp_path)
    run._fn_rows = [FunctionRow("cold", "/src/a.c", 1, 9, 1), FunctionRow("hot", "/src/a.c", 10, 20, 900),
                    FunctionRow("never", "/src/a.c", 30, 40, 0)]
    assert run._queue_covered() == 2
    names = [item[3][0]["name"] for item in queued(run)]
    assert names == ["hot", "cold"]  # "never" was not executed


def test_the_function_queue_is_capped_and_never_repeats(tmp_path):
    run, _, _ = make(tmp_path, max_functions=2)
    run._fn_rows = [FunctionRow(f"f{i}", "/src/a.c", i, i + 5, 10 - i) for i in range(5)]
    assert run._queue_covered() == 2
    assert run._queue_covered() == 0  # nothing new on a second pass
    assert len(run._queued_fns) == 2


def test_the_mapper_list_comes_before_the_covered_set(tmp_path):
    run, _, _ = make(tmp_path)
    run._fn_rows = [FunctionRow("covered", "/src/a.c", 1, 9, 5)]
    run._fill_queue([{"name": "mapped", "file": "/src/b.c", "start_line": 1, "end_line": 4}])
    assert [i[3][0]["name"] for i in queued(run)] == ["mapped", "covered"]


def test_a_function_the_mapper_named_is_not_queued_twice(tmp_path):
    run, _, _ = make(tmp_path)
    run._fn_rows = [FunctionRow("both", "/src/a.c", 1, 9, 5)]
    run._fill_queue([{"name": "both", "file": "/src/a.c", "start_line": 1, "end_line": 9}])
    assert len(queued(run)) == 1


# -- seeds and the stage summary ------------------------------------------------------------------


def test_seed_sessions_are_counted_in_the_store(tmp_path):
    run, pool, store = make(tmp_path)
    pool.files["seed"] = {"seeds.jsonl": [{"sha1": "a", "size": 2, "corpus": "c1"},
                                          {"sha1": "b", "size": 3, "corpus": "c2"}]}
    run._seed_agent()
    assert store.seed_count("fuzz") == 2


def test_the_stage_stops_when_enough_crashes_are_found(tmp_path):
    run, _, _ = make(tmp_path, stop_on_crashes=1)
    run._monitor = FakeMonitor()
    run._monitor.new_crashes = 1
    run._on_crash({"new": True})
    assert run.stop_flag.is_set() and run._left() == 0.0


def test_a_stop_ends_the_time_budget_immediately(tmp_path):
    run, _, _ = make(tmp_path)
    assert run._left() > 1000
    run.stop_flag.set()
    assert run._left() == 0.0


@pytest.mark.parametrize("mode", ["legacy", "baseline"])
def test_the_baseline_modes_run_no_analysis_agents(tmp_path, mode):
    run, pool, store = make(tmp_path, mode=mode)
    vh = store.create_vh("fuzz", function_name="f")
    run._fp_seed(vh)
    assert pool.calls == []  # fp seeds belong to the directed mode only


def test_the_frontier_lane_is_off_without_a_coverage_build(tmp_path, monkeypatch):
    """coverage_frontier is the breaker's only tool: without it a session is wasted."""
    run, pool, _ = make(tmp_path, breaker=True)
    run._deadline = time.monotonic() + 1  # the scheduler returns at once
    run._schedule()
    assert pool.calls == []
    (run.ws.path("out/coverage")).mkdir(parents=True, exist_ok=True)
    (run.ws.path("out/coverage") / "fuzz").write_bytes(b"\x7fELF")
    assert run._has_coverage()


def test_the_summary_separates_skipped_artifacts_from_crashes(tmp_path):
    """Slow and greedy inputs are reported, but never as bugs."""
    run, _, store = make(tmp_path)
    run._monitor = FakeMonitor()
    run._monitor.skipped = {"timeout": 3, "out-of-memory": 1}
    store.add_crash("fuzz", "k", "sig1", crash_class="heap-buffer-overflow")
    report = run._finish()
    assert report["crashes"] == 1 and report["crash_signatures"] == ["sig1"]
    assert report["artifacts_skipped"] == {"timeout": 3, "out-of-memory": 1}


def test_no_hypothesis_is_left_mid_step_when_the_stage_ends(tmp_path):
    run, _, store = make(tmp_path)
    run._monitor = FakeMonitor()
    verifying = store.create_vh("fuzz", function_name="a")
    store.move_vh(verifying, "verifying")
    pocing = store.create_vh("fuzz", function_name="b")
    store.move_vh(pocing, "pending_poc")
    store.move_vh(pocing, "generating_poc")
    untouched = store.create_vh("fuzz", function_name="c")
    run._finish()
    assert store.get_vh(verifying)["status"] == "pending_verify"  # it never got a verdict
    assert store.get_vh(pocing)["status"] == "poc_failed"  # no attempt is coming
    assert store.get_vh(untouched)["status"] == "pending_verify"
    assert "the stage ended" in store.vh_events(verifying)[-1]["reason"]


def test_closing_leaves_a_finished_hypothesis_alone(tmp_path):
    run, _, store = make(tmp_path)
    run._monitor = FakeMonitor()
    done = store.create_vh("fuzz", function_name="a")
    store.move_vh(done, "pending_poc")
    store.move_vh(done, "generating_poc")
    store.move_vh(done, "poc_generated")
    assert run._close_open_vhs() == 0
    assert store.get_vh(done)["status"] == "poc_generated"


def test_a_crash_a_verifier_stumbled_on_is_reproduced_and_kept(tmp_path):
    """The verifier hand-wrote a crashing input; losing it would be absurd."""
    run, pool, store = make(tmp_path)
    run.ws.path("fuzz/poc/corpus").mkdir(parents=True, exist_ok=True)
    run._monitor = FakeMonitor(crashing=["sig-abc.bin"])
    vh = store.create_vh("fuzz", function_name="ConvertMeshMultiMaterial")

    def verdict_with_crash(out_dir):
        d = out_dir / "crashing"
        d.mkdir(parents=True, exist_ok=True)
        (d / "sig-abc.bin").write_bytes(b"AC3Db")
        return {"verdict.json": {"score": 1.0, "evidence": "confirmed by sanitizer report",
                                 "verification_notes": "n", "poc_guidance": "g"}}

    pool.files["verifier"] = verdict_with_crash
    run._verify(vh)
    assert run._monitor.handled == [("verifier_agent", "sig-abc.bin")]
    assert store.get_vh(vh)["status"] == "pending_poc"  # the PoC agent still has to own it
    # and the PoC fuzzer gets it to mutate around
    assert [p.name for p in run.ws.path("fuzz/poc/corpus").iterdir()] == ["verifier-sig-abc.bin"]


def test_harvesting_is_quiet_when_a_session_crashed_on_nothing(tmp_path):
    run, pool, store = make(tmp_path)
    run._monitor = FakeMonitor()
    vh = store.create_vh("fuzz", function_name="f")
    pool.files["verifier"] = verdict(0.9)
    run._verify(vh)
    assert run._monitor.handled == []


def test_the_projects_seed_corpus_fills_the_corpus(tmp_path):
    import zipfile

    run, _, store = make(tmp_path)
    run.ws.path("out/address").mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(run.ws.path("out/address") / "fuzz_seed_corpus.zip", "w") as zf:
        zf.writestr("a.bin", b"first")
        zf.writestr("sub/", b"")
        zf.writestr("b.bin", b"second")
    run._seed_corpus()
    files = sorted(p.read_bytes() for p in run.ws.path("fuzz/global/corpus").iterdir())
    assert files == [b"first", b"second"]  # the directory entry is not an input


def test_a_seed_corpus_symlinked_into_the_container_is_reported(tmp_path, caplog):
    """In a build's /out the sidecar is often a symlink to an absolute /out/... path."""
    run, _, store = make(tmp_path)
    run.lg.asan_out.mkdir(parents=True, exist_ok=True)
    (run.lg.asan_out / "fuzz_seed_corpus.zip").symlink_to("/out/seed_corpus.zip")
    with caplog.at_level("WARNING"):
        run._seed_corpus()
    assert list(run.ws.path("fuzz/global/corpus").iterdir()) == []
    assert "only resolves in the container" in caplog.text


def test_the_workspace_copy_wins_over_the_unresolvable_one(tmp_path):
    import zipfile

    run, _, store = make(tmp_path)
    run.lg.asan_out.mkdir(parents=True, exist_ok=True)
    (run.lg.asan_out / "fuzz_seed_corpus.zip").symlink_to("/out/seed_corpus.zip")
    run.ws.path("out/address").mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(run.ws.path("out/address") / "fuzz_seed_corpus.zip", "w") as zf:
        zf.writestr("a.bin", b"resolved")
    run._seed_corpus()
    assert [p.read_bytes() for p in run.ws.path("fuzz/global/corpus").iterdir()] == [b"resolved"]


def test_one_bad_coverage_sample_does_not_end_the_timeline(tmp_path, monkeypatch):
    run, _, store = make(tmp_path)
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("the container went away")
        store.add_coverage("fuzz", float(calls["n"]), edges=10)

    monkeypatch.setattr(run, "_sample_once", flaky)
    monkeypatch.setattr("fbv3.directed.loop.SAMPLE_S", 0.01)
    import threading

    t = threading.Thread(target=run._sampler, daemon=True)
    t.start()
    for _ in range(200):
        if calls["n"] >= 3:
            break
        __import__("time").sleep(0.01)
    run._stop_threads.set()
    t.join(timeout=5)
    assert calls["n"] >= 3  # it kept sampling after the failure
    assert store.coverage("fuzz")


def test_a_failing_coverage_export_does_not_kill_the_refresh(tmp_path, monkeypatch):
    """This thread is phase 2 of the queue: if it dies the run stops growing work."""
    run, _, store = make(tmp_path, coverage_interval_s=0)
    rounds = {"n": 0}

    def flaky(timeout_s=600):
        rounds["n"] += 1
        if rounds["n"] == 1:
            raise RuntimeError("llvm-cov is missing")
        if rounds["n"] == 2:
            return [], "no coverage build"
        run._stop_threads.set()
        return [FunctionRow("deflate", "/src/a.c", 1, 9, 5)], ""

    monkeypatch.setattr(run, "_collect_coverage", flaky)
    run._coverage_refresh()
    assert rounds["n"] == 3  # it survived the raise and the error
    assert "deflate" in run._queued_fns


@pytest.mark.parametrize("afl,expected", [
    (False, ["fuzzers", "seed"]),   # libFuzzer reloads: no idle fuzzing time
    (True, ["seed", "fuzzers"]),    # AFL copies its inputs once, at startup
])
def test_the_engine_decides_whether_seeds_come_before_the_fuzzer(tmp_path, monkeypatch, afl, expected):
    run, _, _ = make(tmp_path)
    order = []
    monkeypatch.setattr(run, "_prepare", lambda: None)
    monkeypatch.setattr(run, "_build_function_index", lambda: {})
    monkeypatch.setattr(run, "_detect_engine", lambda: afl)
    monkeypatch.setattr(run, "_seed_agent", lambda: order.append("seed"))
    monkeypatch.setattr(run, "_start_fuzzers", lambda: order.append("fuzzers"))
    monkeypatch.setattr(run, "_sampler", lambda: None)
    monkeypatch.setattr(run, "_mapper", lambda: [])
    monkeypatch.setattr(run, "_schedule", lambda: None)
    monkeypatch.setattr(run, "_finish", lambda: {})
    run.run()
    assert order == expected


def test_a_session_that_cannot_finish_is_not_started(tmp_path):
    """Two live runs lost a breaker at 394s and an fp-seed at 161s this way."""
    run, pool, store = make(tmp_path)
    roles = run.task.agents.roles
    run._deadline = time.monotonic() + 300  # less than a third of most budgets
    assert not run._enough_time("breaker")  # 1200s budget -> needs 400s
    assert not run._enough_time("verifier")
    run._breaker()
    vh = store.create_vh("fuzz", function_name="f")
    run._verify(vh)
    run._fp_seed(vh)
    assert pool.calls == []
    assert store.get_vh(vh)["status"] == "pending_verify"  # left honestly pending
    run._deadline = time.monotonic() + 3600
    assert all(run._enough_time(r) for r in ("breaker", "verifier", "finder", "poc", "fp_seed"))
    assert roles["breaker"].timeout_s / 3 < 3600


def test_the_bar_is_a_third_of_the_role_budget_with_a_floor(tmp_path):
    run, _, _ = make(tmp_path)
    run.task.agents.roles["finder"].timeout_s = 90  # a third would be 30s; the floor is 150s
    run._deadline = time.monotonic() + 140
    assert not run._enough_time("finder")
    run._deadline = time.monotonic() + 200
    assert run._enough_time("finder")
    run.task.agents.roles["finder"].timeout_s = 1800  # a big budget sets its own bar
    assert not run._enough_time("finder")
    run._deadline = time.monotonic() + 700
    assert run._enough_time("finder")


def test_the_summary_says_where_the_function_index_came_from(tmp_path, monkeypatch):
    """A run with no index at all must not look like a normal one."""
    run, _, store = make(tmp_path)
    run._monitor = FakeMonitor()
    monkeypatch.setattr(run, "_prepare", lambda: None)
    monkeypatch.setattr(run, "_collect_coverage", lambda timeout_s=600: ([], "llvm-profdata: not found"))
    monkeypatch.setattr("fbv3.directed.loop.symbols.linked_functions",
                        lambda ws, **kw: ([], "no debug info"))
    monkeypatch.setattr(run, "_start_fuzzers", lambda: None)
    monkeypatch.setattr(run, "_sampler", lambda: None)
    monkeypatch.setattr(run, "_seed_agent", lambda: None)
    monkeypatch.setattr(run, "_mapper", lambda: [])
    monkeypatch.setattr(run, "_schedule", lambda: None)
    out = run.run()
    assert out["function_index"] == {"source": "none", "functions": 0, "error": "no debug info"}


def test_the_summary_counts_functions_a_finder_reached_not_queued(tmp_path):
    """A 900s stage can queue forty functions and reach two; saying 40 is a lie."""
    run, pool, store = make(tmp_path)
    run._monitor = FakeMonitor()
    run._fn_rows = [FunctionRow(f"f{i}", "/src/a.c", i, i + 4, 9 - i) for i in range(5)]
    run._queue_covered()
    assert len(run._queued_fns) == 5
    pool.files["finder"] = {"vhs.jsonl": []}
    run._finder({"name": "f0", "file": "/src/a.c", "start_line": 0, "end_line": 4})
    report = run._finish()
    assert report["functions_analysed"] == 1
    assert report["functions_queued"] == 5


def test_a_skipped_finder_is_not_counted_as_analysed(tmp_path):
    run, pool, store = make(tmp_path)
    run._monitor = FakeMonitor()
    pool.status["finder"] = "skipped"
    run._finder({"name": "f0", "file": "/src/a.c", "start_line": 0, "end_line": 4})
    assert run._finish()["functions_analysed"] == 0


def test_each_role_tells_the_pool_how_much_time_it_needs(tmp_path):
    run, pool, store = make(tmp_path)
    run._monitor = FakeMonitor()
    pool.files["finder"] = {"vhs.jsonl": []}
    run._finder({"name": "f", "file": "/src/a.c", "start_line": 1, "end_line": 9})
    role, bar = pool.min_runtimes[-1]
    assert role == "finder" and bar == max(150.0, run.task.agents.roles["finder"].timeout_s / 3)


def test_the_breaker_waits_until_the_bug_lane_is_idle(tmp_path, monkeypatch):
    """It exists to open ground for the finders; taking the only slot while they
    queue is what left one run with 200 functions queued and zero analysed."""
    run, pool, store = make(tmp_path, breaker=True)
    run.ws.path("out/coverage").mkdir(parents=True, exist_ok=True)
    (run.ws.path("out/coverage") / "fuzz").write_bytes(b"\x7fELF")  # a coverage build exists
    order = []
    monkeypatch.setattr(run, "_breaker", lambda: order.append("breaker"))
    monkeypatch.setattr(run, "_coverage_refresh", lambda: None)

    def finder(fn):
        order.append("finder:" + fn["name"])
        if len(order) >= 2:
            run.stop_flag.set()  # end the stage once both have run

    monkeypatch.setattr(run, "_finder", finder)
    run._enqueue(1, run._finder, {"name": "a"})
    run._enqueue(1, run._finder, {"name": "b"})
    run._deadline = time.monotonic() + 3600
    run._schedule()
    # every queued finder ran, and the breaker never took the slot from them
    assert sorted(order) == ["finder:a", "finder:b"]


def test_the_breaker_runs_when_nothing_else_needs_the_slot(tmp_path, monkeypatch):
    run, pool, store = make(tmp_path, breaker=True)
    run.ws.path("out/coverage").mkdir(parents=True, exist_ok=True)
    (run.ws.path("out/coverage") / "fuzz").write_bytes(b"\x7fELF")
    ran = []

    def breaker():
        ran.append("breaker")
        run.stop_flag.set()

    monkeypatch.setattr(run, "_breaker", breaker)
    monkeypatch.setattr(run, "_coverage_refresh", lambda: None)
    run._deadline = time.monotonic() + 3600  # the breaker needs a third of its budget
    run._schedule()
    assert ran == ["breaker"]
