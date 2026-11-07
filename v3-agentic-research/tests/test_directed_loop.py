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
        self.stopped = __import__("threading").Event()
        self._n = 0

    def run(self, role, *, scope, system, task, tools, ctx, session_root, subject="", deadline=None):
        self._n += 1
        sid = f"{role}-{self._n}"
        self.calls.append((role, subject))
        self.prompts.append((role, system, task))
        d = Path(session_root) / sid
        (d / "out").mkdir(parents=True, exist_ok=True)
        for name, content in (self.files.get(role) or {}).items():
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
