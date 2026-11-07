import json

import pytest

from fbv3.store import Store


class FakeResult:
    def __init__(self, sid="s1", role="finder", backend="codex", status="completed"):
        self.session_id, self.role, self.backend, self.status = sid, role, backend, status
        self.turns, self.duration_s, self.error = 7, 12.5, ""
        self.usage, self.session_dir = {"input_tokens": 10}, "/tmp/s1"


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path)
    s.start_run("t", {"project": "zlib"})
    yield s
    s.close()


def test_run_lifecycle_and_event_stream(store, tmp_path):
    assert store.run()["status"] == "running"
    store.end_run("completed", "work done")
    assert store.run()["status"] == "completed"
    events = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert [e["event"] for e in events] == ["run_started", "run_ended"]


def test_sessions_are_recorded_by_scope(store):
    store.record_session(FakeResult(), "directed", "lg/compress2")
    store.record_session(FakeResult("s2", role="poc", backend="claude"), "directed", "lg/x")
    store.record_session(FakeResult("s3", role="harness"), "harness", "t")
    assert len(store.sessions()) == 3
    assert {s["id"] for s in store.sessions("directed")} == {"s1", "s2"}
    assert json.loads(store.sessions("harness")[0]["usage"]) == {"input_tokens": 10}


def test_vh_lifecycle(store):
    vh = store.create_vh("lg", function_name="deflate", finder_score=0.75, description="oob")
    assert store.get_vh(vh)["status"] == "pending_verify"
    assert store.move_vh(vh, "verifying", frm=("pending_verify",))
    store.update_vh(vh, score=0.8, evidence="e", poc_guidance="g")
    assert store.get_vh(vh)["score"] == 0.8
    assert store.move_vh(vh, "pending_poc")
    assert store.move_vh(vh, "generating_poc", frm=("pending_poc",))
    assert store.move_vh(vh, "poc_generated")
    assert [e["to_status"] for e in store.vh_events(vh)][-1] == "poc_generated"


def test_move_vh_respects_the_source_status(store):
    vh = store.create_vh("lg", function_name="f")
    assert not store.move_vh(vh, "poc_generated", frm=("generating_poc",))
    assert store.get_vh(vh)["status"] == "pending_verify"


def test_update_vh_rejects_unknown_fields(store):
    vh = store.create_vh("lg", function_name="f")
    with pytest.raises(KeyError):
        store.update_vh(vh, status="poc_generated")


def test_an_invalid_status_cannot_be_written(store):
    vh = store.create_vh("lg", function_name="f")
    with pytest.raises(AssertionError):
        store.move_vh(vh, "solved")


def test_crashes_are_deduplicated_per_logic_group(store):
    first, new1 = store.add_crash("lg", "key-a", "aaaa", crash_class="heap-buffer-overflow", source="global")
    second, new2 = store.add_crash("lg", "key-a", "aaaa", source="poc")
    assert new1 and not new2 and first == second
    _, new3 = store.add_crash("other", "key-a", "aaaa")
    assert new3  # the same signature in another logic group is its own crash
    assert len(store.crashes("lg")) == 1
    assert store.crashes("lg")[0]["crash_class"] == "heap-buffer-overflow"


def test_seeds_and_coverage(store):
    store.add_seeds("lg", "s1", "seed", [{"sha1": "a", "size": 3, "corpus": "c1"},
                                         {"sha1": "b", "size": 4, "corpus": "c2"}])
    assert store.seed_count("lg") == 2
    store.add_coverage("lg", 15.0, edges=100, exec_s=900, functions_covered=12)
    store.add_coverage("lg", 30.0, edges=140)
    rows = store.coverage("lg")
    assert [r["t"] for r in rows] == [15.0, 30.0]
    assert rows[0]["functions_covered"] == 12


def test_harness_rounds_and_result(store):
    store.add_harness_round("compress2", 1, build_ok=0, verdict="no_build", generator_session="g1")
    store.add_harness_round("compress2", 2, build_ok=1, verdict="accept", binary="fuzz",
                            gate={"passed": True}, review={"verdict": "accept"})
    rounds = store.harness_rounds("compress2")
    assert [r["round"] for r in rounds] == [1, 2]
    assert json.loads(rounds[1]["gate"])["passed"] is True
    store.set_harness("compress2", "accepted", binary="fuzz", builds={"address": "/o/a"}, rounds=2)
    h = store.harnesses()[0]
    assert h["status"] == "accepted" and h["builds"] == {"address": "/o/a"}
