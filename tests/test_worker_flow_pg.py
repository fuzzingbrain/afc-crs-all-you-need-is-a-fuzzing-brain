# SPDX-License-Identifier: Apache-2.0
"""The worker's data path on a real PostgreSQL: scope -> VH tools -> claims ->
PoC attempts -> crash dedup -> the dispatcher's stopping rules.

No LLM, no docker: the duplicate check and the analyzer are stubbed.
Skipped when POSTGRES_URL does not answer.
"""

import os
import uuid
from types import SimpleNamespace
from urllib.parse import urlparse, urlunparse

import pytest
from sqlalchemy import create_engine, text

from fuzzingbrain.db import store as store_mod
from fuzzingbrain.db.pg import migrate

BASE_URL = os.environ.get(
    "POSTGRES_URL",
    "postgresql+psycopg://fuzzingbrain:fuzzingbrain@localhost:5432/fuzzingbrain",
)

ASAN = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020 at pc 0x1
READ of size 1 at 0x6020 thread T0
    #0 0x1 in png_read_row /src/libpng/pngread.c:100:5
    #1 0x2 in png_read_image /src/libpng/pngread.c:200:3
    #2 0x3 in LLVMFuzzerTestOneInput /src/fuzz.cc:10:1
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/libpng/pngread.c:100:5 in png_read_row
"""


@pytest.fixture(scope="module")
def pg_url():
    admin = create_engine(BASE_URL, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as c:
            c.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not reachable")
    name = f"fb_test_{uuid.uuid4().hex[:10]}"
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"'))
    url = urlunparse(urlparse(BASE_URL)._replace(path="/" + name))
    migrate(url)
    old = os.environ.get("POSTGRES_URL")
    try:
        yield url
    finally:
        store_mod.reset_store()
        if old is not None:
            os.environ["POSTGRES_URL"] = old
        with admin.connect() as c:
            c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture
def world(pg_url, monkeypatch):
    from fuzzingbrain.worker import scope as scope_mod

    store_mod.reset_store()
    st = store_mod.get_store(pg_url)
    rid = str(uuid.uuid4())
    st.create_run(rid, "libpng", "full", {"budget_limit": 1}, {}, "/tmp/fb-test")
    hid = st.add_harness(rid, "fuzz", "/src/fuzz.cc", {"address": "/out/fuzz"})
    wid = st.create_worker(rid, hid, "/tmp/fb-test/worker_workspace/fuzz")
    assert st.worker_started(wid)
    scope_mod.set_scope(
        scope_mod.WorkerScope(
            run_id=rid, worker_id=str(wid), harness_id=str(hid), harness="fuzz",
            sanitizers=["address"], binaries={"address": "/out/fuzz"},
        )
    )
    # No analyzer and no LLM in a unit test.
    from fuzzingbrain.tools import vulnerability_hypotheses as vht

    vht.set_vh_context()
    vht.set_vh_agent_id("")

    monkeypatch.setattr(vht, "_function_row", lambda name: {
        "file_path": "pngread.c", "start_line": 90,
        "content": "int f() {\n  x = row[i];\n}\n",
    })
    yield SimpleNamespace(store=st, run_id=rid, harness_id=str(hid), worker_id=str(wid))
    scope_mod.set_scope(None)


def _agent(st, w, agent_type, **kw):
    aid = str(uuid.uuid4())
    st.start_agent(aid, w.run_id, w.worker_id, agent_type, **kw)
    return aid


def test_vh_create_merge_claim_and_crash(world, monkeypatch):
    from fuzzingbrain.core import vh_dedup
    from fuzzingbrain.core.crashes import record_crash
    from fuzzingbrain.tools import vulnerability_hypotheses as vht

    st, w = world.store, world
    finder = _agent(st, w, "DeltaVHGenerator")
    vht.set_vh_context(agent_id=finder)

    r = vht.create_vulnerability_hypothesis_impl(
        "png_read_row", "row index unchecked", score=0.8, sink_code="x = row[i];"
    )
    assert r["success"] and r["created"], r
    vh = st.find_vh_by_prefix(w.worker_id, r["id"])
    assert vh.function_file == "pngread.c" and vh.sink_line == 91
    assert vh.status == "pending_verify" and str(vh.created_by_agent_id) == finder

    # A second hypothesis in the same function the dedup calls a duplicate.
    monkeypatch.setattr(vh_dedup, "check_vh_duplicate", lambda *a, **k: vh.id)
    r2 = vht.create_vulnerability_hypothesis_impl("png_read_row", "same bug", score=0.6, sink_code="x = row[i];")
    assert r2["merged"] and r2["id"] == r["id"]
    assert st.merge_count(worker_id=w.worker_id) == 1
    assert len(st.vhs(worker_id=w.worker_id)) == 1

    # verify: claim, verdict, pass
    claimed = st.claim_vh(w.worker_id, "pending_verify", "verifying")
    assert claimed is not None and str(claimed.id) == str(vh.id)
    assert st.claim_vh(w.worker_id, "pending_verify", "verifying") is None
    assert st.move_vh(vh.id, "verifying", "pending_poc", score=0.9)

    # poc: claim, an attempt that crashes, a second attempt with the same bug
    assert st.claim_vh(w.worker_id, "pending_poc", "generating_poc") is not None
    poc_agent = _agent(st, w, "POCAgent", vh_id=vh.id)
    first = st.add_poc_attempt(
        w.run_id, "vh_agent", w.harness_id, "address", b"AAAA", vh_id=vh.id,
        worker_id=w.worker_id, agent_id=poc_agent, attempt=1, variant=1,
        generator_code="def generate(v): return b'AAAA'",
    )
    c1 = record_crash(first, ASAN, "fuzz", b"AAAA")
    assert c1.is_new and c1.vuln_type == "heap-buffer-overflow"

    # The global fuzzer hits the same bug: an attempt of its own, no new crash.
    g = st.add_poc_attempt(w.run_id, "global_fuzzer", w.harness_id, "address", b"BBBB")
    c2 = record_crash(g, ASAN, "fuzz", b"BBBB")
    assert not c2.is_new and c2.crash_id == c1.crash_id
    assert st.crash_count(w.run_id) == 1

    # An output with no recognisable class or frame is its own bug.
    g2 = st.add_poc_attempt(w.run_id, "global_fuzzer", w.harness_id, "address", b"CCCC")
    c3 = record_crash(g2, "something odd", "fuzz", b"CCCC")
    assert c3.is_new and c3.signature.startswith("unsigned-")
    assert st.crash_count(w.run_id) == 2

    # The crash already moved its VH; the agent's own move at its end is a no-op.
    assert st.get_vh(vh.id).status == "poc_generated"
    assert not st.move_vh(vh.id, "generating_poc", "poc_generated")
    st.end_agent(poc_agent, "completed", end_reason="poc_target", iterations=3)
    st.end_agent(finder, "completed", end_reason="work_done", iterations=2)

    summary = st.run_summary(w.run_id)
    row = summary["workers"][0]
    assert row["vhs_found"] == 1 and row["vhs_merged"] == 1 and row["crashes"] == 2


def test_vh_tool_rejects_foreign_sanitizer_and_outside_worker(world):
    from fuzzingbrain.tools import vulnerability_hypotheses as vht
    from fuzzingbrain.worker import scope as scope_mod

    r = vht.create_vulnerability_hypothesis_impl("f", "d", sanitizer="memory", sink_code="x;")
    assert not r["success"] and "sanitizer" in r["error"]
    scope_mod.set_scope(None)
    r = vht.create_vulnerability_hypothesis_impl("f", "d")
    assert not r["success"] and "worker" in r["error"]


def _dispatcher(world, **cfg):
    from fuzzingbrain.core.dispatcher import WorkerDispatcher

    config = SimpleNamespace(
        ossfuzz_project_name=None, project_name="libpng", workspace="/tmp/fb-test",
        poc_count=cfg.get("poc_count", 1), budget_limit=cfg.get("budget_limit", 0.0),
        redis_url="redis://127.0.0.1:1/0", max_parallel_fuzzers=1,
        timeout_minutes=cfg.get("timeout_minutes", 1),
    )
    d = WorkerDispatcher(world.run_id, config, world.store, harnesses=[])
    stops = []
    d.stop_everything = lambda reason, deadline=None, status="completed": stops.append(reason) or True
    d.get_status = lambda: {"total": 1, "queued": 0, "running": 1, "completed": 0,
                            "cancelled": 0, "error": 0, "lost": 0}
    return d, stops


def test_dispatcher_stops_on_poc_target(world):
    st, w = world.store, world
    d, stops = _dispatcher(world, poc_count=1)
    g = st.add_poc_attempt(w.run_id, "global_fuzzer", w.harness_id, "address", b"Z")
    from fuzzingbrain.core.crashes import record_crash

    record_crash(g, ASAN, "fuzz", b"Z")
    out = d.wait_for_completion(timeout_minutes=1, poll_interval=1)
    assert out["status"] == "poc_target_reached" and out["poc_count"] == 1
    assert stops == ["poc_target"]


def test_dispatcher_stops_on_budget(world):
    d, stops = _dispatcher(world, poc_count=0, budget_limit=0.5)
    d.current_cost = lambda: 0.75
    out = d.wait_for_completion(timeout_minutes=1, poll_interval=1)
    assert out["status"] == "budget_exceeded" and stops == ["budget"]


def test_dispatcher_closes_open_workers_with_reason(world):
    from fuzzingbrain.core.dispatcher import WorkerDispatcher

    st, w = world.store, world
    a = _agent(st, w, "DeltaVHGenerator")
    config = SimpleNamespace(
        ossfuzz_project_name=None, project_name="libpng", workspace="/tmp/fb-test",
        poc_count=1, budget_limit=0.0, redis_url="redis://127.0.0.1:1/0",
        max_parallel_fuzzers=1, timeout_minutes=1,
    )
    d = WorkerDispatcher(w.run_id, config, st, harnesses=[])
    d._revoke_workers("timeout")
    wrow = st.get_worker(w.worker_id)
    assert wrow.status == "completed" and wrow.end_reason == "timeout"
    assert st.get_agent(a).status == "cancelled"


def test_parallel_finders_keep_their_logic_group_and_agent(world):
    """Concurrent finders of one worker run as asyncio tasks; each VH must
    carry the logic group and agent of the task that created it."""
    import asyncio

    from fuzzingbrain.tools import vulnerability_hypotheses as vht

    st, w = world.store, world
    planner = _agent(st, w, "LGPlanningAgent")
    lgs = [
        str(st.create_logic_group(w.run_id, w.worker_id, planner, f"lg{i}", "high", ["f"], ["g"]))
        for i in range(3)
    ]

    async def finder(i):
        aid = str(uuid.uuid4())
        st.start_agent(aid, w.run_id, w.worker_id, "FullVHGenerator",
                       lg_id=lgs[i], function=("pngread.c", f"fn{i}", 1))
        vht.set_vh_context(lg_id=lgs[i], agent_id=aid)
        await asyncio.sleep(0.01 * (3 - i))  # interleave
        r = vht.create_vulnerability_hypothesis_impl(f"fn{i}", f"bug {i}", score=0.7, sink_code="x = row[i];")
        return aid, r

    async def main():
        return await asyncio.gather(*(finder(i) for i in range(3)))

    for i, (aid, r) in enumerate(asyncio.run(main())):
        assert r.get("success"), r
        vh = st.find_vh_by_prefix(w.worker_id, r["id"])
        assert str(vh.lg_id) == lgs[i] and str(vh.created_by_agent_id) == aid


def test_agent_vh_needs_a_sink(world):
    from fuzzingbrain.tools import vulnerability_hypotheses as vht

    vht.set_vh_context(agent_id=_agent(world.store, world, "DeltaVHGenerator"))
    r = vht.create_vulnerability_hypothesis_impl("f", "d")
    assert not r["success"] and "sink_code" in r["error"]


def test_store_writes_land_in_events_jsonl(world, tmp_path):
    import json

    from fuzzingbrain.core import events
    from fuzzingbrain.core.crashes import record_crash

    st, w = world.store, world
    events.set_events_path(tmp_path / "events.jsonl")
    try:
        aid = _agent(st, w, "DeltaVHGenerator")
        vid = st.create_vh(w.run_id, w.worker_id, "pngread.c", "png_read_row", "d", 0.8,
                           agent_id=aid, sink_code="x = row[i];", sink_line=91)
        assert st.move_vh(vid, "pending_verify", "verifying")
        assert not st.move_vh(vid, "pending_verify", "verifying")  # no-op: no event
        g = st.add_poc_attempt(w.run_id, "global_fuzzer", w.harness_id, "address", b"Q")
        c = record_crash(g, ASAN, "fuzz", b"Q")
        st.end_agent(aid, "completed", end_reason="work_done", iterations=1)
    finally:
        events.set_events_path(None)
    recs = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    kinds = [r["event"] for r in recs]
    assert kinds == ["agent_started", "vh_created", "vh_moved", "crash", "agent_ended"], kinds
    assert recs[1]["vh_id"] == str(vid) and recs[1]["agent_id"] == aid
    assert recs[2]["to_status"] == "verifying"
    assert recs[3]["crash_id"] == str(c.crash_id) and recs[3]["new"] is True
    assert "sink_code" not in recs[1] and "sanitizer_output" not in recs[3]
