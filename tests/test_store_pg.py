# SPDX-License-Identifier: Apache-2.0
"""The PostgreSQL store against a real server: a throwaway database per module.

Skipped when POSTGRES_URL does not answer.
"""

import os
import uuid
from urllib.parse import urlparse, urlunparse

import pytest
from sqlalchemy import create_engine, text

from fuzzingbrain.db.pg import migrate
from fuzzingbrain.db.store import NUL_MARK, Store, message_sha256

BASE_URL = os.environ.get(
    "POSTGRES_URL",
    "postgresql+psycopg://fuzzingbrain:fuzzingbrain@localhost:5432/fuzzingbrain",
)


def _with_db(url: str, name: str) -> str:
    p = urlparse(url)
    return urlunparse(p._replace(path="/" + name))


@pytest.fixture(scope="module")
def store():
    admin = create_engine(BASE_URL, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as c:
            c.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not reachable")
    name = f"fb_test_{uuid.uuid4().hex[:10]}"
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"'))
    url = _with_db(BASE_URL, name)
    try:
        migrate(url)
        st = Store(url)
        yield st
        st.close()
    finally:
        with admin.connect() as c:
            c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture
def run(store):
    rid = str(uuid.uuid4())
    store.create_run(rid, "proj", "full", {"budget": 1}, {"budget": "file"}, "/tmp/x")
    hid = store.add_harness(rid, "fuzz", "fuzz.c", {"address": "/b/fuzz"})
    wid = store.create_worker(rid, hid, "/tmp/x/worker_workspace/fuzz")
    return rid, hid, wid


def test_run_lifecycle(store, run):
    rid, hid, wid = run
    assert store.get_run(rid).status == "preparing"
    store.run_dispatched(rid)
    assert store.get_run(rid).status == "running"
    assert store.worker_started(wid)
    assert store.end_worker(wid, "completed", "work_done")
    assert not store.end_worker(wid, "error", error="late")  # already ended
    assert store.end_run(rid, "completed", "timeout")
    r = store.get_run(rid)
    assert (r.status, r.end_reason) == ("completed", "timeout")


def test_vh_claims_are_conditional(store, run):
    rid, hid, wid = run
    aid = uuid.uuid4()
    lg = None
    store.start_agent(aid, rid, wid, "DeltaVHGenerator")
    low = store.create_vh(rid, wid, "a.c", "f", "d1", 0.3, agent_id=aid, sink_code="x;")
    high = store.create_vh(rid, wid, "a.c", "g", "d2", 0.9, agent_id=aid, sink_code="y;")
    got = store.claim_vh(wid, "pending_verify", "verifying")
    assert got.id == high  # best score first
    assert store.claim_vh(wid, "pending_verify", "verifying").id == low
    assert store.claim_vh(wid, "pending_verify", "verifying") is None
    assert store.move_vh(high, "verifying", "pending_poc", verifier_reproduced=False)
    assert not store.move_vh(high, "verifying", "rejected")  # no longer verifying
    assert store.update_vh(high, score=2.0, evidence="e")
    assert store.get_vh(high).score == 1.0
    assert store.get_vh(high).finder_score == pytest.approx(0.9)
    assert store.find_vh_by_prefix(wid, str(high)[:8]).id == high
    store.merge_vh(high, aid, "same", 0.5)
    assert store.merge_count(worker_id=wid) == 1
    assert store.return_stuck_vhs(wid) == 1  # `low` was still verifying
    assert lg is None


def test_crashes_dedup_by_signature(store, run):
    rid, hid, wid = run
    a1 = store.add_poc_attempt(rid, "global_fuzzer", hid, "address", b"AAAA")
    a2 = store.add_poc_attempt(rid, "global_fuzzer", hid, "address", b"BBBB")
    c1, new1 = store.attempt_crashed(a1, "sig", "heap-buffer-overflow", "out\x00put")
    c2, new2 = store.attempt_crashed(a2, "sig", "heap-buffer-overflow", "out")
    assert (new1, new2) == (True, False) and c1 == c2
    assert store.crash_count(rid) == 1
    assert NUL_MARK in store.get_poc_attempt(a1).sanitizer_output
    a3 = store.add_poc_attempt(rid, "global_fuzzer", hid, "address", b"C")
    store.attempt_ran(a3, "no_crash")
    assert store.get_poc_attempt(a3).status == "no_crash"


def test_messages_are_stored_once(store, run):
    rid, hid, wid = run
    m = {"role": "system", "content": "harness\x00source"}
    sha = message_sha256(m)
    ids1 = store.message_ids(rid, [(sha, "system", m)])
    ids2 = store.message_ids(rid, [(sha, "system", m)])
    assert ids1 == ids2
    reply = {"role": "assistant", "content": "ok"}
    rsha = message_sha256(reply)
    rid_map = store.message_ids(rid, [(rsha, "assistant", reply)])
    [cid] = store.insert_llm_calls([{
        "run_id": uuid.UUID(rid), "worker_id": wid, "role": "finder",
        "model": "m", "params": {}, "provider": "p", "input_tokens": 1,
        "output_tokens": 1, "cost": 0.5, "latency_ms": 3, "success": True,
        "input_message_ids": [ids1[sha]], "output_message_id": rid_map[rsha],
    }])
    assert store.conversation(cid) == [m, reply]
    assert store.run_cost(rid) == pytest.approx(0.5)
