# SPDX-License-Identifier: Apache-2.0
"""The Lead board: append-only persistence, the six-state machine, dedup by
(function, crash class), and submit-backed crash recording from any stage."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent.lead import (  # noqa: E402
    FAILED, GENERATING_POV, PENDING_POV, PENDING_VERIFY, POV_GENERATED, REJECTED,
    Lead, LeadBoard, crash_class,
)


def test_crash_class_longest_match():
    assert crash_class("a heap-buffer-overflow in foo") == "heap-buffer-overflow"
    assert crash_class("some overflow") == "overflow"
    assert crash_class("logic error, no memory issue") == ""


def test_create_and_reload(tmp_path):
    p = tmp_path / ".fb" / "leads.jsonl"
    b = LeadBoard(p)
    lead = b.create(function="foo", description="heap-buffer-overflow via memcpy",
                    origin="discovery/llm", harness="h.cc")
    assert lead.id == "L01" and lead.status == PENDING_VERIFY
    # a fresh board reads the same state back from disk
    b2 = LeadBoard(p)
    assert b2.get("L01").function == "foo"
    assert b2._seq == 1                      # id sequence recovered


def test_dedup_merges_same_function_and_class(tmp_path):
    b = LeadBoard(tmp_path / "leads.jsonl")
    a = b.create(function="foo", description="heap-buffer-overflow", origin="discovery/llm")
    c = b.create(function="foo", description="another heap-buffer-overflow read", origin="discovery/worklist")
    assert a.id == c.id                       # merged, not a new lead
    assert "discovery/worklist" in c.merged_from
    assert len(b.all()) == 1
    # a different crash class on the same function is a distinct lead
    d = b.create(function="foo", description="use-after-free", origin="discovery/llm")
    assert d.id != a.id and len(b.all()) == 2


def test_update_respects_allowed_fields(tmp_path):
    b = LeadBoard(tmp_path / "leads.jsonl")
    lead = b.create(function="foo", description="overflow")
    from fbagent.lead import _VERIFY_FIELDS
    b.update(lead.id, allowed=_VERIFY_FIELDS, score=0.8, evidence="reached foo",
             status="pov_generated")          # status not in _VERIFY_FIELDS -> ignored
    got = b.get(lead.id)
    assert got.score == 0.8 and got.evidence == "reached foo"
    assert got.status == PENDING_VERIFY       # unchanged: role agents can't move status


def test_status_machine_and_rev(tmp_path):
    b = LeadBoard(tmp_path / "leads.jsonl")
    lead = b.create(function="foo", description="overflow")
    r0 = lead.rev
    b.set_status(lead.id, PENDING_POV)
    b.set_status(lead.id, GENERATING_POV)
    assert b.get(lead.id).status == GENERATING_POV
    assert b.get(lead.id).rev > r0
    try:
        b.set_status(lead.id, "bogus")
        assert False, "should reject unknown status"
    except ValueError:
        pass


def test_record_crash_from_any_stage(tmp_path):
    b = LeadBoard(tmp_path / "leads.jsonl")
    lead = b.create(function="cupsUTF8ToCharset", description="heap-buffer-overflow")
    # verification, holding trace, carried the crash — submit backed it
    b.record_crash(lead.id, "heap-buffer-overflow:cupsUTF8ToCharset")
    got = b.get(lead.id)
    assert got.status == POV_GENERATED
    assert got.signature == "heap-buffer-overflow:cupsUTF8ToCharset"
    assert b.solved_signatures() == {"heap-buffer-overflow:cupsUTF8ToCharset"}


def test_by_status_query(tmp_path):
    b = LeadBoard(tmp_path / "leads.jsonl")
    a = b.create(function="a", description="overflow")
    c = b.create(function="b", description="use-after-free")
    b.set_status(a.id, REJECTED)
    assert [l.id for l in b.by_status(REJECTED)] == [a.id]
    assert [l.id for l in b.by_status(PENDING_VERIFY)] == [c.id]


def test_append_only_audit_trail(tmp_path):
    p = tmp_path / "leads.jsonl"
    b = LeadBoard(p)
    lead = b.create(function="foo", description="overflow")
    b.set_status(lead.id, PENDING_POV)
    b.update(lead.id, allowed=None, attempts=1)
    lines = [l for l in p.read_text().splitlines() if l.strip()]
    assert len(lines) == 3                    # create + set_status + update, nothing overwritten
