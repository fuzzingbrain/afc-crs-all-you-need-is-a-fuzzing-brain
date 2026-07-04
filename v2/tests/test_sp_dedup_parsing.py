# SPDX-License-Identifier: Apache-2.0
"""
Adversarial tests for SP dedup response parsing.

_parse_sp_dedup_response turns a chat model's free-form reply into "which
existing SP is this a duplicate of, if any". The failure modes it must survive:
markdown-fenced JSON, plain-number references, out-of-range indices, ObjectId
values, and NON-JSON prose (the text fallback). The prose fallback previously
raised UnboundLocalError because its id-resolver helper was defined only after
the json.loads that had already thrown — so any malformed-but-affirmative reply
crashed instead of resolving the duplicate. These tests pin all of that down.
"""

from fuzzingbrain.core.sp_dedup import _parse_sp_dedup_response


def _sps():
    return [
        {"suspicious_point_id": "id-one", "description": "heap overflow in a"},
        {"suspicious_point_id": "id-two", "description": "uaf in b"},
        {"suspicious_point_id": "id-three", "description": "int overflow in c"},
    ]


# --------------------------------------------------------------------------
# Clean JSON paths
# --------------------------------------------------------------------------

def test_not_duplicate_returns_none():
    out = _parse_sp_dedup_response('{"duplicate": false, "duplicate_of": null}', _sps())
    assert out is None


def test_duplicate_sp_n_resolves_to_id():
    out = _parse_sp_dedup_response('{"duplicate": true, "duplicate_of": "SP-2"}', _sps())
    assert out == "id-two"


def test_duplicate_first_and_last_index():
    assert _parse_sp_dedup_response(
        '{"duplicate": true, "duplicate_of": "SP-1"}', _sps()) == "id-one"
    assert _parse_sp_dedup_response(
        '{"duplicate": true, "duplicate_of": "SP-3"}', _sps()) == "id-three"


def test_plain_number_reference_is_accepted():
    """Model sometimes answers "2" instead of "SP-2"."""
    out = _parse_sp_dedup_response('{"duplicate": true, "duplicate_of": "2"}', _sps())
    assert out == "id-two"


def test_markdown_fenced_json_is_unwrapped():
    resp = '```json\n{"duplicate": true, "duplicate_of": "SP-1"}\n```'
    assert _parse_sp_dedup_response(resp, _sps()) == "id-one"


def test_direct_id_reference_matches():
    resp = '{"duplicate": true, "duplicate_of": "id-three"}'
    assert _parse_sp_dedup_response(resp, _sps()) == "id-three"


# --------------------------------------------------------------------------
# Out-of-range / malformed references must not resolve to a wrong SP
# --------------------------------------------------------------------------

def test_out_of_range_sp_index_returns_none():
    """SP-9 with only 3 SPs must be None, not an IndexError or a wraparound."""
    assert _parse_sp_dedup_response(
        '{"duplicate": true, "duplicate_of": "SP-9"}', _sps()) is None


def test_zero_index_returns_none():
    """SP-0 -> idx -1; must not resolve to the LAST element via negative index."""
    assert _parse_sp_dedup_response(
        '{"duplicate": true, "duplicate_of": "SP-0"}', _sps()) is None


def test_duplicate_true_but_ref_null_returns_none():
    assert _parse_sp_dedup_response(
        '{"duplicate": true, "duplicate_of": null}', _sps()) is None


def test_unknown_direct_id_returns_none():
    assert _parse_sp_dedup_response(
        '{"duplicate": true, "duplicate_of": "id-nonexistent"}', _sps()) is None


# --------------------------------------------------------------------------
# Non-JSON prose fallback (the UnboundLocalError regression)
# --------------------------------------------------------------------------

def test_prose_affirmative_with_sp_ref_resolves_without_crashing():
    """Regression: 'this is a duplicate of SP-1' is not JSON; the fallback must
    resolve it to id-one, not raise UnboundLocalError."""
    out = _parse_sp_dedup_response("Yes, this is a duplicate of SP-1.", _sps())
    assert out == "id-one"


def test_prose_negative_returns_none():
    assert _parse_sp_dedup_response("No duplicate here.", _sps()) is None
    assert _parse_sp_dedup_response("This is not a duplicate.", _sps()) is None


def test_prose_affirmative_out_of_range_ref_returns_none():
    out = _parse_sp_dedup_response("It's a duplicate of SP-42.", _sps())
    assert out is None


def test_prose_without_any_sp_ref_returns_none():
    """'duplicate' with no SP-N marker resolves to nothing rather than guessing."""
    out = _parse_sp_dedup_response("Looks like a duplicate to me.", _sps())
    assert out is None


def test_garbage_returns_none():
    for junk in ["", "   ", "42", "{not json", "```\n```"]:
        assert _parse_sp_dedup_response(junk, _sps()) is None


# --------------------------------------------------------------------------
# ObjectId / _id fallbacks
# --------------------------------------------------------------------------

def test_resolves_via_mongo_underscore_id_when_no_sp_id():
    sps = [{"_id": "mongo-oid", "description": "x"}]
    out = _parse_sp_dedup_response('{"duplicate": true, "duplicate_of": "SP-1"}', sps)
    assert out == "mongo-oid"


def test_missing_ids_yield_none_not_crash():
    sps = [{"description": "no id here"}]
    out = _parse_sp_dedup_response('{"duplicate": true, "duplicate_of": "SP-1"}', sps)
    assert out is None
