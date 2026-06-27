# SPDX-License-Identifier: Apache-2.0
"""Pure-logic tests for the bench sweep orchestrator (no V2 / Docker / bench)."""

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "run_bench", Path(__file__).resolve().parent.parent / "scripts" / "run_bench.py"
)
run_bench = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(run_bench)


def test_scan_markers_detects_build_and_dispatch():
    log = (
        "Parallel build completed in 96.7s. 2/2 succeeded, 1 fuzzers available.\n"
        "Dispatched worker: vacm_fuzzer_address\n"
    )
    m = run_bench._scan_markers(log)
    assert m["built"] and m["dispatched"]
    assert not m["build_failed"] and not m["no_workers"]


def test_scan_markers_detects_failures():
    m = run_bench._scan_markers("Code Analyzer failed: Build failed")
    assert m["build_failed"] and not m["built"]
    m2 = run_bench._scan_markers("No workers were dispatched")
    assert m2["no_workers"]


def test_scan_markers_strips_ansi():
    m = run_bench._scan_markers("\x1b[32m1 fuzzers available\x1b[0m")
    assert m["built"]


def test_cap_rank_orders_by_fired_flags():
    assert run_bench._cap_rank({}) == 0
    assert run_bench._cap_rank({"reach": "fired"}) == 1
    full = {f: "fired" for f in ("reach", "crash", "crash2", "class", "site")}
    assert run_bench._cap_rank(full) == 5
    assert run_bench._cap_rank({"reach": "fired", "crash": "n/a"}) == 1


def test_locate_blobs_finds_attempt_blobs(tmp_path):
    d = tmp_path / "povs" / "task1" / "worker1" / "attempt_001"
    d.mkdir(parents=True)
    (d / "v1.bin").write_bytes(b"crash")
    (d / "v2.bin").write_bytes(b"")  # empty -> skipped
    blobs = run_bench.locate_blobs(tmp_path)
    names = [b.name for b in blobs]
    assert "v1.bin" in names
    assert "v2.bin" not in names  # zero-byte filtered


def test_locate_blobs_caps_count(tmp_path):
    d = tmp_path / "povs" / "t" / "w" / "attempt_001"
    d.mkdir(parents=True)
    for i in range(20):
        (d / f"v{i}.bin").write_bytes(b"x")
    assert len(run_bench.locate_blobs(tmp_path, cap=5)) == 5


def test_scorecard_counts_solved():
    recs = [
        {"bug_id": "a", "solved": True, "built": True, "dispatched": True},
        {"bug_id": "b", "solved": False, "built": True, "dispatched": True, "n_blobs": 0},
        {"bug_id": "c", "solved": False, "build_failed": True},
    ]
    card = run_bench.scorecard(recs)
    assert "1/3 SOLVED" in card
    assert "build-fail" in card and "no-pov" in card
