# SPDX-License-Identifier: Apache-2.0
"""
Adversarial tests for the introspector call-graph parser.

These tests are written to *break* the parser, not to mirror it: they probe
BFS-distance correctness on shapes that expose ordering/shortest-path mistakes,
and they pin down find_call_path, which previously spun forever on any path of
length >= 2 (the reconstruction loop overwrote the target's sentinel and cycled).

Every graph test carries a hard iteration/time budget so a regression to the
infinite-loop behaviour fails loudly instead of hanging the suite.
"""

import json
import threading

import pytest

from fuzzingbrain.analysis.introspector_parser import (
    CallGraph,
    FunctionInfo,
    parse_introspector_json,
    get_reachable_functions,
    get_functions_at_distance,
    find_call_path,
)


def _fn(name, **kw):
    return FunctionInfo(
        name=name,
        file_path=kw.get("file_path", f"{name}.c"),
        start_line=kw.get("start_line", 1),
        end_line=kw.get("end_line", 2),
    )


def _graph(edges, entry_points, distances=None):
    """Build a CallGraph; distances default to BFS-consistent values if omitted."""
    names = set(edges) | {c for cs in edges.values() for c in cs} | set(entry_points)
    if distances:
        names |= set(distances)
    functions = {n: _fn(n) for n in names}
    return CallGraph(
        edges={k: set(v) for k, v in edges.items()},
        functions=functions,
        entry_points=list(entry_points),
        distances=distances if distances is not None else {},
    )


def _run_with_timeout(fn, seconds=5.0):
    """Run fn() in a thread; fail (not hang) if it exceeds the budget."""
    box = {}

    def target():
        box["result"] = fn()

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        pytest.fail(f"call did not return within {seconds}s (likely infinite loop)")
    return box.get("result")


# --------------------------------------------------------------------------
# parse_introspector_json: distances come from BFS, not from input ordering
# --------------------------------------------------------------------------

def _write_introspector(tmp_path, funcs):
    p = tmp_path / "all-fuzz-introspector-functions.json"
    p.write_text(json.dumps(funcs))
    return p


def test_entry_point_needs_both_fuzzer_reach_and_zero_callers(tmp_path):
    """A function reached by fuzzers but *called* by others is NOT an entry.

    Entry = reached by a fuzzer AND 'Reached by functions' == 0. A parser that
    only checks the fuzzer flag would wrongly seed BFS from an interior node.
    """
    funcs = [
        {
            "Func name": "LLVMFuzzerTestOneInput",
            "Functions filename": "harness.c",
            "Reached by Fuzzers": ["fuzz"],
            "Reached by functions": 0,
            "callsites": {"parse": [1]},
        },
        {
            "Func name": "parse",
            "Functions filename": "parse.c",
            "Reached by Fuzzers": ["fuzz"],
            "Reached by functions": 1,  # has a caller -> not an entry
            "callsites": {},
        },
    ]
    cg = parse_introspector_json(_write_introspector(tmp_path, funcs))
    assert cg.entry_points == ["LLVMFuzzerTestOneInput"]
    assert cg.distances["LLVMFuzzerTestOneInput"] == 0
    assert cg.distances["parse"] == 1


def test_bfs_distance_is_shortest_not_first_seen(tmp_path):
    """Distance must be the *shortest* hop count.

    entry -> a -> b -> target, and entry -> target directly. The direct edge
    makes target distance 1; a DFS-ish or last-write-wins accumulation could
    report 3. BFS with 'first assignment wins' is the only correct answer.
    """
    funcs = [
        {"Func name": "entry", "Reached by Fuzzers": ["f"], "Reached by functions": 0,
         "callsites": {"a": [1], "target": [2]}},
        {"Func name": "a", "Reached by functions": 1, "callsites": {"b": [1]}},
        {"Func name": "b", "Reached by functions": 1, "callsites": {"target": [1]}},
        {"Func name": "target", "Reached by functions": 2, "callsites": {}},
    ]
    cg = parse_introspector_json(_write_introspector(tmp_path, funcs))
    assert cg.distances["target"] == 1  # not 3


def test_unreachable_function_absent_from_distances(tmp_path):
    """A function no entry can reach must not appear in distances at all."""
    funcs = [
        {"Func name": "entry", "Reached by Fuzzers": ["f"], "Reached by functions": 0,
         "callsites": {"reached": [1]}},
        {"Func name": "reached", "Reached by functions": 1, "callsites": {}},
        {"Func name": "island", "Reached by functions": 0, "callsites": {}},
    ]
    cg = parse_introspector_json(_write_introspector(tmp_path, funcs))
    assert "island" not in cg.distances
    # ...but it is still a known function (just unreachable, distance stays -1)
    assert "island" in cg.functions
    assert cg.functions["island"].distance_from_entry == -1


def test_self_recursive_function_does_not_hang(tmp_path):
    """A function that calls itself must not cause the BFS to loop forever."""
    funcs = [
        {"Func name": "entry", "Reached by Fuzzers": ["f"], "Reached by functions": 0,
         "callsites": {"rec": [1]}},
        {"Func name": "rec", "Reached by functions": 1, "callsites": {"rec": [2]}},
    ]
    cg = _run_with_timeout(
        lambda: parse_introspector_json(_write_introspector(tmp_path, funcs))
    )
    assert cg.distances["rec"] == 1


# --------------------------------------------------------------------------
# get_reachable_functions / get_functions_at_distance
# --------------------------------------------------------------------------

def test_max_distance_filter_is_inclusive():
    """max_distance=1 must keep distance-1 functions and drop distance-2."""
    cg = _graph(
        edges={"e": {"a"}, "a": {"b"}},
        entry_points=["e"],
        distances={"e": 0, "a": 1, "b": 2},
    )
    names = {f.name for f in get_reachable_functions(cg, max_distance=1)}
    assert names == {"e", "a"}


def test_reachable_functions_sorted_by_distance():
    cg = _graph(
        edges={},
        entry_points=["e"],
        distances={"e": 0, "far": 5, "near": 1},
    )
    # populate distance_from_entry so the sort key is meaningful
    for n, d in cg.distances.items():
        cg.functions[n].distance_from_entry = d
    order = [f.name for f in get_reachable_functions(cg)]
    assert order == ["e", "near", "far"]


def test_functions_at_distance_exact_match_only():
    cg = _graph(
        edges={},
        entry_points=["e"],
        distances={"e": 0, "a": 1, "b": 1, "c": 2},
    )
    got = {f.name for f in get_functions_at_distance(cg, 1)}
    assert got == {"a", "b"}


# --------------------------------------------------------------------------
# find_call_path: regression for the infinite-loop reconstruction bug
# --------------------------------------------------------------------------

def test_find_call_path_two_hop_terminates_and_is_ordered():
    """entry -> target. Must return [entry, target], not hang."""
    cg = _graph(edges={"entry": {"target"}}, entry_points=["entry"],
                distances={"entry": 0, "target": 1})
    path = _run_with_timeout(lambda: find_call_path(cg, "target"))
    assert path == ["entry", "target"]


def test_find_call_path_multi_hop_terminates_and_is_ordered():
    """entry -> a -> b -> target must reconstruct in forward order."""
    cg = _graph(
        edges={"entry": {"a"}, "a": {"b"}, "b": {"target"}},
        entry_points=["entry"],
        distances={"entry": 0, "a": 1, "b": 2, "target": 3},
    )
    path = _run_with_timeout(lambda: find_call_path(cg, "target"))
    assert path == ["entry", "a", "b", "target"]


def test_find_call_path_target_is_entry_returns_singleton():
    cg = _graph(edges={"entry": {"x"}}, entry_points=["entry"],
                distances={"entry": 0, "x": 1})
    path = _run_with_timeout(lambda: find_call_path(cg, "entry"))
    assert path == ["entry"]


def test_find_call_path_picks_a_valid_edge_chain_with_a_diamond():
    """Diamond: entry -> {a, b} -> target. Whatever path is returned must be a
    real chain of edges from entry to target (no fabricated hops)."""
    cg = _graph(
        edges={"entry": {"a", "b"}, "a": {"target"}, "b": {"target"}},
        entry_points=["entry"],
        distances={"entry": 0, "a": 1, "b": 1, "target": 2},
    )
    path = _run_with_timeout(lambda: find_call_path(cg, "target"))
    assert path[0] == "entry" and path[-1] == "target"
    # verify every consecutive pair is a real caller->callee edge
    for caller, callee in zip(path, path[1:]):
        assert callee in cg.edges.get(caller, set()), f"{caller}->{callee} not an edge"


def test_find_call_path_unreachable_target_returns_none():
    """Target exists but no entry reaches it -> None, and must not hang."""
    cg = _graph(
        edges={"entry": {"a"}, "island": {"target"}},
        entry_points=["entry"],
        distances={"entry": 0, "a": 1},
    )
    # 'target' is only reachable via 'island', which no entry reaches
    result = _run_with_timeout(lambda: find_call_path(cg, "target"))
    assert result is None


def test_find_call_path_missing_target_returns_none():
    cg = _graph(edges={"entry": {"a"}}, entry_points=["entry"],
                distances={"entry": 0, "a": 1})
    assert find_call_path(cg, "does_not_exist_anywhere") is None


def test_find_call_path_cycle_on_the_way_does_not_hang():
    """A cycle among interior nodes (a<->b) must not trap the backward BFS."""
    cg = _graph(
        edges={"entry": {"a"}, "a": {"b"}, "b": {"a", "target"}},
        entry_points=["entry"],
        distances={"entry": 0, "a": 1, "b": 2, "target": 3},
    )
    path = _run_with_timeout(lambda: find_call_path(cg, "target"))
    assert path is not None and path[0] == "entry" and path[-1] == "target"
