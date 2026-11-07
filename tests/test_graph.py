# SPDX-License-Identifier: Apache-2.0
"""The index file: conversion from per-harness JSON, and every reader query."""

import json

import pytest

from fuzzingbrain.graph import CallGraph, GraphError, SourceFunctions
from fuzzingbrain.graph.convert import convert


def _fn(name, file, line, body="{\n}"):
    return {"name": name, "file_path": file, "start_line": line, "end_line": line + 2,
            "content": f"void {name}() {body}", "language": "c", "external": False}


def _node(fuzzer, name, depth, callees=(), callers=(), indirect=()):
    return {"fuzzer_name": fuzzer, "function_name": name, "call_depth": depth,
            "callees": list(callees) + list(indirect), "callees_direct": list(callees),
            "callees_indirect": list(indirect), "callers": list(callers),
            "reached_via": "direct"}


def _write(d, functions, nodes):
    d.mkdir(parents=True)
    (d / "functions.json").write_text(json.dumps(functions))
    (d / "callgraph.json").write_text(json.dumps(nodes))
    return d


@pytest.fixture
def graph(tmp_path):
    # Two harnesses over one library; each has its own entry in its own file.
    lib = [_fn("parse", "lib.c", 10), _fn("read_hdr", "lib.c", 20),
           _fn("decode", "lib.c", 30), _fn("unused", "lib.c", 40)]
    a = _write(tmp_path / "a", lib + [_fn("LLVMFuzzerTestOneInput", "fuzz_a.c", 1)], [
        _node("a", "LLVMFuzzerTestOneInput", 0, ["parse"]),
        _node("a", "parse", 1, ["read_hdr"], indirect=["decode"]),
        _node("a", "read_hdr", 2),
        _node("a", "decode", 2),
    ])
    b = _write(tmp_path / "b", lib + [_fn("LLVMFuzzerTestOneInput", "fuzz_b.c", 1)], [
        _node("b", "LLVMFuzzerTestOneInput", 0, ["decode"]),
        _node("b", "decode", 1),
    ])
    out = tmp_path / "g.sqlite"
    stats = convert(out, {"a": a, "b": b}, repo="r", commit="c1")
    return CallGraph(out), stats


def test_functions_are_stored_once_and_entries_kept_apart(graph):
    g, stats = graph
    assert stats["functions"] == 6  # 4 library + one entry per harness
    assert g.meta["commit"] == "c1"
    assert g.function("LLVMFuzzerTestOneInput", "a")["file_path"] == "fuzz_a.c"
    assert g.function("LLVMFuzzerTestOneInput", "b")["file_path"] == "fuzz_b.c"


def test_queries_answer_for_the_harness(graph):
    g, _ = graph
    assert g.callees("LLVMFuzzerTestOneInput", "a") == ["parse"]
    assert g.callees("LLVMFuzzerTestOneInput", "b") == ["decode"]
    # b's entry calls decode too, but b's entry is not a caller for harness a.
    assert set(g.callers("decode", "a")) == {"parse"}
    assert g.callers("decode", "b") == ["LLVMFuzzerTestOneInput"]
    assert g.reachability("a", "read_hdr")["depth"] == 2
    assert g.reachability("b", "read_hdr") is None
    assert sorted(g.unreached_names("b")) == ["parse", "read_hdr", "unused"]
    with pytest.raises(GraphError):
        g.callers("decode", "no_such_harness")


def test_distances_and_direct_only(graph):
    g, _ = graph
    assert g.distances(["LLVMFuzzerTestOneInput"], "a") == {
        "LLVMFuzzerTestOneInput": 0, "parse": 1, "read_hdr": 2, "decode": 2}
    direct = g.distances(["parse"], "a", direct_only=True)
    assert "decode" not in direct and direct["read_hdr"] == 1


def test_all_paths_respects_depth(graph):
    g, _ = graph
    r = g.all_paths("LLVMFuzzerTestOneInput", "read_hdr", max_depth=3, harness="a")
    assert r["paths"] == [["LLVMFuzzerTestOneInput", "parse", "read_hdr"]]
    assert g.all_paths("LLVMFuzzerTestOneInput", "read_hdr", max_depth=2, harness="a")["paths"] == []


def test_lookup_by_file_and_pattern(graph):
    g, _ = graph
    assert {f["name"] for f in g.functions_in_file("src/lib.c")} == {
        "parse", "read_hdr", "decode", "unused"}
    assert [f["name"] for f in g.search("^read")] == ["read_hdr"]


def test_source_index_has_functions_and_no_edges(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "x.c").write_text("int add(int a, int b)\n{\n  return a + b;\n}\n")
    (repo / ".git").mkdir()
    (repo / ".git" / "y.c").write_text("int hidden(void)\n{\n  return 0;\n}\n")
    g = CallGraph(SourceFunctions(repo, tmp_path / "idx.sqlite").provide())
    f = g.function("add")
    assert f["file_path"] == "src/x.c" and f["start_line"] == 1
    assert g.function("hidden") is None
    assert not g.has_edges and g.harness_names() == []
