# SPDX-License-Identifier: Apache-2.0
"""Tests for the diversity frontier (fbagent/frontier.py): recursion-cycle sinks
and Furthest-Point-First target selection, both pure graph computations."""
from __future__ import annotations

from pathlib import Path

from fbagent import analysis, frontier


def _ctx():
    cg = analysis.CallGraph()
    edges = [("LLVMFuzzerTestOneInput", "parse"), ("parse", "recurse"),
             ("recurse", "recurse"), ("parse", "a"), ("a", "b"),
             ("parse", "c"), ("c", "d"), ("d", "c")]
    for a, b in edges:
        cg.add_def(a, "f.c", 1); cg.add_def(b, "f.c", 2); cg.add_edge(a, b)
    entry = "LLVMFuzzerTestOneInput"
    dist = cg.distances(entry)
    sinks = [analysis.Sink("b", "f.c", 10, "oob", "x", distance=dist["b"]),
             analysis.Sink("d", "f.c", 20, "oob", "y", distance=dist["d"])]
    return analysis.Context(root=Path("."), lang="c", entry=entry, files=1,
                            cg=cg, dist=dist, reach=sinks, span={})


def test_recursive_targets_finds_self_and_mutual():
    rt = frontier.recursive_targets(_ctx())
    funcs = {s.func for s in rt}
    assert "recurse" in funcs                       # self-recursion
    assert funcs & {"c", "d"}                        # mutual recursion cycle
    assert all(s.klass == "stack-overflow" for s in rt)


def test_furthest_first_picks_the_far_site():
    ctx = _ctx()
    ff = frontier.furthest_first(ctx, cracked=["b"])
    assert ff[0].func == "d"                          # d is on the far branch from b


def test_furthest_first_empty_falls_back_to_entry_distance():
    ctx = _ctx()
    ff = frontier.furthest_first(ctx, cracked=[])
    assert [s.func for s in ff] == ["b", "d"]         # nearest-first by entry distance
