# SPDX-License-Identifier: Apache-2.0
"""Diversity frontier: two deterministic mechanisms that steer the agent toward
*different* faults, computed from the call graph rather than judged by the model.

  - `recursive_targets` turns the graph's call cycles into stack-overflow sinks
    (unbounded recursion is a graph property the pattern pre-screen cannot see);
  - `furthest_first` ranks the remaining reachable sinks by how *far* they are,
    in the call structure, from the faults already found — the Fuzzer-Taming
    Furthest-Point-First ordering, on the real graph, so "go somewhere different"
    is a measured distance and not a model's guess.

Both are pure functions over an `analysis.Context`. This module is deliberately
standalone (imported by nothing on the run's hot path yet) so it can grow while a
bench sweep is in flight; it is wired into the worklist and a `diversify` tool in
a single integration step afterward.
"""
from __future__ import annotations

from collections import deque

from .analysis import Context, Sink


def recursive_targets(ctx: Context, max_n: int = 12) -> list[Sink]:
    """Recursion / call-cycle sinks the harness can reach, nearest first.

    Each cycle in the reachable subgraph is a candidate unbounded-recursion /
    deep-recursion stack overflow. The representative function of the cycle is
    reported with its distance from the entry and the cycle that formed it, so
    the agent can attack a fault class the token pre-screen misses entirely."""
    reachable = set(ctx.dist)
    out: list[Sink] = []
    seen: set[str] = set()
    for cycle in ctx.cg.cycles(reachable):
        rep = cycle[0]
        if rep in seen:
            continue
        seen.add(rep)
        file_rel, line = ctx.cg.where.get(rep, ("?", 0))
        kind = "self-recursion" if len(cycle) == 1 else f"recursion cycle of {len(cycle)}"
        ring = " -> ".join(cycle + [cycle[0]]) if len(cycle) > 1 else f"{rep} -> {rep}"
        s = Sink(func=rep, file=file_rel, line=line, klass="stack-overflow",
                 why=f"{kind}: {ring[:80]}", distance=ctx.dist.get(rep, -1))
        s.path = ctx.cg.path_to(ctx.entry, rep, ctx.dist) if ctx.entry else []
        out.append(s)
    out.sort(key=lambda s: (s.distance if s.distance >= 0 else 1 << 30, s.file, s.func))
    return out[:max_n]


def _undirected_adj(ctx: Context) -> dict[str, set[str]]:
    """The call graph as an undirected graph -- two sites are 'different' if far
    apart in the call structure, regardless of who calls whom."""
    adj: dict[str, set[str]] = {}
    for a, bs in ctx.cg.edges.items():
        for b in bs:
            adj.setdefault(a, set()).add(b)
            adj.setdefault(b, set()).add(a)
    return adj


def _multi_source_dist(adj: dict[str, set[str]], sources: list[str]) -> dict[str, int]:
    """BFS distance from the nearest of several sources to every node at once."""
    dist: dict[str, int] = {}
    q: deque[str] = deque()
    for s in sources:
        if s in adj and s not in dist:
            dist[s] = 0
            q.append(s)
    while q:
        u = q.popleft()
        for v in adj.get(u, ()):  # noqa: SIM118
            if v not in dist:
                dist[v] = dist[u] + 1
                q.append(v)
    return dist


def furthest_first(ctx: Context, cracked: list[str], max_n: int = 10) -> list[Sink]:
    """Reachable sinks ranked by call-structure distance from the faults already
    found -- furthest first. Given the functions where distinct crashes were
    already recorded, the next target should be maximally *different*; this
    computes that distance on the real graph (Furthest-Point-First) instead of
    letting the model guess what 'somewhere else' means. With no cracked sites
    yet, falls back to the entry-distance ordering the worklist already uses."""
    cand = ctx.reach
    if not cracked:
        return sorted(cand, key=lambda s: (s.distance, s.file, s.line))[:max_n]
    adj = _undirected_adj(ctx)
    far = _multi_source_dist(adj, [c.split("::")[-1] for c in cracked])
    INF = 1 << 30
    ranked = sorted(
        cand,
        key=lambda s: (-(far.get(s.func, INF) if far.get(s.func, INF) != INF else -1),
                       s.distance, s.file, s.line),
    )
    return ranked[:max_n]
