# SPDX-License-Identifier: Apache-2.0
"""Check converted index files answer like the MongoDB import did.

For every artifact challenge: convert its per-harness JSON graphs into
<challenge>/graph.sqlite (unless --no-convert), then, harness by harness,
replay what the old path stored -- one run imported one harness's
functions.json (keyed by name, last write wins) and callgraph.json (keyed by
fuzzer + name) -- and compare every query the analysis server and the full-scan
strategy make:

  function rows, callers, callees, reachability depth, reachable / unreached
  sets, entry points, and BFS distances from the entry.

Lists are compared as sets (the old order was the file's, the new one is by
id). Prints one line per harness and a total; exits 1 on any difference.

    python scripts/verify_graph_conversion.py /home/ze/fbv2/artifact [--only NAME ...]
"""

import argparse
import json
import sys
import time
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzzingbrain.graph import CallGraph  # noqa: E402
from fuzzingbrain.graph.convert import artifact_harness_dirs, artifact_meta, convert  # noqa: E402


def old_view(graph_dir: Path):
    functions = {}
    for doc in json.load(open(graph_dir / "functions.json")):
        functions[doc["name"]] = doc  # Mongo _id {run}_{name}: last write wins
    nodes = {}
    dup = set()
    for doc in json.load(open(graph_dir / "callgraph.json")):
        if doc["function_name"] in nodes:
            dup.add(doc["function_name"])
        nodes[doc["function_name"]] = doc  # _id {run}_{fuzzer}_{name}
    return functions, nodes, dup


def old_bfs(nodes, seeds):
    depth = {}
    q = deque()
    for s in seeds:
        if s not in depth:
            depth[s] = 0
            q.append(s)
    while q:
        f = q.popleft()
        for c in (nodes.get(f) or {}).get("callees", []):
            if c not in depth:
                depth[c] = depth[f] + 1
                q.append(c)
    return depth


def compare(g: CallGraph, harness: str, graph_dir: Path) -> dict:
    functions, nodes, dup = old_view(graph_dir)
    diff = {}
    # Two definitions sharing a name (static functions in different files):
    # MongoDB kept whichever node came last, the index keeps both. Reported,
    # not counted as a difference.
    known = sorted(dup)

    def bump(k, example):
        e = diff.setdefault(k, [0, example])
        e[0] += 1

    for name, doc in functions.items():
        new = g.function(name, harness)
        if new is None:
            bump("function_missing", name)
            continue
        old_line = doc.get("start_line") if (doc.get("start_line") or 0) > 0 else None
        if (new["file_path"], new["start_line"], new["content"]) != (
            doc.get("file_path") or "", old_line, doc.get("content") or ""
        ):
            bump("function_row", name)

    for name, node in nodes.items():
        if name in dup:
            continue
        if set(g.callers(name, harness)) != set(node.get("callers", [])):
            bump("callers", name)
        if set(g.callees(name, harness)) != set(node.get("callees", [])):
            bump("callees", name)
        r = g.reachability(harness, name)
        old_d = node.get("call_depth", -1)
        new_d = None if r is None else (-1 if r["depth"] is None else r["depth"])
        if new_d != (old_d if old_d >= 0 else -1):
            bump("depth", name)

    # The old server answered "reachable" for every node of the harness's file.
    old_reached = set(nodes)
    if set(g.reachable_names(harness)) != old_reached:
        bump("reachable_set", sorted(set(g.reachable_names(harness)) ^ old_reached)[:3])
    # Unreached = defined functions not in the harness's graph. The merged file
    # holds every harness's functions and the index does not list externals
    # (libc, sanitizer hooks) as unreached code, so compare within this file's
    # defined functions.
    defined_here = {n for n, d in functions.items() if not d.get("external")}
    old_unreached = defined_here - set(nodes)
    new_unreached = set(g.unreached_names(harness)) & defined_here
    if new_unreached != old_unreached:
        bump("unreached_set", sorted(new_unreached ^ old_unreached)[:3])
    old_entries = sorted({n for n, d in nodes.items() if d.get("call_depth") == 0})
    if g.entry_names(harness) != old_entries[:1] and set(g.entry_names(harness)) != set(old_entries):
        bump("entries", (g.entry_names(harness), old_entries))
    if old_entries:
        if g.distances(old_entries, harness) != old_bfs(nodes, old_entries):
            a, b = g.distances(old_entries, harness), old_bfs(nodes, old_entries)
            bad = [k for k in set(a) | set(b) if a.get(k) != b.get(k)]
            bump("bfs_distances", (len(bad), bad[:3]))
    return {"functions": len(functions), "nodes": len(nodes), "diff": diff, "known": known}


def challenges(root: Path):
    for suite in ("aixcc", "cybergym-e2e"):
        for d in sorted((root / suite).iterdir()):
            if d.is_dir() and artifact_harness_dirs(d):
                yield d


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("artifact", type=Path)
    p.add_argument("--only", nargs="*")
    p.add_argument("--no-convert", action="store_true")
    a = p.parse_args()
    failed = 0
    total = 0
    for d in challenges(a.artifact):
        if a.only and d.name not in a.only:
            continue
        out = d / "graph.sqlite"
        dirs = artifact_harness_dirs(d)
        if not a.no_convert or not out.exists():
            if out.exists():
                out.unlink()
            t = time.time()
            stats = convert(out, dirs, **artifact_meta(d))
            print(f"{d.name}: converted in {time.time() - t:.1f}s "
                  f"({stats['functions']} functions, {stats['edges']} edges, "
                  f"{out.stat().st_size / 1e6:.1f} MB)", flush=True)
        t = time.time()
        g = CallGraph(out)
        load = time.time() - t
        for h, gd in dirs.items():
            total += 1
            r = compare(g, h, gd)
            status = "OK" if not r["diff"] else "DIFF " + json.dumps(r["diff"])
            if r["known"]:
                status += f" (same-name nodes kept apart: {r['known']})"
            if r["diff"]:
                failed += 1
            print(f"  {d.name}/{h}: load {load:.2f}s, {r['functions']} fn, "
                  f"{r['nodes']} nodes: {status}", flush=True)
        del g
    print(f"{total - failed}/{total} harness graphs identical")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
