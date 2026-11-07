# SPDX-License-Identifier: Apache-2.0
"""Build an index file from the per-harness JSON graphs the artifact ships.

The artifact keeps one graph per harness (graph/<harness>/mongodb/
{functions,callgraph}.json). Each is the whole software's functions plus that
harness's reachability, so N harnesses repeat the same functions N times. This
merges them into one file:

- functions are deduplicated by (file_path, name, start_line);
- edges are the union over the harnesses (indirect-call inference can differ
  between them); an edge is indirect only if no harness saw it as direct;
- each harness keeps the depths its own file recorded; nothing is recomputed.

Names in a callgraph file are resolved against the functions of the same file
first: every harness defines its own LLVMFuzzerTestOneInput, and a name lookup
across files would wire one harness's entry to another's callees.

    python -m fuzzingbrain.graph.convert OUT.sqlite --harness NAME=DIR ... \
        [--repo URL] [--commit SHA] [--producer TEXT]
    python -m fuzzingbrain.graph.convert OUT.sqlite --artifact CHALLENGE_DIR
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .schema import create

Key = Tuple[str, str, Optional[int]]


class _Builder:
    def __init__(self):
        self.rows: List[dict] = []  # index = id - 1
        self.by_key: Dict[Key, int] = {}
        self.by_name: Dict[str, List[int]] = defaultdict(list)  # defined only
        self.stubs: Dict[str, int] = {}
        self.edges: Dict[Tuple[int, int], int] = {}  # (src, dst) -> indirect
        self.reach: Dict[Tuple[int, int], Tuple[int, Optional[str]]] = {}
        self.harnesses: List[Tuple[str, Optional[int]]] = []
        self.stats = defaultdict(int)

    def _add(self, row: dict) -> int:
        self.rows.append(row)
        return len(self.rows)

    def add_function(self, doc: dict) -> int:
        line = doc.get("start_line")
        if not isinstance(line, int) or line <= 0:
            line = None
        if line is None:
            self.stats["functions_without_line"] += 1
        key = (doc.get("file_path") or "", doc["name"], line)
        fid = self.by_key.get(key)
        if fid is None:
            fid = self._add(
                {
                    "name": doc["name"],
                    "file_path": key[0],
                    "start_line": line,
                    "end_line": doc["end_line"] if line and (doc.get("end_line") or 0) >= line else None,
                    "content": doc.get("content") or "",
                    "cyclomatic_complexity": doc.get("cyclomatic_complexity"),
                    "language": doc.get("language"),
                    "symbol": doc.get("symbol"),
                    "external": 1 if doc.get("external") else 0,
                }
            )
            self.by_key[key] = fid
            self.by_name[doc["name"]].append(fid)
        return fid

    def resolve(self, name: str, local: Dict[str, List[int]]) -> List[int]:
        if name in local:
            return local[name]
        defined = self.by_name.get(name, [])
        if len(defined) == 1:
            self.stats["names_resolved_from_other_harness"] += 1
            return defined
        if name not in self.stubs:
            self.stubs[name] = self._add(
                {
                    "name": name,
                    "file_path": "",
                    "start_line": None,
                    "end_line": None,
                    "content": "",
                    "cyclomatic_complexity": None,
                    "language": None,
                    "symbol": None,
                    "external": 1,
                }
            )
            self.stats["stub_functions"] += 1
        return [self.stubs[name]]

    def add_harness(self, name: str, graph_dir: Path) -> None:
        hid = len(self.harnesses) + 1
        with open(graph_dir / "functions.json") as f:
            functions = json.load(f)
        local: Dict[str, List[int]] = defaultdict(list)
        for doc in functions:
            fid = self.add_function(doc)
            if fid not in local[doc["name"]]:
                local[doc["name"]].append(fid)
        del functions
        self.stats["duplicate_names"] += sum(1 for v in local.values() if len(v) > 1)

        with open(graph_dir / "callgraph.json") as f:
            nodes = json.load(f)
        fuzzers = {n.get("fuzzer_name") for n in nodes}
        if len(fuzzers) > 1:
            raise ValueError(f"{graph_dir}: callgraph.json mixes fuzzers {sorted(fuzzers)}")
        entry: Optional[int] = None
        for node in nodes:
            srcs = self.resolve(node["function_name"], local)
            direct = set(node.get("callees_direct", [])) | set(node.get("callees_observed", []))
            indirect = set(node.get("callees_indirect", []))
            for callee in node.get("callees", []):
                flag = 1 if (callee in indirect and callee not in direct) else 0
                for dst in self.resolve(callee, local):
                    for src in srcs:
                        old = self.edges.get((src, dst))
                        self.edges[(src, dst)] = flag if old is None else min(old, flag)
            depth = node.get("call_depth", -1)
            if depth is None or depth < 0:
                # In this harness's graph, depth unknown.
                self.stats["nodes_without_depth"] += 1
                depth = None
            for fid in srcs:
                cur = self.reach.get((hid, fid))
                if cur is None or (depth is not None and (cur[0] is None or depth < cur[0])):
                    self.reach[(hid, fid)] = (depth, node.get("reached_via"))
            if depth == 0 and (entry is None or node["function_name"] == "LLVMFuzzerTestOneInput"):
                entry = srcs[0]
        self.harnesses.append((name, entry))


def convert(
    out: Path,
    harness_dirs: Dict[str, Path],
    repo: Optional[str] = None,
    commit: Optional[str] = None,
    producer: Optional[str] = None,
) -> dict:
    """Write `out` from {harness: dir holding functions.json, callgraph.json}."""
    b = _Builder()
    for name in sorted(harness_dirs):
        b.add_harness(name, Path(harness_dirs[name]))

    db = create(Path(out))
    try:
        db.executemany(
            "INSERT INTO functions (id, name, file_path, start_line, end_line, content,"
            " cyclomatic_complexity, language, symbol, external)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                (
                    i + 1, r["name"], r["file_path"], r["start_line"], r["end_line"],
                    r["content"], r["cyclomatic_complexity"], r["language"],
                    r["symbol"], r["external"],
                )
                for i, r in enumerate(b.rows)
            ),
        )
        db.executemany(
            "INSERT INTO edges (src, dst, indirect) VALUES (?,?,?)",
            ((s, d, f) for (s, d), f in sorted(b.edges.items())),
        )
        db.executemany(
            "INSERT INTO harnesses (id, name, entry_function_id) VALUES (?,?,?)",
            ((i + 1, n, e) for i, (n, e) in enumerate(b.harnesses)),
        )
        db.executemany(
            "INSERT INTO reach (harness_id, function_id, depth, reached_via) VALUES (?,?,?,?)",
            ((h, f, d, v) for (h, f), (d, v) in sorted(b.reach.items())),
        )
        n_indirect = sum(1 for f in b.edges.values() if f)
        meta = {
            "repo": repo or "",
            "commit": commit or "",
            "producer": producer or "",
            "converted_from": "artifact per-harness JSON",
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "n_functions": str(len(b.rows)),
            "n_edges": str(len(b.edges)),
            "n_indirect_edges": str(n_indirect),
        }
        db.executemany("INSERT INTO meta VALUES (?, ?)", meta.items())
        db.commit()
        db.execute("VACUUM")
    finally:
        db.close()
    return {
        "functions": len(b.rows),
        "edges": len(b.edges),
        "indirect_edges": sum(1 for f in b.edges.values() if f),
        "harnesses": [n for n, _ in b.harnesses],
        "harnesses_without_entry": [n for n, e in b.harnesses if e is None],
        **b.stats,
    }


def artifact_harness_dirs(challenge_dir: Path) -> Dict[str, Path]:
    """{harness: graph dir} for an artifact challenge directory."""
    root = Path(challenge_dir) / "graph"
    found = {}
    for d in sorted(p for p in root.iterdir() if p.is_dir()) if root.is_dir() else []:
        if (d / "mongodb" / "callgraph.json").is_file():
            found[d.name] = d / "mongodb"
    return found


def artifact_meta(challenge_dir: Path) -> Dict[str, Optional[str]]:
    """repo / commit / producer from the challenge's challenge.json or task.json."""
    challenge_dir = Path(challenge_dir)
    for name in ("challenge.json", "task.json"):
        p = challenge_dir / name
        if p.is_file():
            data = json.loads(p.read_text())
            src = data.get("source") or {}
            return {
                "repo": src.get("repo") or data.get("repo_url"),
                "commit": data.get("graph_resolved_commit") or data.get("target_commit"),
                "producer": data.get("graph_producer"),
            }
    return {"repo": None, "commit": None, "producer": None}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m fuzzingbrain.graph.convert", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("out", type=Path)
    p.add_argument("--harness", action="append", default=[], metavar="NAME=DIR")
    p.add_argument("--artifact", type=Path, help="artifact challenge directory")
    p.add_argument("--repo")
    p.add_argument("--commit")
    p.add_argument("--producer")
    a = p.parse_args(argv)

    dirs: Dict[str, Path] = {}
    meta = {"repo": a.repo, "commit": a.commit, "producer": a.producer}
    if a.artifact:
        dirs.update(artifact_harness_dirs(a.artifact))
        found = artifact_meta(a.artifact)
        meta = {k: meta[k] or found[k] for k in meta}
    for spec in a.harness:
        name, _, d = spec.partition("=")
        if not d:
            p.error(f"--harness wants NAME=DIR, got {spec!r}")
        d = Path(d)
        dirs[name] = d / "mongodb" if (d / "mongodb").is_dir() else d
    if not dirs:
        p.error("no harness graphs given")
    stats = convert(a.out, dirs, **meta)
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
