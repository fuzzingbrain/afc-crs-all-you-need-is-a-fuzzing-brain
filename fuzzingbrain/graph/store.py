# SPDX-License-Identifier: Apache-2.0
"""Read an index file: point lookups from SQLite, traversals on an in-memory CSR.

Point lookups (a function's row, its source) go to SQLite. Everything that walks
the graph -- callers, callees, reachability, distances, paths -- runs on two
CSR arrays loaded once, so nothing walks the graph one query per hop.

A harness is a set of marks on the shared graph. Asked about a harness, a
query only sees edges whose two ends are in that harness's graph (or are
externals no harness's graph holds): a caller the harness never reaches is not
a caller for it.
"""

import re
import sqlite3
import threading
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

import numpy as np
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import dijkstra

from .schema import FORMAT_VERSION, file_sha256

ENTRY = "LLVMFuzzerTestOneInput"
_BATCH = 100_000
_ROW_COLUMNS = (
    "id, name, file_path, start_line, end_line, content, cyclomatic_complexity,"
    " language, symbol, external"
)


class GraphError(RuntimeError):
    """The index file cannot be used as asked."""


def _row(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "name": r["name"],
        "file_path": r["file_path"],
        "start_line": r["start_line"],
        "end_line": r["end_line"],
        "content": r["content"],
        "cyclomatic_complexity": r["cyclomatic_complexity"],
        "language": r["language"],
        "symbol": r["symbol"],
        "external": bool(r["external"]),
    }


class CallGraph:
    """One index file, opened read-only."""

    def __init__(self, path, expect_sha256: Optional[str] = None):
        self.path = Path(path)
        if not self.path.is_file():
            raise GraphError(f"no index file at {self.path}")
        if expect_sha256 and file_sha256(self.path) != expect_sha256:
            raise GraphError(f"{self.path} changed since it was registered")
        self._local = threading.local()
        db = self._db()
        self.meta = dict(db.execute("SELECT key, value FROM meta"))
        if self.meta.get("format_version") != FORMAT_VERSION:
            raise GraphError(
                f"{self.path}: format {self.meta.get('format_version')!r}, "
                f"this code reads {FORMAT_VERSION!r}"
            )
        self._load(db)
        self._sub: Dict[Optional[int], tuple] = {}
        self._sub_lock = threading.Lock()

    # ------------------------------------------------------------ loading

    def _db(self) -> sqlite3.Connection:
        db = getattr(self._local, "db", None)
        if db is None:
            db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=False)
            db.row_factory = sqlite3.Row
            self._local.db = db
        return db

    def _load(self, db: sqlite3.Connection) -> None:
        n = db.execute("SELECT COALESCE(MAX(id), 0) FROM functions").fetchone()[0]
        self.n = n + 1  # ids start at 1; slot 0 stays unused
        self.names: List[Optional[str]] = [None] * self.n
        self.defined = np.zeros(self.n, dtype=bool)
        self.by_name: Dict[str, List[int]] = defaultdict(list)
        cur = db.execute("SELECT id, name, external FROM functions ORDER BY id")
        while rows := cur.fetchmany(_BATCH):
            for fid, name, external in rows:
                self.names[fid] = name
                self.by_name[name].append(fid)
                if not external:
                    self.defined[fid] = True

        n_edges = db.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        src = np.empty(n_edges, dtype=np.int32)
        dst = np.empty(n_edges, dtype=np.int32)
        ind = np.empty(n_edges, dtype=np.int8)
        cur = db.execute("SELECT src, dst, indirect FROM edges")
        i = 0
        while rows := cur.fetchmany(_BATCH):
            a = np.asarray(rows, dtype=np.int32)
            k = len(a)
            src[i : i + k], dst[i : i + k], ind[i : i + k] = a[:, 0], a[:, 1], a[:, 2]
            i += k
        self.n_edges = n_edges
        self.n_indirect = int(ind.sum()) if n_edges else 0
        # Stored value: 1 = direct, 2 = indirect (0 would vanish from a sparse matrix).
        self.fwd = csr_matrix((ind + 1, (src, dst)), shape=(self.n, self.n))
        self.rev = self.fwd.T.tocsr()

        self.harnesses: Dict[str, int] = {}
        self.entry: Dict[str, Optional[int]] = {}
        # member: in the harness's graph; depth: calls from its entry, -1 unknown.
        self.member: Dict[str, np.ndarray] = {}
        self.depth: Dict[str, np.ndarray] = {}
        self.reached_via: Dict[str, Dict[int, str]] = {}
        for hid, name, entry in db.execute("SELECT id, name, entry_function_id FROM harnesses"):
            self.harnesses[name] = hid
            self.entry[name] = entry
            self.depth[name] = np.full(self.n, -1, dtype=np.int32)
            self.member[name] = np.zeros(self.n, dtype=bool)
            self.reached_via[name] = {}
        by_id = {hid: name for name, hid in self.harnesses.items()}
        cur = db.execute("SELECT harness_id, function_id, depth, reached_via FROM reach")
        while rows := cur.fetchmany(_BATCH):
            for hid, fid, d, via in rows:
                name = by_id[hid]
                self.member[name][fid] = True
                if d is not None:
                    self.depth[name][fid] = d
                if via:
                    self.reached_via[name][fid] = via

    # ------------------------------------------------------------- basics

    @property
    def has_edges(self) -> bool:
        return self.n_edges > 0

    def harness_names(self) -> List[str]:
        return sorted(self.harnesses)

    def stats(self) -> dict:
        return {
            "functions": int(self.defined.sum()),
            "edges": self.n_edges,
            "indirect_edges": self.n_indirect,
            "harnesses": {
                h: {"reachable": int(self.member[h].sum()), "max_depth": max(int(d.max()), 0)}
                for h, d in self.depth.items()
            },
        }

    def _check_harness(self, harness: Optional[str]) -> None:
        if harness is not None and harness not in self.harnesses:
            raise GraphError(
                f"the graph has no harness {harness!r} (it has {self.harness_names()})"
            )

    def _reached(self, harness: Optional[str]) -> np.ndarray:
        """Boolean mask of functions the harness reaches (any harness if None)."""
        if harness is not None:
            return self.member[harness]
        mask = np.zeros(self.n, dtype=bool)
        for m in self.member.values():
            mask |= m
        return mask

    def ids(self, name: str, harness: Optional[str] = None) -> List[int]:
        """Ids named `name`; with a harness, the ones it reaches if any does."""
        ids = self.by_name.get(name, [])
        if harness is not None and len(ids) > 1:
            m = self.member[harness]
            reached = [i for i in ids if m[i]]
            if reached:
                return reached
        return list(ids)

    # ------------------------------------------------------- point lookups

    def rows(self, ids: Sequence[int]) -> List[dict]:
        if not ids:
            return []
        out = []
        db = self._db()
        ids = list(ids)
        for k in range(0, len(ids), 900):
            chunk = ids[k : k + 900]
            q = f"SELECT {_ROW_COLUMNS} FROM functions WHERE id IN ({','.join('?' * len(chunk))})"
            out.extend(_row(r) for r in db.execute(q, chunk))
        order = {fid: i for i, fid in enumerate(ids)}
        out.sort(key=lambda r: order[r["id"]])
        return out

    def function(self, name: str, harness: Optional[str] = None) -> Optional[dict]:
        """The definition of `name`: defined beats external; the last one wins a tie."""
        ids = self.ids(name, harness)
        if not ids:
            return None
        ids.sort(key=lambda i: (bool(self.defined[i]), i))
        row = self.rows([ids[-1]])[0]
        row["reached_by_fuzzers"] = [h for h, m in self.member.items() if m[row["id"]]]
        return row

    def functions_in_file(self, file_path: str) -> List[dict]:
        """Defined functions whose file has the same last component."""
        base = Path(file_path.replace("\\", "/")).name
        if not base:
            return []
        db = self._db()
        q = (
            f"SELECT {_ROW_COLUMNS} FROM functions WHERE external = 0 AND"
            " (file_path = ? OR file_path LIKE ? ESCAPE '\\') ORDER BY id"
        )
        like = "%/" + base.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        return [_row(r) for r in db.execute(q, (base, like))]

    def search(self, pattern: str, limit: int = 50) -> List[dict]:
        """Defined functions whose name matches `pattern` (regex, any case)."""
        rx = re.compile(pattern, re.IGNORECASE)
        hits = []
        for fid in range(1, self.n):
            name = self.names[fid]
            if name is not None and self.defined[fid] and rx.search(name):
                hits.append(fid)
                if len(hits) >= limit:
                    break
        return self.rows(hits)

    def all_functions(self, harness: Optional[str] = None) -> List[dict]:
        """Every defined function (reached by `harness`, if given), without source."""
        mask = self.defined & (self._reached(harness) if harness else True)
        ids = np.nonzero(mask)[0].tolist()
        db = self._db()
        out = []
        q = "SELECT id, name, file_path, start_line, end_line FROM functions WHERE id = ?"
        for fid in ids:
            r = db.execute(q, (fid,)).fetchone()
            out.append(dict(r))
        return out

    # ------------------------------------------------------------ the graph

    def _graph(self, harness: Optional[str], direct_only: bool = False):
        """(forward, reverse) CSR restricted to `harness`'s graph."""
        key = (harness, direct_only)
        got = self._sub.get(key)
        if got is not None:
            return got
        with self._sub_lock:
            got = self._sub.get(key)
            if got is not None:
                return got
            g = self.fwd
            if harness is not None:
                # The harness's graph, plus what no harness's graph holds
                # (externals such as libc): callees() lists those too.
                keep = (self._reached(harness) | ~self._reached(None)).astype(np.int8)
                g = csr_matrix(g.multiply(keep[:, None]).multiply(keep[None, :]))
            if direct_only:
                g = csr_matrix(g.multiply(g == 1))
            g.eliminate_zeros()
            got = (g, g.T.tocsr())
            self._sub[key] = got
            return got

    def _neighbours(self, m: csr_matrix, ids: Iterable[int]) -> List[int]:
        seen = set()
        out = []
        for i in ids:
            for j in m.indices[m.indptr[i] : m.indptr[i + 1]]:
                j = int(j)
                if j not in seen:
                    seen.add(j)
                    out.append(j)
        return out

    def callers(self, name: str, harness: Optional[str] = None) -> List[str]:
        self._check_harness(harness)
        _, rev = self._graph(harness)
        return self._unique_names(self._neighbours(rev, self.ids(name, harness)))

    def callees(self, name: str, harness: Optional[str] = None) -> List[str]:
        """What `name` calls. A callee nothing reaches (libc, a hook) is kept."""
        self._check_harness(harness)
        ids = self.ids(name, harness)
        out = self._neighbours(self.fwd, ids)
        if harness is not None:
            here = self.member[harness]
            anywhere = self._reached(None)
            out = [j for j in out if here[j] or not anywhere[j]]
        return self._unique_names(out)

    def _unique_names(self, ids: Iterable[int]) -> List[str]:
        seen = set()
        out = []
        for i in ids:
            n = self.names[i]
            if n not in seen:
                seen.add(n)
                out.append(n)
        return out

    def reachability(self, harness: str, name: str) -> Optional[dict]:
        """{depth, reached_via} for the closest function called `name`, or None.

        depth is None for a function in the harness's graph without a known depth.
        """
        self._check_harness(harness)
        m, d = self.member[harness], self.depth[harness]
        best = None
        for fid in self.by_name.get(name, []):
            if not m[fid]:
                continue
            if best is None or (d[fid] >= 0 and (d[best] < 0 or d[fid] < d[best])):
                best = fid
        if best is None:
            return None
        return {
            "depth": int(d[best]) if d[best] >= 0 else None,
            "reached_via": self.reached_via[harness].get(best),
        }

    def reachable_names(self, harness: Optional[str] = None) -> List[str]:
        if harness is not None:
            self._check_harness(harness)
        ids = np.nonzero(self._reached(harness))[0]
        return self._unique_names(int(i) for i in ids)

    def unreached_names(self, harness: Optional[str] = None) -> List[str]:
        reached = set(self.reachable_names(harness))
        ids = np.nonzero(self.defined)[0]
        return [n for n in self._unique_names(int(i) for i in ids) if n not in reached]

    def entry_names(self, harness: Optional[str] = None) -> List[str]:
        hs = [harness] if harness is not None else self.harness_names()
        out = []
        for h in hs:
            self._check_harness(h)
            e = self.entry[h]
            if e is not None and self.names[e] not in out:
                out.append(self.names[e])
        return out

    def distances(
        self,
        seeds: Iterable[str],
        harness: Optional[str] = None,
        direct_only: bool = False,
    ) -> Dict[str, int]:
        """{name: fewest calls from any seed} over everything the seeds reach."""
        self._check_harness(harness)
        fwd, _ = self._graph(harness, direct_only)
        src = sorted({i for s in seeds for i in self.ids(s, harness)})
        if not src:
            return {}
        dist = dijkstra(fwd, unweighted=True, indices=src, min_only=True)
        out: Dict[str, int] = {}
        for fid in np.nonzero(np.isfinite(dist))[0]:
            name = self.names[int(fid)]
            d = int(dist[fid])
            if name not in out or d < out[name]:
                out[name] = d
        return out

    def all_paths(
        self,
        start: str,
        target: str,
        max_depth: int = 10,
        max_paths: int = 100,
        harness: Optional[str] = None,
    ) -> dict:
        """Call chains start -> ... -> target with at most `max_depth` functions.

        A start of LLVMFuzzerTestOneInput, or one the graph does not have, means
        the harness entries. Branches that cannot reach the target within the
        remaining depth are cut before they are walked.
        """
        self._check_harness(harness)
        fwd, rev = self._graph(harness)
        targets = set(self.ids(target, harness))
        if start == ENTRY or not self.ids(start, harness):
            starts = [i for h in ([harness] if harness else self.harness_names())
                      if (i := self.entry.get(h)) is not None]
        else:
            starts = self.ids(start, harness)
        result = {"paths": [], "truncated": False}
        if not targets or not starts:
            return result
        # Calls still needed from each function to reach the target.
        to_target = dijkstra(rev, unweighted=True, indices=sorted(targets), min_only=True)
        paths: List[List[str]] = []

        def walk(cur: int, path: List[int], on_path: set) -> None:
            if len(paths) >= max_paths:
                result["truncated"] = True
                return
            if cur in targets:
                paths.append([self.names[i] for i in path])
                return
            on_path.add(cur)
            for nxt in fwd.indices[fwd.indptr[cur] : fwd.indptr[cur + 1]]:
                nxt = int(nxt)
                if nxt in on_path:
                    continue
                if len(path) + 1 + to_target[nxt] > max_depth:
                    continue
                path.append(nxt)
                walk(nxt, path, on_path)
                path.pop()
                if len(paths) >= max_paths:
                    result["truncated"] = True
                    break
            on_path.discard(cur)

        for s in starts:
            if len(paths) >= max_paths:
                result["truncated"] = True
                break
            if 1 + to_target[s] <= max_depth:
                walk(s, [s], set())
        result["paths"] = paths
        return result
