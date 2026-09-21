# SPDX-License-Identifier: Apache-2.0
"""
LocalAnalysisBackend — a standalone stand-in for the FuzzingBrain Analysis Server.

The agent tools (get_function_source, get_callers, check_reachability, ...) all go
through `fuzzingbrain.tools.analyzer._get_client()`, which returns an
``AnalysisClient`` bound to a running Analysis Server over a unix socket. That
server needs the introspector build + MongoDB function index — i.e. a whole
pipeline run.

For component-level experiments we do not want the pipeline. This class implements
the same method surface the tools call, served from a plain source tree on disk:

  * function bodies via a brace-matching C/C++ extractor,
  * a shallow call graph built by scanning each body for calls to known functions,
  * reachability by BFS from the fuzzer over that call graph.

It is deliberately approximate (a real introspector resolves function pointers,
macros, and cross-TU edges we cannot). Every approximation is marked; the point is
to let an agent *read the real vulnerable code* and reason, not to reproduce the
Analysis Server's precision. Reachability answers are best-effort and biased toward
"reachable" so the agent is never wrongly told a real path does not exist.

Nothing here imports or mutates production wiring. The probe injects an instance
into the tools' client cache; see probe.py.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

# Trees larger than this many source files are indexed lazily (per-function, via
# ripgrep) instead of scanned whole up front — wireshark's ~3.7k files take
# minutes to scan fully, which is impractical per probe run.
_LAZY_FILE_THRESHOLD = 1500


# Files we index. C/C++ only for now (the first challenges are C); the extractor
# is language-specific and the probe skips a challenge whose language it can't index.
_SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

# Candidate opener: an identifier immediately followed by '('. We then paren-match
# the argument list and check that a '{' follows (modulo whitespace, comments, and
# a few trailing qualifiers) — that distinguishes a definition from a call. This
# tolerates real-world C style the naive "type name(args) {" regex misses:
# comments inside the return type, the name on its own line, attributes, etc.
_NAME_PAREN = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

# Language keywords that look like a function opener but are control flow.
_NOT_FUNCTIONS = {
    "if", "for", "while", "switch", "return", "sizeof", "do", "else",
    "case", "defined", "static_assert", "assert", "typedef",
}

# Between the arg list's ')' and the body '{' a definition may carry comments and
# a short run of qualifier/attribute tokens (const, PNG_RESTRICT, __attribute__…).
_GAP_TOKEN = re.compile(r"[A-Za-z_]\w*|__attribute__\s*\(|\(|\)|\s+")


def _strip_comments(text: str) -> str:
    """Replace /* */ and // comments with spaces, preserving newlines and offsets.

    Keeping length/newlines identical means line numbers computed on the stripped
    text still match the original file.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        two = text[i : i + 2]
        if two == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
        elif two == "//":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif c in ('"', "'"):  # skip string/char literals so braces inside don't count
            q = c
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == q:
                    j += 1
                    break
                j += 1
            out.append(text[i:j])
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


class LocalAnalysisBackend:
    """Serves the AnalysisClient surface from a source tree on disk."""

    def __init__(self, source_root: str, fuzzers: Optional[List[str]] = None):
        self.source_root = Path(source_root)
        self._fuzzers = fuzzers or []
        # name -> {file, start_line, end_line, source}
        self._funcs: Dict[str, Dict[str, Any]] = {}
        # name -> set(callee names) ; built lazily after indexing
        self._callees: Dict[str, set] = {}
        self._callers: Dict[str, set] = {}
        self._indexed = False
        self._lazy = False
        self._indexed_files: set = set()
        # SP store (populated by create/update_suspicious_point).
        self.suspicious_points: List[Dict[str, Any]] = []

    # ---- indexing --------------------------------------------------------

    def index(self) -> "LocalAnalysisBackend":
        """Index the tree. Small trees are scanned whole (full call graph); large
        trees switch to lazy per-function lookup so a run doesn't stall on a huge
        codebase like wireshark."""
        sources = list(self._iter_sources())
        if len(sources) > _LAZY_FILE_THRESHOLD:
            self._lazy = True
            self._indexed = True
            return self  # nothing scanned up front; _ensure_function pulls on demand
        for path in sources:
            self._index_one(path)
        self._build_call_graph()
        self._indexed = True
        return self

    # -- lazy path (large trees) ------------------------------------------

    def _index_one(self, path: Path) -> None:
        if str(path) in self._indexed_files:
            return
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return
        self._index_file(path, text)
        self._indexed_files.add(str(path))

    def _ensure_function(self, name: str) -> None:
        """In lazy mode, locate a function's definition with ripgrep and index just
        the file(s) that contain it, incrementally growing the table + call graph."""
        if not self._lazy or name in self._funcs or not name.isidentifier():
            return
        rg = shutil.which("rg")
        pat = rf"\b{re.escape(name)}\s*\("
        files: List[str] = []
        try:
            if rg:
                r = subprocess.run(
                    [rg, "-l", "--type", "c", "--type", "cpp", "-e", pat, str(self.source_root)],
                    capture_output=True, text=True, timeout=30,
                )
                files = [f for f in r.stdout.splitlines() if f]
            else:
                r = subprocess.run(
                    ["grep", "-rIlE", "--include=*.c", "--include=*.h",
                     "--include=*.cc", "--include=*.cpp", pat, str(self.source_root)],
                    capture_output=True, text=True, timeout=60,
                )
                files = [f for f in r.stdout.splitlines() if f]
        except Exception:
            files = []
        for f in files[:8]:  # cap: enough to catch the def + a couple of callers
            p = Path(f)
            if p.suffix in _SOURCE_SUFFIXES:
                self._index_one(p)
        # Refresh call-graph edges for the newly indexed functions.
        self._build_call_graph()

    def _iter_sources(self):
        for p in self.source_root.rglob("*"):
            if p.is_file() and p.suffix in _SOURCE_SUFFIXES:
                # Skip vendored/test trees — checked on the path RELATIVE to the
                # source root, so a source_root that itself sits under a dir named
                # "build" (e.g. fb-graphs/build/<ch>/repo) is not wholly excluded.
                rel_parts = {x.lower() for x in p.relative_to(self.source_root).parts}
                if rel_parts & {".git", "third_party", "googletest"}:
                    continue
                yield p

    def _index_file(self, path: Path, text: str) -> None:
        rel = str(path.relative_to(self.source_root))
        stripped = _strip_comments(text)
        for m in _NAME_PAREN.finditer(stripped):
            name = m.group(1)
            if name in _NOT_FUNCTIONS or name in self._funcs:
                continue
            paren_close = self._paren_match(stripped, m.end() - 1)
            if paren_close is None:
                continue
            brace_open = self._body_brace_after(stripped, paren_close + 1)
            if brace_open is None:
                continue
            body = self._brace_match(stripped, brace_open)
            if body is None:
                continue
            start_line = stripped.count("\n", 0, m.start()) + 1
            end_line = stripped.count("\n", 0, brace_open) + body.count("\n") + 1
            sig_start = stripped.rfind("\n", 0, m.start()) + 1
            self._funcs[name] = {
                "name": name,
                "file": rel,
                "start_line": start_line,
                "end_line": end_line,
                # Source is taken from the comment-stripped text so bodies are clean
                # for call-graph scanning; good enough for the agent to read.
                "source": stripped[sig_start:brace_open] + body,
            }

    @staticmethod
    def _paren_match(text: str, open_idx: int) -> Optional[int]:
        """Index of the ')' matching the '(' at open_idx, or None."""
        depth = 0
        for i in range(open_idx, len(text)):
            c = text[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return i
            elif c in ";{}":
                return None  # a statement boundary — not an arg list
        return None

    @staticmethod
    def _body_brace_after(text: str, pos: int) -> Optional[int]:
        """After the arg list, the next '{' is the body iff only qualifier tokens
        separate them. A ';' first means it was a prototype/declaration."""
        i = pos
        n = len(text)
        while i < n:
            c = text[i]
            if c.isspace():
                i += 1
                continue
            if c == "{":
                return i
            if c in ";)=,":
                return None  # prototype, call, initializer — not a definition
            tok = _GAP_TOKEN.match(text, i)
            if not tok or tok.end() == i:
                return None
            i = tok.end()
        return None

    @staticmethod
    def _brace_match(text: str, open_idx: int) -> Optional[str]:
        """Return the substring from the opening brace to its match, inclusive."""
        depth = 0
        i = open_idx
        n = len(text)
        while i < n:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[open_idx : i + 1]
            i += 1
        return None  # unbalanced — reject this opener

    def _build_call_graph(self) -> None:
        names = set(self._funcs)
        call_ref = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
        for name, info in self._funcs.items():
            callees = set()
            for m in call_ref.finditer(info["source"]):
                callee = m.group(1)
                if callee != name and callee in names:
                    callees.add(callee)
            self._callees[name] = callees
            for callee in callees:
                self._callers.setdefault(callee, set()).add(name)

    # ---- AnalysisClient surface -----------------------------------------
    # Method names + return shapes mirror what fuzzingbrain/tools/*.py expect.

    def ping(self) -> bool:
        return True

    def get_status(self) -> Dict[str, Any]:
        return {
            "backend": "LocalAnalysisBackend",
            "functions_indexed": len(self._funcs),
            "source_root": str(self.source_root),
        }

    def get_function_source(self, function_name: str) -> Optional[str]:
        self._ensure_function(function_name)
        info = self._funcs.get(function_name)
        return info["source"] if info else None

    def get_function(self, function_name: str) -> Optional[Dict[str, Any]]:
        self._ensure_function(function_name)
        info = self._funcs.get(function_name)
        if not info:
            return None
        return {k: info[k] for k in ("name", "file", "start_line", "end_line")}

    def get_functions_by_file(self, file_path: str) -> List[Dict[str, Any]]:
        tail = file_path.split("/")[-1]
        out = []
        for info in self._funcs.values():
            if info["file"].endswith(tail):
                out.append(
                    {
                        "name": info["name"],
                        "file_path": info["file"],
                        "start_line": info["start_line"],
                        "end_line": info["end_line"],
                    }
                )
        return out

    def get_callers(self, function_name: str) -> Dict[str, Any]:
        self._ensure_function(function_name)
        return {"callers": sorted(self._callers.get(function_name, set()))}

    def get_callees(self, function_name: str) -> Dict[str, Any]:
        self._ensure_function(function_name)
        return {"callees": sorted(self._callees.get(function_name, set()))}

    def get_call_graph(self, function_name: str = "", depth: int = 2) -> Dict[str, Any]:
        return {
            "callers": sorted(self._callers.get(function_name, set())),
            "callees": sorted(self._callees.get(function_name, set())),
        }

    def search_functions(self, query: str) -> List[Dict[str, Any]]:
        q = query.lower()
        return [
            {"name": n, "file_path": info["file"]}
            for n, info in self._funcs.items()
            if q in n.lower()
        ][:50]

    def get_fuzzers(self) -> List[str]:
        return list(self._fuzzers)

    def get_fuzzer_source(self, fuzzer_name: str = "") -> Dict[str, Any]:
        # The get_fuzzer_source tool spreads this result ({**result}), so return a
        # dict shaped like the real AnalysisClient's, not a bare string.
        for cand in (fuzzer_name, "LLVMFuzzerTestOneInput"):
            info = self._funcs.get(cand)
            if info:
                return {
                    "fuzzer": fuzzer_name or cand,
                    "source": info["source"],
                    "source_path": info["file"],
                }
        return {"error": f"fuzzer source for '{fuzzer_name}' not indexed"}

    def get_build_paths(self) -> Dict[str, Any]:
        return {"source_root": str(self.source_root)}

    # ---- reachability (approximate, BFS over the shallow call graph) ------

    def _reaches(self, src_fn: str, dst_fn: str, max_depth: int = 12):
        """BFS from src to dst over callee edges. Returns distance or None."""
        if src_fn == dst_fn:
            return 0
        seen = {src_fn}
        q = deque([(src_fn, 0)])
        while q:
            cur, d = q.popleft()
            if d >= max_depth:
                continue
            for callee in self._callees.get(cur, ()):
                if callee == dst_fn:
                    return d + 1
                if callee not in seen:
                    seen.add(callee)
                    q.append((callee, d + 1))
        return None

    def _entry_points(self, fuzzer_name: str) -> List[str]:
        cands = [fuzzer_name, "LLVMFuzzerTestOneInput"]
        return [c for c in cands if c in self._funcs] or ["LLVMFuzzerTestOneInput"]

    def get_reachability(self, fuzzer_name: str, function_name: str) -> Dict[str, Any]:
        self._ensure_function(function_name)
        if function_name not in self._funcs:
            # Unknown to our shallow index — do not claim unreachable.
            return {"reachable": True, "distance": None, "note": "unindexed; assumed reachable"}
        for entry in self._entry_points(fuzzer_name):
            dist = self._reaches(entry, function_name)
            if dist is not None:
                return {"reachable": True, "distance": dist}
        # No static path found. Our graph misses function pointers/macros, so this
        # is "no path found", not a hard "unreachable".
        return {"reachable": False, "distance": None, "note": "no static path in shallow graph"}

    # check_reachability tool calls this name in some paths
    def check_reachability(self, fuzzer_name: str, function_name: str) -> Dict[str, Any]:
        return self.get_reachability(fuzzer_name, function_name)

    def find_all_paths(self, fuzzer_name: str, function_name: str, **_: Any) -> Dict[str, Any]:
        r = self.get_reachability(fuzzer_name, function_name)
        if r.get("reachable") and r.get("distance") is not None:
            return {"paths": [[fuzzer_name, "...", function_name]], "reachable": True}
        return {"paths": [], "reachable": r.get("reachable", False)}

    def get_reachable_functions(self, fuzzer_name: str = "", **_: Any) -> List[str]:
        entry = self._entry_points(fuzzer_name)[0]
        seen = {entry}
        q = deque([entry])
        while q:
            cur = q.popleft()
            for callee in self._callees.get(cur, ()):
                if callee not in seen:
                    seen.add(callee)
                    q.append(callee)
        return sorted(seen)

    def get_unreached_functions(self, fuzzer_name: str = "", **_: Any) -> List[str]:
        reached = set(self.get_reachable_functions(fuzzer_name))
        return sorted(set(self._funcs) - reached)

    # ---- suspicious points (stored here, not in Mongo) -------------------
    # create/update_suspicious_point_impl forward to the analysis client, so the
    # SP store lives on this backend. The probe reads `suspicious_points` back to
    # answer Q1 (did the finder create one?) and Q2 (what verdict did the
    # verifier write?), with no database involved.

    def create_suspicious_point(
        self,
        function_name: str,
        description: str = "",
        vuln_type: str = "",
        score: float = 0.5,
        important_controlflow: Optional[list] = None,
        harness_name: str = "",
        sanitizer: str = "",
        direction_id: str = "",
        agent_id: str = "",
    ) -> Dict[str, Any]:
        import uuid

        sp_id = uuid.uuid4().hex
        self.suspicious_points.append(
            {
                "suspicious_point_id": sp_id,
                "function_name": function_name,
                "description": description,
                "vuln_type": vuln_type,
                "score": score,
                "important_controlflow": important_controlflow or [],
                "harness_name": harness_name,
                "sanitizer": sanitizer,
                "created_by_agent_id": agent_id,
                # verifier-written fields, filled by update_suspicious_point
                "is_checked_by_verifier": None,
                "is_crash_found": None,
                "is_important": None,
                "verification_notes": None,
            }
        )
        return {"id": sp_id, "merged": False}

    def update_suspicious_point(self, sp_id: str, **fields: Any) -> Dict[str, Any]:
        for sp in self.suspicious_points:
            if sp["suspicious_point_id"] == sp_id:
                for k, v in fields.items():
                    if v is not None:
                        sp[k] = v
                return {"updated": True}
        # Probe-injected SPs (Q2) may not be in the list yet; record anyway.
        rec = {"suspicious_point_id": sp_id}
        rec.update({k: v for k, v in fields.items() if v is not None})
        self.suspicious_points.append(rec)
        return {"updated": True}

    def call_tool(self, name: str, **kwargs: Any) -> Any:
        fn = getattr(self, name, None)
        if callable(fn):
            return fn(**kwargs)
        return {"error": f"LocalAnalysisBackend has no method '{name}'"}
