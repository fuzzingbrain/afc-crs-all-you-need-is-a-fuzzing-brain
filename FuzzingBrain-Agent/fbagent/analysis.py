# SPDX-License-Identifier: Apache-2.0
"""The deterministic navigation substrate: a static call graph, a sink
pre-screen, and reachability/distance from the harness entry.

This is the part of the agent that is *not* the model. It reads the challenge
source and computes, deterministically and reproducibly:

  - a call graph  (who calls whom),                              [pillars P2/P3]
  - a set of candidate fault sinks  (unchecked memcpy, input-sized allocation,
    array index, recursion, ...),                                     [pillar P5]
  - which sinks the harness entry can actually reach, and how far each is in
    call-graph hops,                                                  [pillar P1]

and hands the agent a *worklist* of reachable niches ranked by distance. The
model then reasons about and attacks those niches; it does not have to guess
where the bugs might be, and it cannot claim reach the graph does not support.

The call graph is lexical (function definitions by brace-matching, call sites by
`name(` tokens) so it works on any C/C++/Java project with no build system --
the price is imprecision (no type resolution, macro noise), which the ranking and
the model's own reading absorb. It is refined by clang's AST for C/C++ files that
parse. Everything here is pure computation over text: same input, same worklist.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# Files worth reading: source in the languages the bench uses. Skip obvious
# non-target trees so the graph is about the code the harness links, not docs,
# tests, or vendored build junk.
_C_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}
_JAVA_EXT = {".java"}
_SKIP_DIR = re.compile(r"(^|/)(\.git|doc|docs|man|examples?|vcnet|desktop|"
                       r"templates|locale|test|tests|testing|third_party|"
                       r"node_modules|build|cmake)(/|$)")

# The harness entry point, per language/engine. The graph is rooted here.
_ENTRIES = ("LLVMFuzzerTestOneInput", "fuzzerTestOneInput", "TestOneInput",
            "fuzzOne")

_MAX_FILES = 1200          # a big project is bounded so recon stays fast
_MAX_BYTES = 1_500_000     # skip a single pathological generated file


@dataclass
class Sink:
    func: str
    file: str
    line: int
    klass: str        # the fault class this pattern suggests
    why: str          # the exact code that matched
    distance: int = -1
    path: list[str] = field(default_factory=list)


# --------------------------------------------------------------- source discovery

def discover(root: Path) -> tuple[list[Path], str]:
    """Source files under root, and the dominant language ('c' or 'java')."""
    c, java = [], []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(root))
        if _SKIP_DIR.search("/" + rel):
            continue
        ext = p.suffix.lower()
        if ext in _C_EXT:
            c.append(p)
        elif ext in _JAVA_EXT:
            java.append(p)
        if len(c) + len(java) > _MAX_FILES:
            break
    # Language is decided by which harness entry symbol actually appears, not by
    # file count: a project that ships both C++ and Java  is classified
    # by the harness it is fuzzed through, so the sink patterns match the code the
    # entry reaches. Fall back to the file-count majority when no entry is found.
    lang = _lang_from_entry(c, java)
    if lang is None:
        lang = "java" if len(java) > len(c) else "c"
    files = (java if lang == "java" else c) + (c if lang == "java" else java)
    return files[:_MAX_FILES], lang


_C_ENTRY = re.compile(r"\bLLVMFuzzerTestOneInput\b")
_JAVA_ENTRY = re.compile(r"\bfuzzerTestOneInput\b|com\.code_intelligence\.jazzer")


def _lang_from_entry(c: list[Path], java: list[Path]) -> str | None:
    """'c' or 'java' from whichever fuzz entry symbol appears in a harness file,
    or None if neither is found. Harness-looking files are scanned first, cheaply."""
    def rank(p: Path) -> int:
        s = str(p).lower()
        return 0 if ("harness" in s or "fuzz" in s) else 1
    for p in sorted(c + java, key=rank)[:60]:
        try:
            text = p.read_text(errors="replace")
        except Exception:
            continue
        if _C_ENTRY.search(text):
            return "c"
        if _JAVA_ENTRY.search(text):
            return "java"
    return None


# --------------------------------------------------------------- function segmentation

# A function definition header: an identifier immediately before `(`, whose
# matching `)` is followed (possibly across newlines and a few C++ qualifiers) by
# `{`. The scan only *tests* an identifier as a header when it is not already
# inside a function body -- see _segment_functions -- so a call site like
# `if (!(p = malloc(n))) {` is never mistaken for a definition of `malloc`.
_DEF_HEAD = re.compile(r"(?P<name>[A-Za-z_]\w*)\s*\(")
_IDENT = re.compile(r"[A-Za-z_]\w*")
# Tokens the C/C++ grammar allows between a header's `)` and its `{`. A `)` that
# is followed by anything else (`;`, `=`, `,`, another `)`) is not a definition.
_QUAL = re.compile(r"(const|volatile|noexcept|override|final|mutable|throw|"
                   r"__restrict|restrict|_Nonnull|_Nullable)\b\s*(\([^)]*\))?")
_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "catch",
             "do", "else", "case", "new", "delete", "throw", "assert", "static_assert"}


def _mask(text: str) -> str:
    """text with string/char-literal bodies and comments blanked to spaces,
    length and newlines preserved. Structural scans (brace matching, header
    detection) run on this so a `{` in a string or a `(` in a comment is inert."""
    out = list(text)
    n = len(text)
    i = 0
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
            if i + 1 < n:
                out[i + 1] = " "
            i += 2
            continue
        if c == '"' or c == "'":
            i += 1
            while i < n and text[i] != c:
                if text[i] == "\\" and i + 1 < n:
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            i += 1  # step over the closing quote
            continue
        i += 1
    return "".join(out)


def _header_body(masked: str, start: int) -> tuple[str, int, int] | None:
    """If a function-definition header begins at `start`, return
    (name, body_open_index, body_close_index); else None. `start` is the index
    of the header's leading identifier in the masked text."""
    n = len(masked)
    m = _DEF_HEAD.match(masked, start)
    if not m or m.group("name") in _KEYWORDS:
        return None
    # match the parameter-list parens
    depth, k = 0, m.end() - 1
    while k < n:
        ch = masked[k]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
        k += 1
    if k >= n:
        return None
    # after `)`: whitespace and only recognised qualifiers may precede `{`
    p = k + 1
    while True:
        while p < n and masked[p] in " \t\r\n":
            p += 1
        if p >= n:
            return None
        if masked[p] == "{":
            break
        q = _QUAL.match(masked, p)
        if not q:
            return None            # `;`, `=`, `,`, ... -> not a definition
        p = q.end()
    # brace-match the body
    depth, b = 0, p
    while b < n:
        ch = masked[b]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        b += 1
    if b >= n:
        return None
    return (m.group("name"), p, b)


def _segment_functions(text: str) -> list[tuple[str, int, int, int]]:
    """(name, header_line, body_start_index, body_end_index) for each function.

    A single linear scan over the masked text. Only positions that are *not*
    already inside a function body are tested as headers: when a header is
    accepted, the scan jumps past its whole body, so nested call sites are never
    seen at the top level. Class/namespace/struct braces are simply counted, so
    in-class C++ methods and Java methods are still found.
    """
    masked = _mask(text)
    n = len(masked)
    line_starts = _line_index(text)
    funcs: list[tuple[str, int, int, int]] = []
    i = 0
    while i < n:
        c = masked[i]
        if c == "_" or c.isalpha():
            hb = _header_body(masked, i)
            if hb is not None:
                name, bopen, bclose = hb
                funcs.append((name, _line_of(line_starts, i), bopen + 1, bclose))
                i = bclose + 1          # jump past the body; never look inside it
                continue
            im = _IDENT.match(masked, i)
            i = im.end() if im else i + 1
            continue
        i += 1
    return funcs


def _line_index(text: str) -> list[int]:
    idx, pos = [0], 0
    for line in text.splitlines(keepends=True):
        pos += len(line)
        idx.append(pos)
    return idx


def _line_of(line_starts: list[int], pos: int) -> int:
    import bisect
    return bisect.bisect_right(line_starts, pos)


_CALL = re.compile(r"(?P<name>[A-Za-z_]\w*)\s*\(")


def _calls_in(body: str) -> set[str]:
    out = set()
    for m in _CALL.finditer(body):
        name = m.group("name")
        if name not in _KEYWORDS:
            out.add(name)
    return out


# --------------------------------------------------------------- the sink pre-screen

# Deterministic patterns. Each is (regex, fault-class). Kept conservative: a hit
# is a *candidate* the model must confirm, so precision matters less than not
# missing the classic sinks. Length/size arg being non-literal is the signal.
_C_SINKS = [
    (re.compile(r"\bmemcpy\s*\([^;]*,[^;]*,[^;)]*\)"), "heap-buffer-overflow", "memcpy"),
    (re.compile(r"\bmemmove\s*\([^;]*,[^;]*,[^;)]*\)"), "heap-buffer-overflow", "memmove"),
    (re.compile(r"\bstrcpy\s*\("), "buffer-overflow", "strcpy"),
    (re.compile(r"\bstrcat\s*\("), "buffer-overflow", "strcat"),
    (re.compile(r"\bsprintf\s*\("), "buffer-overflow", "sprintf"),
    (re.compile(r"\balloca\s*\("), "stack-overflow", "alloca"),
    (re.compile(r"\b(malloc|calloc|realloc)\s*\([^;)]*[a-z_]\w*[^;)]*\)"),
     "allocation-size", "input-sized alloc"),
    (re.compile(r"\[\s*[a-z_]\w*\s*(\+\+|--|\+|-)?\s*[a-z_0-9]*\s*\]"),
     "out-of-bounds", "variable index"),
]
_JAVA_SINKS = [
    (re.compile(r"new\s+\w+\s*\[\s*[a-z_]\w*"), "negative-array-size", "input-sized array"),
    (re.compile(r"\.read\w*\s*\("), "parse", "stream read"),
    (re.compile(r"Integer\.parseInt|Long\.parseLong"), "number-format", "parse int"),
    (re.compile(r"readObject\s*\(|ObjectInputStream"), "deserialization", "java deserialize"),
    (re.compile(r"\[\s*[a-z_]\w*\s*\]"), "index-out-of-bounds", "variable index"),
]


def _sinks_in(func: str, file_rel: str, header_line: int, body: str,
             base_line: int, patterns) -> list[Sink]:
    out = []
    lines = body.splitlines()
    for off, ln in enumerate(lines):
        for rx, klass, why in patterns:
            if rx.search(ln):
                out.append(Sink(func=func, file=file_rel, line=base_line + off,
                                klass=klass, why=f"{why}: {ln.strip()[:80]}"))
                break
    return out


# --------------------------------------------------------------- clang refinement (C/C++)

def _clang_calls(path: Path, include_dirs: list[str]) -> dict[str, set[str]] | None:
    """Precise caller->callees for one C/C++ file via clang's AST, or None if it
    does not parse. Adds real edges on top of the lexical graph where it can."""
    inc = []
    for d in include_dirs:
        inc += ["-I", d]
    try:
        r = subprocess.run(["clang", "-fsyntax-only", "-Xclang", "-ast-dump=json",
                            "-ferror-limit=0", "-w", str(path), *inc],
                           capture_output=True, text=True, timeout=25)
        if not r.stdout or len(r.stdout) < 50:
            return None
        ast = json.loads(r.stdout)
    except Exception:
        return None
    edges: dict[str, set[str]] = {}

    def walk(node, cur):
        if not isinstance(node, dict):
            return
        k = node.get("kind")
        if k == "FunctionDecl" and node.get("name") and node.get("inner"):
            cur = node["name"]
            edges.setdefault(cur, set())
        elif k == "CallExpr" and cur:
            callee = _callee_name(node)
            if callee:
                edges[cur].add(callee)
        for ch in node.get("inner", []) or []:
            walk(ch, cur)

    walk(ast, None)
    return edges or None


def _callee_name(call: dict):
    for ch in call.get("inner", []) or []:
        if ch.get("kind") == "ImplicitCastExpr":
            for g in ch.get("inner", []) or []:
                if g.get("kind") == "DeclRefExpr":
                    return (g.get("referencedDecl") or {}).get("name")
        if ch.get("kind") == "DeclRefExpr":
            return (ch.get("referencedDecl") or {}).get("name")
    return None


# --------------------------------------------------------------- the graph + reachability

class CallGraph:
    def __init__(self):
        self.edges: dict[str, set[str]] = {}
        self.where: dict[str, tuple[str, int]] = {}   # func -> (file, line)

    def add_def(self, func: str, file_rel: str, line: int):
        self.edges.setdefault(func, set())
        self.where.setdefault(func, (file_rel, line))

    def add_edge(self, a: str, b: str):
        self.edges.setdefault(a, set()).add(b)

    def entry(self) -> str | None:
        for e in _ENTRIES:
            if e in self.edges:
                return e
        # sometimes the entry is only a caller, never a callee/def; still usable
        for e in _ENTRIES:
            for callees in self.edges.values():
                if e in callees:
                    return e
        return None

    def distances(self, root: str) -> dict[str, int]:
        """BFS hop-distance from root to every reachable function."""
        from collections import deque
        dist = {root: 0}
        q = deque([root])
        while q:
            u = q.popleft()
            for v in self.edges.get(u, ()):  # noqa: SIM118
                if v not in dist:
                    dist[v] = dist[u] + 1
                    q.append(v)
        return dist

    def path_to(self, root: str, target: str, dist: dict[str, int]) -> list[str]:
        """One shortest call path root..target, reconstructed greedily over BFS
        distances (deterministic: callees sorted)."""
        if target not in dist:
            return []
        path = [target]
        cur = target
        # walk backwards: find a predecessor whose distance is one less
        preds = {}
        for a, bs in self.edges.items():
            for b in bs:
                preds.setdefault(b, set()).add(a)
        while cur != root:
            cands = [p for p in sorted(preds.get(cur, ())) if dist.get(p, 1 << 30) == dist[cur] - 1]
            if not cands:
                break
            cur = cands[0]
            path.append(cur)
        return list(reversed(path))

    def cycles(self, reachable: set[str]) -> list[list[str]]:
        """The call cycles wholly inside `reachable` -- each a stack-overflow sink
        the pattern pre-screen cannot see, because unbounded recursion is a graph
        property, not a token. Returns one representative cycle per strongly
        connected component of size > 1, plus every direct self-loop (f calls f),
        deterministically (Tarjan over sorted adjacency, cycle rotated to its
        smallest name). This is a sink found purely from graph structure."""
        # Tarjan's SCC, iterative to survive deep graphs.
        index: dict[str, int] = {}
        low: dict[str, int] = {}
        onstack: dict[str, bool] = {}
        stack: list[str] = []
        out: list[list[str]] = []
        counter = 0
        nodes = sorted(n for n in self.edges if n in reachable)
        for start in nodes:
            if start in index:
                continue
            work = [(start, iter(sorted(self.edges.get(start, ()))))]
            index[start] = low[start] = counter; counter += 1
            stack.append(start); onstack[start] = True
            while work:
                v, it = work[-1]
                advanced = False
                for w in it:
                    if w not in reachable or w not in self.edges:
                        continue
                    if w not in index:
                        index[w] = low[w] = counter; counter += 1
                        stack.append(w); onstack[w] = True
                        work.append((w, iter(sorted(self.edges.get(w, ())))))
                        advanced = True
                        break
                    elif onstack.get(w):
                        low[v] = min(low[v], index[w])
                if advanced:
                    continue
                if low[v] == index[v]:
                    comp = []
                    while True:
                        w = stack.pop(); onstack[w] = False
                        comp.append(w)
                        if w == v:
                            break
                    if len(comp) > 1:
                        # rotate to smallest name for a stable representative
                        m = min(range(len(comp)), key=lambda i: comp[i])
                        out.append(comp[m:] + comp[:m])
                work.pop()
                if work:
                    p = work[-1][0]
                    low[p] = min(low[p], low[v])
        # direct self-recursion (a self-loop is an SCC of size 1 Tarjan skips)
        for n in nodes:
            if n in self.edges.get(n, ()):
                out.append([n])
        return out


# --------------------------------------------------------------- orchestration

@dataclass
class Context:
    """Everything the deterministic substrate computes for one challenge, built
    once and reused by every tool. Function bodies are *not* held in memory --
    only their (file, char-span) so a tool can re-read the one it needs; a big
    project is then a few MB of graph, not all its source at once."""
    root: Path
    lang: str
    entry: str | None
    files: int
    cg: CallGraph
    dist: dict[str, int]
    reach: list[Sink]
    span: dict[str, tuple[str, int, int]]   # func -> (file_rel, body_start, body_end)


_CTX_CACHE: dict[tuple[str, bool], Context] = {}


def build(root: Path, use_clang: bool = False) -> Context:
    """Discover source, segment functions, build the call graph and sink list,
    compute reachability from the entry. Cached per (root, use_clang) so the
    recon pass and the reached/gates tools share one graph. clang refinement is
    off by default: the lexical graph is ~20x faster and enough for ranking."""
    key = (str(Path(root).resolve()), use_clang)
    if key in _CTX_CACHE:
        return _CTX_CACHE[key]
    root = Path(root)
    files, lang = discover(root)
    cg = CallGraph()
    sinks: list[Sink] = []
    span: dict[str, tuple[str, int, int]] = {}
    patterns = _JAVA_SINKS if lang == "java" else _C_SINKS
    include_dirs = _guess_includes(root, files) if lang == "c" else []

    for p in files:
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
            text = p.read_text(errors="replace")
        except Exception:
            continue
        rel = str(p.relative_to(root))
        for name, hline, bstart, bend in _segment_functions(text):
            cg.add_def(name, rel, hline)
            span.setdefault(name, (rel, bstart, bend))
            body = text[bstart:bend]
            for callee in _calls_in(body):
                cg.add_edge(name, callee)
            base_line = text.count("\n", 0, bstart) + 1
            sinks += _sinks_in(name, rel, hline, body, base_line, patterns)

    if use_clang and lang == "c":
        for p in _clang_targets(files, root):
            edges = _clang_calls(p, include_dirs)
            if edges:
                for a, bs in edges.items():
                    for b in bs:
                        cg.add_edge(a, b)

    entry = cg.entry()
    dist = cg.distances(entry) if entry else {}
    # Recursion/call-cycle sinks: a stack overflow the token pre-screen cannot see,
    # read straight off the reachable graph (P-recursion). Folded into the sink
    # list so it flows through the same reachability filter and ranking below.
    if entry:
        for cyc in cg.cycles(set(dist)):
            rep = cyc[0]
            file_rel, line = cg.where.get(rep, ("?", 0))
            kind = "self-recursion" if len(cyc) == 1 else f"recursion cycle of {len(cyc)}"
            ring = " -> ".join(cyc + [cyc[0]]) if len(cyc) > 1 else f"{rep} -> {rep}"
            sinks.append(Sink(func=rep, file=file_rel, line=line, klass="stack-overflow",
                              why=f"{kind}: {ring[:80]}"))
    reach: list[Sink] = []
    seen = set()
    for s in sinks:
        d = dist.get(s.func)
        if d is None:
            continue
        skey = (s.func, s.klass, s.line)
        if skey in seen:
            continue
        seen.add(skey)
        s.distance = d
        reach.append(s)
    reach.sort(key=lambda s: (s.distance, s.file, s.line))
    for s in reach:
        s.path = cg.path_to(entry, s.func, dist) if entry else []

    ctx = Context(root=root, lang=lang, entry=entry, files=len(files),
                  cg=cg, dist=dist, reach=reach, span=span)
    if len(_CTX_CACHE) > 3:            # bound the cache; a run only needs one
        _CTX_CACHE.clear()
    _CTX_CACHE[key] = ctx
    return ctx


def analyze(root: Path, use_clang: bool = False, max_sinks: int = 40) -> dict:
    """Build the worklist. Returns a dict with the ranked reachable sinks and a
    human summary the agent reads at recon time."""
    ctx = build(Path(root), use_clang=use_clang)
    if not ctx.entry:
        return {"lang": ctx.lang, "entry": None, "files": ctx.files,
                "reachable_sinks": [], "summary":
                "No fuzzer entry point found in the source; falling back to "
                "unguided reading. (Looked for LLVMFuzzerTestOneInput.)"}
    reach = ctx.reach[:max_sinks]
    cg, dist, entry, lang = ctx.cg, ctx.dist, ctx.entry, ctx.lang
    return {
        "lang": lang, "entry": entry, "files": ctx.files,
        "functions": len(cg.edges), "reachable_from_entry": len(dist),
        "reachable_sinks": [vars(s) for s in reach],
        "summary": _summary(entry, lang, cg, dist, reach),
    }


def _guess_includes(root: Path, files: list[Path]) -> list[str]:
    """Directories that hold headers, so clang has a chance to resolve includes.
    Best-effort and bounded; wrong guesses just make a file not parse."""
    dirs = set()
    for p in files:
        if p.suffix.lower() in {".h", ".hpp", ".hh"}:
            dirs.add(str(p.parent))
    dirs.add(str(root))
    dirs.add(str(root / "src"))
    # common include roots
    for d in ("include", "src/include"):
        if (root / d).is_dir():
            dirs.add(str(root / d))
    return sorted(dirs)[:60]


def _clang_targets(files: list[Path], root: Path) -> list[Path]:
    """Which files to spend a clang parse on: the harness, plus .c/.cc files
    (headers are pulled in as includes). Bounded so recon stays inside a minute."""
    out = [p for p in files if p.suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}]
    harness = [p for p in out if "harness" in str(p).lower() or "fuzz" in str(p).lower()]
    rest = [p for p in out if p not in harness]
    return (harness + rest)[:25]


def _summary(entry, lang, cg: CallGraph, dist, reach: list[Sink]) -> str:
    lines = [
        f"Deterministic static analysis ({lang}). Entry: {entry}. "
        f"{len(cg.edges)} functions, {len(dist)} reachable from the entry.",
        f"{len(reach)} candidate fault sinks the harness can reach, nearest first "
        "(distance = call-graph hops from the entry). Attack the near ones first; "
        "for diversity, spread across different files/classes:",
        "",
    ]
    for i, s in enumerate(reach, 1):
        path = " -> ".join(s.path) if s.path else entry
        lines.append(f"{i:2}. [{s.klass}] {s.func}  ({s.file}:{s.line}, dist {s.distance})")
        lines.append(f"      {s.why}")
        lines.append(f"      path: {path}")
    lines.append("")
    lines.append("These are computed candidates, not confirmed bugs. Confirm each "
                 "by reading it, build an input that reaches it, and verify with "
                 "./submit. Aim for sinks in DIFFERENT functions/files to score "
                 "distinct crashes.")
    return "\n".join(lines)


# --------------------------------------------------------------- P4: where the PoV reached

# A stack frame the sanitizer/JVM printed. Deterministic: parsed from the crash
# report the grader already produces, so "where did my input reach" is a fact the
# agent reads off the real execution, not a guess it makes from the source.
_FRAME_C = re.compile(r"#(?P<n>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<func>[\w:~<>]+)"
                      r"(?:\([^)]*\))?\s+(?P<file>[^\s:]+):(?P<line>\d+)")
_FRAME_JAVA = re.compile(r"\bat\s+(?P<func>[\w.$<>]+)\((?P<file>[\w.$]+\.java):(?P<line>\d+)\)")
_ERR_LINE = re.compile(r"(?P<klass>ERROR:\s*\w+Sanitizer|runtime error|"
                       r"AddressSanitizer|libFuzzer:|Java Exception|"
                       r"==\d+==\s*ERROR)[:\s].*", re.I)


@dataclass
class Frame:
    n: int
    func: str
    file: str
    line: int
    in_project: bool = False


def crash_frames(stderr: str, root: Path | None = None) -> list[Frame]:
    """The call stack from a sanitizer / JVM crash report, top frame first.

    Purely lexical over the report text -- no execution, no rebuild. When `root`
    is given, each frame is tagged in_project if the file resolves under it, so
    the agent can tell the frame in *its* code from the libc/runtime frames above
    and below it."""
    frames: list[Frame] = []
    for m in _FRAME_C.finditer(stderr):
        frames.append(Frame(int(m.group("n")), m.group("func"),
                            m.group("file"), int(m.group("line"))))
    if not frames:
        for i, m in enumerate(_FRAME_JAVA.finditer(stderr)):
            frames.append(Frame(i, m.group("func"), m.group("file"),
                                int(m.group("line"))))
    if root is not None:
        rp = Path(root).resolve()
        names = {p.name for p in rp.rglob("*") if p.is_file()} if rp.is_dir() else set()
        for f in frames:
            f.in_project = Path(f.file).name in names
    return frames


def reached_report(stderr: str, root: Path) -> str:
    """A short, deterministic 'your PoV reached here' note from a crash report.

    Names the crashing frame, the nearest frame inside the challenge's own code,
    and -- if that function is one the static graph knew about -- its distance
    from the entry. This is pillar P4: the agent is told, from the real run,
    exactly where its input landed, instead of inferring it."""
    frames = crash_frames(stderr, root)
    if not frames:
        return ""
    ctx = build(root)
    top = frames[0]
    proj = next((f for f in frames if f.in_project), None)
    lines = ["reached (from the sanitizer stack -- this is where your input actually went):"]
    lines.append(f"  crash frame: {top.func}  ({top.file}:{top.line})")
    if proj and proj is not top:
        lines.append(f"  in your code: {proj.func}  ({proj.file}:{proj.line})")
    key = (proj or top).func.split("::")[-1]
    d = ctx.dist.get(key)
    if d is not None:
        path = ctx.cg.path_to(ctx.entry, key, ctx.dist) if ctx.entry else []
        lines.append(f"  graph distance from entry: {d} hop(s)"
                     + (f"   path: {' -> '.join(path)}" if path else ""))
    depth = sum(1 for f in frames if f.in_project)
    lines.append(f"  {len(frames)} frames, {depth} in the challenge's own source.")
    return "\n".join(lines)


# --------------------------------------------------------------- P7: constraints to a target

# Literal input gates: comparisons the code makes against attacker bytes that an
# input must satisfy to travel deeper. Solved without z3 -- magic bytes, minimum
# lengths and byte-equality are literal constraints, read straight off the text.
_G_MEMCMP = re.compile(r"\b(?:mem|str|strn)cmp\s*\([^,]+,\s*\"([^\"]{1,64})\"")
_G_MAGIC = re.compile(r"==\s*(0x[0-9a-fA-F]{2,8}|'[^']'|\d{2,10})")
_G_LEN = re.compile(r"\b(?:size|len|length|n|count|nbytes|remaining)\w*\s*"
                    r"(<|<=|>=|>)\s*(\d{1,9}|0x[0-9a-fA-F]+)")
_G_BYTEEQ = re.compile(r"\[[^\]]{0,20}\]\s*==\s*(0x[0-9a-fA-F]{1,2}|'[^']'|\d{1,3})")


def _func_body(ctx: Context, name: str) -> str:
    loc = ctx.span.get(name)
    if not loc:
        return ""
    rel, bstart, bend = loc
    try:
        text = (ctx.root / rel).read_text(errors="replace")
    except Exception:
        return ""
    return text[bstart:bend]


def gates_to(root: Path, target: str, max_funcs: int = 8) -> str:
    """The literal input constraints on the shortest path entry..target.

    For each function on the path, the byte-magic / length / equality gates it
    imposes are extracted deterministically. This is the seed-tree precompute
    (pillar P7): the agent gets the concrete literals its input must contain to
    reach `target`, which is most of what a seed for that node has to satisfy --
    no solver needed for the common gates, and no guessing which bytes matter."""
    ctx = build(Path(root))
    if not ctx.entry:
        return "no entry point; cannot compute a path."
    key = target.split("::")[-1]
    if key not in ctx.dist:
        near = sorted((abs(len(k) - len(key)), k) for k in ctx.dist
                      if key.lower() in k.lower())[:5]
        hint = ("  did you mean: " + ", ".join(k for _, k in near)) if near else ""
        return f"'{target}' is not reachable from {ctx.entry} in the static graph.{hint}"
    path = ctx.cg.path_to(ctx.entry, key, ctx.dist) or [ctx.entry, key]
    out = [f"Path to {target}  (dist {ctx.dist[key]}):  {' -> '.join(path)}",
           "Literal input gates on this path (satisfy these for the input to reach the target):"]
    found_any = False
    for fn in path[:max_funcs]:
        body = _func_body(ctx, fn)
        if not body:
            continue
        gates: list[str] = []
        for m in _G_MEMCMP.finditer(body):
            gates.append(f"magic bytes: input must contain \"{m.group(1)}\"")
        for m in _G_MAGIC.finditer(body):
            gates.append(f"equals constant {m.group(1)}")
        for m in _G_LEN.finditer(body):
            gates.append(f"length gate: {m.group(0).strip()}")
        for m in _G_BYTEEQ.finditer(body):
            gates.append(f"byte equals {m.group(1)}")
        gates = list(dict.fromkeys(gates))[:6]     # dedup, cap noise
        if gates:
            found_any = True
            loc = ctx.span.get(fn, ("?", 0, 0))[0]
            out.append(f"  {fn}  ({loc}):")
            out += [f"      - {g}" for g in gates]
    if not found_any:
        out.append("  (no literal magic/length gates found on this path -- the "
                   "target is likely reachable with a minimal well-formed input.)")
    out.append("These are literal constraints read from the source; place the "
               "magic bytes at the offsets the harness parse dictates, then verify with ./submit.")
    return "\n".join(out)


if __name__ == "__main__":
    import sys
    out = analyze(Path(sys.argv[1] if len(sys.argv) > 1 else "."))
    print(out["summary"])
    print(f"\n[{len(out['reachable_sinks'])} reachable sinks / "
          f"{out.get('functions', 0)} functions]")
