from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
import logging
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

try:
    from rapidfuzz import fuzz  # type: ignore
    _FUZZ_OK = True
except Exception:
    _FUZZ_OK = False

try:
    from tree_sitter import Parser  # type: ignore
    from tree_sitter_languages import get_language  # type: ignore
    _TS_OK = True
except Exception:
    _TS_OK = False


@dataclass(frozen=True)
class FunctionBody:
    start_line: int
    end_line: int
    body: str


@dataclass(frozen=True)
class Function:
    name: str
    file_path: Path
    bodies: Tuple[FunctionBody, ...]


@dataclass(frozen=True)
class TypeDefinition:
    name: str
    file_path: Path
    definition: str
    definition_line: int
    type: str | None = None


class LocalCodeQuery:
    """Local CodeQuery-like wrapper using cscope/ctags/cqmakedb/cqsearch + Tree-sitter.

    DB is created under `<project_root>/.cqdb` and reused across calls.
    Provides Buttercup-like APIs with fuzzy and constrained queries.
    """

    def __init__(self, project_root: Path) -> None:
        self.root = project_root
        self.db_dir = self.root / ".cqdb"
        self.cscope_files = self.db_dir / "cscope.files"
        self.cscope_out = self.db_dir / "cscope.out"
        self.tags = self.db_dir / "tags"
        self.db = self.db_dir / "codequery.db"
        self._ensure_db()

    def _have_tools(self) -> bool:
        return all(shutil.which(cmd) for cmd in ("cscope", "ctags", "cqmakedb", "cqsearch"))

    def _ensure_db(self) -> None:
        if not self._have_tools():
            raise RuntimeError("CodeQuery tools not installed (cscope/ctags/cqmakedb/cqsearch)")
        self.db_dir.mkdir(parents=True, exist_ok=True)
        # Only consider DB usable if cscope index, tags, and file list exist and are non-empty
        if (
            self.db.exists()
            and self.cscope_out.exists()
            and self.tags.exists()
            and self.cscope_files.exists()
            and self.cscope_files.stat().st_size > 0
        ):
            logging.getLogger(__name__).info("[CQ] Using existing CodeQuery DB at %s", self.db_dir)
            return
        logging.getLogger(__name__).info("[CQ] Building CodeQuery DB at %s", self.db_dir)
        with self.cscope_files.open("w", encoding="utf-8") as f:
            # Iterate over glob patterns correctly (tuple with one item)
            for g in ("**/*.java",):
                for fp in self.root.rglob(g):
                    if fp.is_file():
                        f.write(str(fp.resolve()) + "\n")
        # Build cscope: use -c (required by cqmakedb), -b (build), -q (inverted index), with file list
        subprocess.run(["cscope", "-bcq", "-i", str(self.cscope_files.name)], cwd=self.db_dir, check=False, capture_output=True)
        subprocess.run(["ctags", "--fields=+i", "-n", "-L", str(self.cscope_files.name)], cwd=self.db_dir, check=False, capture_output=True)
        subprocess.run(["cqmakedb", "-s", self.db.name, "-c", self.cscope_out.name, "-t", self.tags.name, "-p"], cwd=self.db_dir, check=False, capture_output=True)
        logging.getLogger(__name__).info("[CQ] CodeQuery DB ready at %s", self.db_dir)

    def _run_cqsearch(self, *args: str) -> List[Tuple[str, Path, int, str]]:
        try:
            proc = subprocess.run(["cqsearch", *args], cwd=self.db_dir, check=True, text=True, capture_output=True)
            out = proc.stdout
        except subprocess.CalledProcessError:
            return []
        res: List[Tuple[str, Path, int, str]] = []
        for line in out.splitlines():
            try:
                value, file_line, body = line.split("\t", 2)
                file_str, ln = file_line.split(":", 1)
                res.append((value, Path(file_str), int(ln), body))
            except Exception:
                continue
        return res

    def _rebase(self, p: Path) -> Path:
        if p.exists():
            return p
        cand = self.root / p
        return cand if cand.exists() else p

    def _normalize_b(self, p: Optional[Path]) -> Optional[Path]:
        if p is None:
            return None
        if p.is_absolute():
            return p
        # Treat as relative to project root
        cand = (self.root / p).resolve()
        return cand

    # Tree-sitter helpers
    def _ts_parser(self, lang_name: str) -> Optional[Parser]:
        if not _TS_OK:
            return None
        try:
            lang = get_language(lang_name)
            parser = Parser()
            parser.set_language(lang)
            return parser
        except Exception:
            return None

    def _lang_from_ext(self, p: Path) -> Optional[str]:
        ext = p.suffix.lower()
        if ext == ".java":
            return "java"
        # if ext in (".c", ".h"):
        #     return "c"
        # if ext in (".cc", ".cpp", ".hpp", ".hh", ".cxx", ".hxx"):
        #     return "cpp"
        return None

    def _read_text(self, p: Path) -> str:
        try:
            return p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def _extract_java_function(self, p: Path, name: str) -> List[FunctionBody]:
        parser = self._ts_parser("java")
        src = self._read_text(p)
        if not parser or not src:
            # Fallback: regex brace matching
            bodies: List[FunctionBody] = []
            m = re.search(rf"^[\t ]*(?:[\w<>\[\]\s]+\s+)?{re.escape(name)}\s*\(.*\)\s*{{", src, re.MULTILINE)
            if m:
                start_line = src[: m.start()].count("\n") + 1
                lines = src.splitlines()
                brace = 0
                started = False
                end_line = start_line
                for i in range(start_line - 1, len(lines)):
                    line = lines[i]
                    if not started and "{" in line:
                        started = True
                    if started:
                        brace += line.count("{")
                        brace -= line.count("}")
                        if brace <= 0 and "}" in line:
                            end_line = i + 1
                            break
                body = "\n".join(lines[start_line - 1 : end_line])
                bodies.append(FunctionBody(start_line, end_line, body))
            return bodies
        tree = parser.parse(src.encode("utf-8"))
        lang = get_language("java")
        q_code = rf"""
(
 (method_declaration name: (identifier) @mname) @method
 (#eq? @mname "{name}")
)
(
 (constructor_declaration name: (identifier) @cname) @ctor
 (#eq? @cname "{name}")
)
"""
        query = lang.query(q_code)
        captures = query.captures(tree.root_node)
        bodies: List[FunctionBody] = []
        lines = src.splitlines()
        for node, cap in captures:
            if cap not in ("method", "ctor"):
                continue
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            body = "\n".join(lines[start_line - 1 : end_line])
            bodies.append(FunctionBody(start_line, end_line, body))
        return bodies

    def _extract_java_type(self, p: Path, name: str) -> Optional[TypeDefinition]:
        parser = self._ts_parser("java")
        src = self._read_text(p)
        if not parser or not src:
            # regex fallback for class/interface/enum line and block
            m = re.search(
                rf"^[\t ]*(class|interface|enum)\s+{re.escape(name)}\b.*?{{",
                src,
                re.MULTILINE | re.DOTALL,
            )
            if not m:
                return None
            start_line = src[: m.start()].count("\n") + 1
            lines = src.splitlines()
            brace = 0
            started = False
            end_line = start_line
            for i in range(start_line - 1, len(lines)):
                line = lines[i]
                if not started and "{" in line:
                    started = True
                if started:
                    brace += line.count("{")
                    brace -= line.count("}")
                    if brace <= 0 and "}" in line:
                        end_line = i + 1
                        break
            definition = "\n".join(lines[start_line - 1 : end_line])
            return TypeDefinition(name=name, file_path=p, definition=definition, definition_line=start_line, type=None)
        tree = parser.parse(src.encode("utf-8"))
        lang = get_language("java")
        q_code = rf"""
(
 (class_declaration name: (identifier) @tname) @class
 (#eq? @tname "{name}")
)
(
 (interface_declaration name: (identifier) @iname) @iface
 (#eq? @iname "{name}")
)
(
 (enum_declaration name: (identifier) @ename) @enum
 (#eq? @ename "{name}")
)
"""
        query = lang.query(q_code)
        captures = query.captures(tree.root_node)
        lines = src.splitlines()
        for node, cap in captures:
            if cap not in ("class", "iface", "enum"):
                continue
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            definition = "\n".join(lines[start_line - 1 : end_line])
            return TypeDefinition(name=name, file_path=p, definition=definition, definition_line=start_line, type=cap)
        return None

    # Public API
    def get_functions(
        self,
        function_name: str,
        file_path: Path | None = None,
        line_number: int | None = None,
        fuzzy: bool | None = False,
        fuzzy_threshold: int = 80,
    ) -> List[Function]:
        # Ensure DB is valid/initialized
        self._ensure_db()
        rows: List[Tuple[str, Path, int, str]] = []
        for flag in ("1", "2"):
            args = ["-s", self.db.name, "-p", flag, "-t", function_name, "-e", "-u"]
            bpath = self._normalize_b(file_path)
            if bpath:
                args += ["-b", str(bpath)]
            rows.extend(self._run_cqsearch(*args))

        # If no results when constrained by file, retry without -b and allow fuzzy if available
        if not rows and file_path is not None:
            for flag in ("1", "2"):
                args = ["-s", self.db.name, "-p", flag, "-t", function_name, "-e", "-u"]
                rows.extend(self._run_cqsearch(*args))
            if not rows and _FUZZ_OK:
                all_rows = self._run_cqsearch("-s", self.db.name, "-p", "2", "-t", "*", "-u")
                for val, fp, ln, body in all_rows:
                    if fuzz.ratio(function_name, val) >= 80:
                        rows.append((val, fp, ln, body))

        # Fuzzy match against all functions when requested and no file scoped
        if fuzzy and not file_path and _FUZZ_OK:
            all_rows = self._run_cqsearch("-s", self.db.name, "-p", "2", "-t", "*", "-u")
            for val, fp, ln, body in all_rows:
                if fuzz.ratio(function_name, val) >= fuzzy_threshold:
                    rows.append((val, fp, ln, body))

        # Tree-sitter single-file fallback (no regex) when CQ yields no rows and a file_path is given (Java)
        if not rows and file_path is not None and self._lang_from_ext(file_path) == "java":
            parser = self._ts_parser("java")
            if parser:
                try:
                    from tree_sitter_languages import get_language as _get_lang  # type: ignore
                    src_path = self._normalize_b(file_path) or file_path
                    code = self._read_text(src_path)
                    if code:
                        tree = parser.parse(code.encode("utf-8"))
                        lang = _get_lang("java")
                        if function_name == "*":
                            q_code = """
(method_declaration) @method
(constructor_declaration) @ctor
"""
                        else:
                            q_code = """
(method_declaration name: (identifier) @mname) @method
(constructor_declaration name: (identifier) @cname) @ctor
"""
                        query = lang.query(q_code)
                        captures = query.captures(tree.root_node)
                        lines = code.splitlines()
                        bodies: List[FunctionBody] = []
                        for node, cap in captures:
                            # If a specific name is requested, check identifier text equality
                            if function_name != "*":
                                ident = None
                                for child in node.children:
                                    if child.type == "identifier":
                                        ident = child
                                        break
                                if ident is None:
                                    continue
                                if code[ident.start_byte:ident.end_byte] != function_name:
                                    continue
                            start_line = node.start_point[0] + 1
                            end_line = node.end_point[0] + 1
                            body = "\n".join(lines[start_line - 1 : end_line])
                            bodies.append(FunctionBody(start_line, end_line, body))
                        if bodies:
                            if function_name == "*" and line_number is not None:
                                bodies = [b for b in bodies if b.start_line <= line_number <= b.end_line]
                            if bodies:
                                return [Function(name=function_name if function_name != "*" else "", file_path=src_path, bodies=tuple(bodies))]
                except Exception:
                    pass

        # Log raw CQ matches (symbol, file, line)
        try:
            import logging as _lg
            _lg.getLogger(__name__).info(
                "[CQ] get_functions raw matches for %s: %s",
                function_name,
                [(val, str(self._rebase(fp)), ln) for (val, fp, ln, _b) in rows][:20],
            )
        except Exception:
            pass

        # Group by file and unique function names
        grouped: dict[Path, List[str]] = {}
        for val, fp, _ln, _ in rows:
            fp2 = self._rebase(fp)
            grouped.setdefault(fp2, [])
            if val not in grouped[fp2]:
                grouped[fp2].append(val)

        results: List[Function] = []
        for fp, names in grouped.items():
            for name in names:
                lang = self._lang_from_ext(fp)
                bodies: List[FunctionBody] = []
                if lang == "java":
                    bodies = self._extract_java_function(fp, name)
                if not bodies:
                    continue
                if line_number is not None:
                    bodies = [b for b in bodies if b.start_line <= line_number <= b.end_line]
                    if not bodies:
                        continue
                results.append(Function(name=name, file_path=fp, bodies=tuple(bodies)))
        try:
            import logging as _lg
            _lg.getLogger(__name__).info(
                "[CQ] get_functions parsed results for %s: %s",
                function_name,
                [(f.name, str(f.file_path), [(b.start_line, b.end_line) for b in f.bodies]) for f in results][:10],
            )
        except Exception:
            pass
        return results

    def get_types(
        self,
        type_name: str,
        file_path: Path | None = None,
        function_name: str | None = None,
        fuzzy: bool | None = False,
        fuzzy_threshold: int = 80,
    ) -> List[TypeDefinition]:
        # Ensure DB is valid/initialized
        self._ensure_db()
        rows: List[Tuple[str, Path, int, str]] = []
        for flag in ("1", "3"):
            args = ["-s", self.db.name, "-p", flag, "-t", type_name, "-e", "-u"]
            bpath = self._normalize_b(file_path)
            if bpath:
                args += ["-b", str(bpath)]
            rows.extend(self._run_cqsearch(*args))
        # If no results when constrained by file, retry without -b and allow fuzzy
        if not rows and file_path is not None:
            for flag in ("1", "3"):
                args = ["-s", self.db.name, "-p", flag, "-t", type_name, "-e", "-u"]
                rows.extend(self._run_cqsearch(*args))
            if not rows and _FUZZ_OK:
                all_rows = self._run_cqsearch("-s", self.db.name, "-p", "1", "-t", "*", "-u")
                for val, fp, ln, body in all_rows:
                    if fuzz.ratio(type_name, val) >= 80:
                        rows.append((val, fp, ln, body))
        if fuzzy and not file_path and _FUZZ_OK:
            all_rows = self._run_cqsearch("-s", self.db.name, "-p", "1", "-t", "*", "-u")
            for val, fp, ln, body in all_rows:
                if fuzz.ratio(type_name, val) >= fuzzy_threshold:
                    rows.append((val, fp, ln, body))

        # Unique by (file, value)
        seen = set()
        results: List[TypeDefinition] = []
        try:
            import logging as _lg
            _lg.getLogger(__name__).info(
                "[CQ] get_types raw matches for %s: %s",
                type_name,
                [(val, str(self._rebase(fp)), ln) for (val, fp, ln, _b) in rows][:20],
            )
        except Exception:
            pass
        for val, fp, _ln, _ in rows:
            fp2 = self._rebase(fp)
            key = (fp2, val)
            if key in seen:
                continue
            seen.add(key)
            if self._lang_from_ext(fp2) == "java":
                td = self._extract_java_type(fp2, val)
                if not td:
                    continue
                results.append(td)
        # Optionally scope to a function range if provided
        if function_name and results and (file_path and file_path.exists()):
            funcs = self.get_functions(function_name, file_path=file_path)
            if funcs:
                fb_ranges = [(b.start_line, b.end_line) for b in funcs[0].bodies]
                results = [td for td in results if any(lo <= td.definition_line <= hi for lo, hi in fb_ranges)]
        try:
            import logging as _lg
            _lg.getLogger(__name__).info(
                "[CQ] get_types parsed results for %s: %s",
                type_name,
                [(t.name, str(t.file_path), t.definition_line) for t in results][:10],
            )
        except Exception:
            pass
        return results

    def _java_imports_for_file(self, p: Path) -> List[str]:
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return []
        imports: List[str] = []
        for line in lines:
            m = re.match(r"\s*import\s+([A-Za-z0-9_\.\*]+);", line)
            if m:
                imports.append(m.group(1))
        return imports

    def _filter_callees_java(self, caller: Function, callees: List[Function]) -> List[Function]:
        imports = self._java_imports_for_file(caller.file_path)
        if not imports:
            return callees
        # Very light heuristic: if an import ends with the callee class name (if any), keep it; otherwise keep all
        # We lack full qualification, so don't over-filter.
        return callees

    def get_callers(
        self,
        function: Function | str,
        file_path: Path | None = None,
    ) -> List[Function]:
        # Ensure DB is valid/initialized
        self._ensure_db()
        if isinstance(function, Function):
            name = function.name
            file_path = function.file_path
        else:
            name = function
        rows = self._run_cqsearch("-s", self.db.name, "-p", "6", "-t", name, "-e", "-u")
        results: List[Function] = []
        for val, fp, ln, _ in rows:
            fp2 = self._rebase(fp)
            funcs = self.get_functions(val, file_path=fp2, line_number=ln)
            results.extend(funcs)
        if results:
            return results
        # Tree-sitter current-file fallback (Java): find method_invocations of `name` and map to enclosing function
        if file_path is not None and self._lang_from_ext(file_path) == "java":
            parser = self._ts_parser("java")
            if parser:
                try:
                    from tree_sitter_languages import get_language as _get_lang  # type: ignore
                    src_path = self._normalize_b(file_path) or file_path
                    code = self._read_text(src_path)
                    if not code:
                        return []
                    lang = _get_lang("java")
                    tree = parser.parse(code.encode("utf-8"))
                    # Collect functions in file
                    q_funcs = """
(method_declaration) @method
(constructor_declaration) @ctor
"""
                    func_caps = lang.query(q_funcs).captures(tree.root_node)
                    lines = code.splitlines()
                    file_funcs: List[Function] = []
                    for node, cap in func_caps:
                        start_line = node.start_point[0] + 1
                        end_line = node.end_point[0] + 1
                        body = "\n".join(lines[start_line - 1 : end_line])
                        file_funcs.append(Function(name="", file_path=src_path, bodies=(FunctionBody(start_line, end_line, body),)))
                    if not file_funcs:
                        return []
                    # Find method_invocations for target name
                    q_calls = """
(method_invocation name: (identifier) @mname) @call
"""
                    call_caps = lang.query(q_calls).captures(tree.root_node)
                    # Build set of call lines whose identifier text equals `name`
                    call_lines: List[int] = []
                    for node, cap in call_caps:
                        # Locate identifier child text
                        ident_text = None
                        for child in node.children:
                            if child.type == "identifier":
                                ident_text = code[child.start_byte:child.end_byte]
                                break
                        if ident_text == name:
                            call_lines.append(node.start_point[0] + 1)
                    if not call_lines:
                        return []
                    # Map call lines to enclosing functions
                    seen_ranges: set[tuple[int, int]] = set()
                    out: List[Function] = []
                    for cl in call_lines:
                        for f in file_funcs:
                            b = f.bodies[0]
                            if b.start_line <= cl <= b.end_line:
                                key = (b.start_line, b.end_line)
                                if key not in seen_ranges:
                                    seen_ranges.add(key)
                                    out.append(f)
                                break
                    return out
                except Exception:
                    return []
        return results

    def get_callees(
        self,
        function: Function | str,
        file_path: Path | None = None,
        line_number: int | None = None,
    ) -> List[Function]:
        # Ensure DB is valid/initialized
        self._ensure_db()
        # Resolve the caller function(s) to establish precise file and line ranges
        caller_functions: List[Function] = []
        if isinstance(function, Function):
            caller_name = function.name
            file_path = function.file_path
            line_number = None
            caller_functions.append(function)
        else:
            caller_name = function
            # When a string is provided, identify the exact function bodies to filter by
            caller_functions.extend(self.get_functions(caller_name, file_path=file_path, line_number=line_number))

        # Query call sites for potential callees
        args = ["-s", self.db.name, "-p", "7", "-t", caller_name, "-e", "-u"]
        if file_path:
            args += ["-b", str(file_path)]
        rows = self._run_cqsearch(*args)

        # Build a filter of file -> list of (start, end) body ranges for the caller(s)
        caller_ranges_by_file: dict[Path, List[tuple[int, int]]] = {}
        for cf in caller_functions:
            ranges = [(b.start_line, b.end_line) for b in cf.bodies]
            if not ranges:
                continue
            caller_ranges_by_file.setdefault(cf.file_path, [])
            caller_ranges_by_file[cf.file_path].extend(ranges)

        # If we failed to locate caller function(s), fall back to using all rows (Buttercup behavior)
        if not caller_ranges_by_file:
            filtered_rows = [(val, self._rebase(fp), ln, body) for (val, fp, ln, body) in rows]
        else:
            # Keep only call sites that occur within the caller's file and body ranges
            filtered_rows: List[tuple[str, Path, int, str]] = []
            for val, fp, ln, body in rows:
                rebased = self._rebase(fp)
                if rebased in caller_ranges_by_file:
                    ranges = caller_ranges_by_file[rebased]
                    if any(lo <= ln <= hi for (lo, hi) in ranges):
                        filtered_rows.append((val, rebased, ln, body))

        # Resolve callee definitions from the filtered call sites
        callee_functions: List[Function] = []
        for val, _fp, _ln, _ in filtered_rows:
            callee_functions.extend(self.get_functions(val))

        # Tree-sitter single-file fallback for Java when CQ returns no callees:
        # Parse the caller's body in the given file and extract method_invocations,
        # then resolve each identifier to a function definition (scoped to the same file first).
        if not callee_functions and file_path is not None and self._lang_from_ext(file_path) == "java":
            parser = self._ts_parser("java")
            if parser:
                try:
                    from tree_sitter_languages import get_language as _get_lang  # type: ignore
                    src_path = self._normalize_b(file_path) or file_path
                    code = self._read_text(src_path)
                    if code:
                        lang = _get_lang("java")
                        tree = parser.parse(code.encode("utf-8"))
                        lines = code.splitlines()
                        # Determine caller range
                        target_lo: int | None = None
                        target_hi: int | None = None
                        if caller_functions:
                            b = caller_functions[0].bodies[0]
                            target_lo, target_hi = b.start_line, b.end_line
                        elif line_number is not None:
                            # Find enclosing method at line_number
                            q_funcs = """
(method_declaration) @method
(constructor_declaration) @ctor
"""
                            func_caps = lang.query(q_funcs).captures(tree.root_node)
                            for node, _ in func_caps:
                                lo = node.start_point[0] + 1
                                hi = node.end_point[0] + 1
                                if lo <= line_number <= hi:
                                    target_lo, target_hi = lo, hi
                                    break
                        if target_lo is not None and target_hi is not None:
                            # Collect method_invocations inside caller body range
                            q_calls = """
(method_invocation name: (identifier) @mname) @call
"""
                            call_caps = lang.query(q_calls).captures(tree.root_node)
                            called_names: set[str] = set()
                            for node, cap in call_caps:
                                cl = node.start_point[0] + 1
                                if not (target_lo <= cl <= target_hi):
                                    continue
                                ident_text = None
                                for child in node.children:
                                    if child.type == "identifier":
                                        ident_text = code[child.start_byte:child.end_byte]
                                        break
                                if ident_text:
                                    called_names.add(ident_text)
                            # Resolve each called name to definitions, preferring same-file
                            for n in sorted(called_names):
                                defs_same_file = self.get_functions(n, file_path=src_path)
                                if defs_same_file:
                                    callee_functions.extend(defs_same_file)
                                else:
                                    callee_functions.extend(self.get_functions(n))
                except Exception:
                    pass

        # Optional Java-specific filtering using imports resolver heuristic
        if caller_functions and self._lang_from_ext(caller_functions[0].file_path) == "java":
            callee_functions = self._filter_callees_java(caller_functions[0], callee_functions)

        # Deduplicate by (name, file_path, ranges)
        unique: dict[tuple[str, Path, tuple[tuple[int, int], ...]], Function] = {}
        for f in callee_functions:
            key = (
                f.name,
                f.file_path,
                tuple((b.start_line, b.end_line) for b in f.bodies),
            )
            if key not in unique:
                unique[key] = f
        return list(unique.values())


@lru_cache(maxsize=64)
def get_codequery(project_root: str | None) -> LocalCodeQuery | None:
    if not project_root:
        return None
    root = Path(project_root)
    try:
        return LocalCodeQuery(root)
    except Exception:
        return None


