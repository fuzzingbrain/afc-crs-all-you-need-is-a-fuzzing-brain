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
        if self.db.exists() and self.cscope_out.exists() and self.tags.exists():
            logging.getLogger(__name__).info("[CQ] Using existing CodeQuery DB at %s", self.db_dir)
            return
        logging.getLogger(__name__).info("[CQ] Building CodeQuery DB at %s", self.db_dir)
        with self.cscope_files.open("w", encoding="utf-8") as f:
            for g in ("**/*.java", "**/*.c", "**/*.cpp", "**/*.cc", "**/*.h", "**/*.hpp"):
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
        if ext in (".c", ".h"):
            return "c"
        if ext in (".cc", ".cpp", ".hpp", ".hh", ".cxx", ".hxx"):
            return "cpp"
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
        return results

    def get_callees(
        self,
        function: Function | str,
        file_path: Path | None = None,
        line_number: int | None = None,
    ) -> List[Function]:
        if isinstance(function, Function):
            name = function.name
            file_path = function.file_path
        else:
            name = function
        args = ["-s", self.db.name, "-p", "7", "-t", name, "-e", "-u"]
        if file_path:
            args += ["-b", str(file_path)]
        rows = self._run_cqsearch(*args)
        # Convert call sites to function definitions
        callees: List[Function] = []
        for val, fp, ln, _ in rows:
            funcs = self.get_functions(val)
            callees.extend(funcs)
        # Optional filtering for Java using imports resolver heuristic
        if isinstance(function, Function) and self._lang_from_ext(function.file_path) == "java":
            callees = self._filter_callees_java(function, callees)
        return callees


@lru_cache(maxsize=64)
def get_codequery(project_root: str | None) -> LocalCodeQuery | None:
    if not project_root:
        return None
    root = Path(project_root)
    try:
        return LocalCodeQuery(root)
    except Exception:
        return None


