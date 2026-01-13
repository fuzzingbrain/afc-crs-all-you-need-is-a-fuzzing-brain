from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Annotated, Iterable, List, Optional
import shutil
import subprocess

from langchain_core.tools import tool
from langchain_core.messages import ToolMessage  # type: ignore
from langgraph.prebuilt import InjectedState
from langchain_core.tools.base import InjectedToolCallId  # type: ignore
from langgraph.types import Command

from multi_agent.state import CodeSnippetKey, ContextCodeSnippet
from multi_agent.overlay import dump_overlay_unified_diff, undo_last_overlay_patch
from multi_agent.overlay import undo_n_overlay_patches, undo_all_overlay_patches

logger = logging.getLogger(__name__)

MAX_OUTPUT_LENGTH = 10000
MAX_TRACKED_LINES = 500
MAX_GREP_TOTAL_MATCHES = 5


def _truncate(s: str, max_len: int = MAX_OUTPUT_LENGTH) -> str:
    if len(s) <= max_len:
        return s
    head = max_len // 2
    tail = max_len - head
    return s[:head] + "\n... [truncated] ...\n" + s[-tail:]


def _wrap_command_output(command: str | List[str], stdout: str, stderr: str = "", returncode: int = 0) -> str:
    if isinstance(command, list):
        command = " ".join(command)
    return (
        "<command_output>\n"
        f"<command>{command}</command>\n"
        f"<returncode>{returncode}</returncode>\n"
        "<stdout>\n"
        f"{_truncate(stdout)}\n"
        "</stdout>\n"
        "<stderr>\n"
        f"{_truncate(stderr)}\n"
        "</stderr>\n"
        "</command_output>"
    )


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _read_lines(path: Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []

def _already_tracked_function(state: Any, function_name: str, file_path: str | None) -> bool:
    try:
        existing = list(getattr(state, "code_snippets", []) or [])
    except Exception:
        return False
    for s in existing:
        try:
            fp = getattr(getattr(s, "key", None), "file_path", None)
            if file_path and fp and Path(fp).as_posix() != Path(file_path).as_posix():
                continue
            code_text = getattr(s, "code", "") or ""
            desc_text = getattr(s, "description", "") or ""
            if (function_name in code_text and "(" in code_text) or (function_name in desc_text):
                return True
        except Exception:
            continue
    return False


def _merge_snippets(state: Any, new_snippets: list[ContextCodeSnippet]) -> list[ContextCodeSnippet]:
    """
    Merge newly produced snippets into the existing state, avoiding overwrite.
    This is defensive against state backends that treat list updates as replacement.
    """
    try:
        existing = list(getattr(state, "code_snippets", []) or [])
    except Exception:
        existing = []
    # Simple de-duplication based on full snippet equality
    for sn in new_snippets:
        if sn not in existing:
            existing.append(sn)
    return existing

def _rglob_many(root: Path, globs: Iterable[str]) -> Iterable[Path]:
    for g in globs:
        yield from root.rglob(g)


def _lang_from_ext(p: Path) -> Optional[str]:
    ext = p.suffix.lower()
    if ext == ".java":
        return "java"
    if ext in [".c", ".h"]:
        return "c"
    if ext in [".cc", ".cpp", ".hpp", ".hh", ".cxx", ".hxx"]:
        return "cpp"
    return None


def _expand_java_range_to_enclosing_entity(file_path: Path, start_line: int, end_line: int) -> tuple[int, int] | None:
    """
    Expand a given [start_line, end_line] to the enclosing Java method/ctor/type if inside one.
    Uses tree-sitter when available; falls back to simple brace scanning.
    Returns (new_start, new_end) or None if no better expansion is found.
    """
    try:
        if _lang_from_ext(file_path) != "java":
            return None
        src_text = _read_text(file_path)
        if not src_text:
            return None
        lines = src_text.splitlines()
        # Tree-sitter path
        if _TS_OK:
            try:
                parser = _ts_parser("java")
            except Exception:
                parser = None
            if parser:
                tree = parser.parse(src_text.encode("utf-8"))
                # Query for method, ctor, and type nodes covering the span
                lang = get_language("java")  # type: ignore[name-defined]
                q = lang.query("""
                (
                  (method_declaration) @m
                )
                (
                  (constructor_declaration) @c
                )
                (
                  (class_declaration) @t
                )
                (
                  (interface_declaration) @i
                )
                (
                  (enum_declaration) @e
                )
                """)
                candidates = []
                for node, cap in q.captures(tree.root_node):
                    s = node.start_point[0] + 1
                    e = node.end_point[0] + 1
                    # If our original range intersects this node, consider it
                    if not (end_line < s or start_line > e):
                        candidates.append((s, e))
                if candidates:
                    # Prefer the smallest enclosing range that still contains our span
                    candidates.sort(key=lambda se: (se[1] - se[0], se[0]))
                    for s, e in candidates:
                        if s <= start_line and end_line <= e:
                            return (s, e)
                    # Otherwise, return the most overlapping one
                    return candidates[0]
        # Fallback: heuristic brace expansion from nearest opening brace above
        # Find a plausible start by searching upwards for a line with '{' that looks like a signature or type
        sig_start = start_line
        for i in range(start_line - 1, 0, -1):
            text = lines[i - 1].strip()
            if "{" in text:
                sig_start = i
                break
            # Stop if we hit an obvious boundary
            if text.endswith(";"):
                break
        # Now expand braces from the first '{' after sig_start
        open_seen = 0
        found_start = None
        found_end = None
        for i in range(sig_start - 1, len(lines)):
            line = lines[i]
            if found_start is None and "{" in line:
                found_start = i + 1
            if found_start is not None:
                open_seen += line.count("{")
                open_seen -= line.count("}")
                if open_seen == 0 and "}" in line:
                    found_end = i + 1
                    break
        if found_start and found_end and (found_start <= start_line <= found_end):
            return (found_start, found_end)
        return None
    except Exception:
        return None


try:
    from tree_sitter import Parser  # type: ignore
    from tree_sitter_languages import get_language  # type: ignore

    def _ts_parser(lang_name: str) -> Optional[Parser]:
        try:
            lang = get_language(lang_name)
            parser = Parser()
            parser.set_language(lang)
            return parser
        except Exception:
            return None

    def _query_java_entities(tree, name: str):
        lang = get_language("java")
        q_code = rf"""
; methods
(
 (method_declaration
    name: (identifier) @mname
 ) @method
 (#eq? @mname "{name}")
)
; constructors
(
 (constructor_declaration
    name: (identifier) @cname
 ) @ctor
 (#eq? @cname "{name}")
)
; types
(
 (class_declaration
    name: (identifier) @tname
 ) @class
 (#eq? @tname "{name}")
)
(
 (interface_declaration
    name: (identifier) @iname
 ) @iface
 (#eq? @iname "{name}")
)
(
 (enum_declaration
    name: (identifier) @ename
 ) @enum
 (#eq? @ename "{name}")
)
; method invocations (references)
(
 (method_invocation
    name: (identifier) @callname
 ) @call
 (#eq? @callname "{name}")
)
"""
        query = lang.query(q_code)
        captures = query.captures(tree.root_node)
        methods, ctors, types, calls = [], [], [], []
        for node, cap in captures:
            if cap == "method":
                methods.append(node)
            elif cap == "ctor":
                ctors.append(node)
            elif cap in ("class", "iface", "enum"):
                types.append(node)
            elif cap == "call":
                calls.append(node)
        return methods, ctors, types, calls

    def _extract_signature_and_body_java(src: str, node):
        lines = src.splitlines()
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        node_text = "\n".join(lines[start_line - 1 : end_line])
        brace_idx = node_text.find("{")
        if brace_idx != -1:
            signature_text = node_text[:brace_idx].rstrip()
            body_text = node_text[brace_idx:].rstrip()
        else:
            signature_text = node_text.rstrip()
            body_text = ""
        return signature_text, body_text, (start_line, end_line)

    _TS_OK = True
except Exception:
    _TS_OK = False
    Parser = None  # type: ignore
    get_language = None  # type: ignore


def _build_snippet_from_java(p: Path, name: str, kind: Optional[str], part: str) -> Optional[ContextCodeSnippet]:
    src = _read_text(p)
    if not src or not name:
        return None

    sig = ""
    body = ""
    start_line = 1
    end_line = max(1, len(src.splitlines()))
    ref_lines: List[str] = []

    if _TS_OK:
        try:
            parser = _ts_parser("java")
        except Exception:
            parser = None
        if parser:
            src_bytes = src.encode("utf-8")
            tree = parser.parse(src_bytes)
            methods, ctors, types, calls = _query_java_entities(tree, name)
            target_node = None
            if kind == "function":
                target_node = methods[0] if methods else (ctors[0] if ctors else None)
            elif kind == "type":
                target_node = types[0] if types else None
            else:
                target_node = methods[0] if methods else (ctors[0] if ctors else (types[0] if types else None))
            if target_node is not None:
                sig, body, (start_line, end_line) = _extract_signature_and_body_java(src, target_node)
                ref_linenos = sorted({n.start_point[0] + 1 for n in calls})
                if ref_linenos:
                    lines = src.splitlines()
                    for ln in ref_linenos[:80]:
                        if 1 <= ln <= len(lines):
                            ref_lines.append(f"{ln}: {lines[ln - 1]}")

    if not sig and not body:
        # regex fallback for method body
        lines = src.splitlines()
        text = src
        m = re.search(rf"^[\t ]*(?:[\w<>\[\]\s]+\s+)?{re.escape(name)}\s*\(.*\)\s*{{", text, re.MULTILINE)
        if m:
            start_line = text[: m.start()].count("\n") + 1
            brace = 0
            started = False
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
            node_text = "\n".join(lines[start_line - 1 : end_line])
            brace_idx = node_text.find("{")
            if brace_idx != -1:
                sig = node_text[:brace_idx].rstrip()
                body = node_text[brace_idx:].rstrip()
            else:
                sig = node_text.rstrip()
                body = ""
            ref_lines = []
            for i, line in enumerate(lines, start=1):
                if re.search(rf"\b{re.escape(name)}\s*\(", line):
                    ref_lines.append(f"{i}: {line}")

    desc_kind = "Implementation" if kind == "function" else ("Definition" if kind == "type" else "Snippet")
    if part == "signature":
        code = sig.strip() or "\n".join(src.splitlines()[start_line - 1 : start_line + 5])
    elif part == "body":
        code = body.strip() or "\n".join(src.splitlines()[start_line - 1 : end_line])
    elif part == "references":
        code = ("// References to " + name + "\n" + "\n".join(ref_lines)) if ref_lines else "// No references found"
    elif part == "definition" and kind == "type":
        code = "\n".join(src.splitlines()[start_line - 1 : end_line])
    else:
        blocks: List[str] = []
        if sig.strip():
            blocks.append(sig.strip())
        if body.strip():
            blocks.append(body.strip())
        if ref_lines:
            blocks.append("// References:\n" + "\n".join(ref_lines))
        code = "\n\n".join(blocks) or "\n".join(src.splitlines()[start_line - 1 : end_line])

    return ContextCodeSnippet(
        key=CodeSnippetKey(file_path=str(p)),
        start_line=start_line,
        end_line=end_line,
        description=f"{desc_kind} of {name} in {p.as_posix()} ({part})",
        code=code,
        can_patch=True,
    )

def _collect_java_field_names(src: str) -> set[str]:
    if not _TS_OK:
        return set()
    try:
        parser = _ts_parser("java")
    except Exception:
        parser = None
    if not parser:
        return set()
    tree = parser.parse(src.encode("utf-8"))
    lang = get_language("java")  # type: ignore[name-defined]
    q_code = r"""
    (
      (field_declaration
        (variable_declarator
          name: (identifier) @fname
        )+
      ) @field
    )
    """
    try:
        q = lang.query(q_code)
        captures = q.captures(tree.root_node)
        names: set[str] = set()
        for node, cap in captures:
            if cap == "fname":
                names.add(src[node.start_byte:node.end_byte])
        return names
    except Exception:
        return set()

def _find_java_method_node(src: str, function_name: str):
    if not _TS_OK:
        return None
    try:
        parser = _ts_parser("java")
    except Exception:
        parser = None
    if not parser:
        return None
    tree = parser.parse(src.encode("utf-8"))
    lang = get_language("java")  # type: ignore[name-defined]
    q_code = rf"""
    (
      (method_declaration
        name: (identifier) @mname
      ) @method
      (#eq? @mname "{function_name}")
    )
    (
      (constructor_declaration
        name: (identifier) @cname
      ) @ctor
      (#eq? @cname "{function_name}")
    )
    """
    try:
        q = lang.query(q_code)
        captures = q.captures(tree.root_node)
        for node, cap in captures:
            if cap in ("method", "ctor"):
                return node
    except Exception:
        return None
    return None

def _collect_identifiers_in_node(src: str, node) -> list[tuple[str, int]]:
    if not _TS_OK or node is None:
        return []
    try:
        lang = get_language("java")  # type: ignore[name-defined]
        q = lang.query("(identifier) @id")
        captures = q.captures(node)
        res: list[tuple[str, int]] = []
        for id_node, _ in captures:
            try:
                name = src[id_node.start_byte:id_node.end_byte]
                line = id_node.start_point[0] + 1
                res.append((name, line))
            except Exception:
                continue
        return res
    except Exception:
        return []

def _build_field_snippet_java(p: Path, field_name: str) -> Optional[ContextCodeSnippet]:
    """
    Extract a Java field/constant declaration by name using tree-sitter when available, with regex fallback.
    Returns a patchable snippet containing the field declaration (and Javadoc/annotations if present).
    """
    src = _read_text(p)
    if not src or not field_name:
        return None

    lines = src.splitlines()
    start_line = 1
    end_line = 1

    # Prefer tree-sitter for precise node bounds
    if _TS_OK:
        try:
            parser = _ts_parser("java")
        except Exception:
            parser = None
        if parser:
            tree = parser.parse(src.encode("utf-8"))
            lang = get_language("java")  # type: ignore[name-defined]
            q_code = rf"""
            (
              (field_declaration
                (_)*
                (variable_declarator
                  name: (identifier) @fname
                ) @decl
              ) @field
              (#eq? @fname "{field_name}")
            )
            """
            try:
                q = lang.query(q_code)
                captures = q.captures(tree.root_node)
                field_node = None
                decl_node = None
                for node, cap in captures:
                    if cap == "field" and field_node is None:
                        field_node = node
                    elif cap == "decl" and decl_node is None:
                        decl_node = node
                if decl_node is not None:
                    # Start at the declarator line for minimal context
                    start_line = decl_node.start_point[0] + 1
                    # Find terminating semicolon from declarator forward
                    # Precompute line offsets to map line->index
                    running = 0
                    line_offsets = []
                    for ln in lines:
                        line_offsets.append(running)
                        running += len(ln) + 1
                    start_idx = line_offsets[max(0, start_line - 1)]
                    semi_idx = src.find(";", start_idx)
                    if semi_idx == -1:
                        end_line = (field_node.end_point[0] + 1) if field_node is not None else start_line
                    else:
                        end_line = src[: semi_idx + 1].count("\n") + 1
            except Exception:
                field_node = None

    # GREP-style fallback: find the first line with the symbol (prefer with '='), then extend to the next semicolon
    if start_line == end_line == 1:
        idx = -1
        for i, ln in enumerate(lines):
            if field_name in ln and "=" in ln:
                idx = i
                break
        if idx == -1:
            for i, ln in enumerate(lines):
                if field_name in ln:
                    idx = i
                    break
        if idx == -1:
            return None
        start_line = idx + 1
        end_line = start_line
        for j in range(idx, len(lines)):
            if ";" in lines[j]:
                end_line = j + 1
                break

    # Build snippet code (bounded)
    start_line = max(1, start_line)
    end_line = min(len(lines), max(start_line, end_line))
    code = "\n".join(lines[start_line - 1 : end_line])
    return ContextCodeSnippet(
        key=CodeSnippetKey(file_path=str(p)),
        start_line=start_line,
        end_line=end_line,
        description=f"Declaration of field {field_name} in {p.as_posix()}",
        code=code,
        can_patch=True,
    )


def _resolve_path(root: Optional[str], path: str | None) -> Optional[Path]:
    if not path:
        return None
    p = Path(path)
    if p.is_absolute():
        exists = p.exists()
        logger.info("[RANGE] _resolve_path abs path=%s exists=%s", p, exists)
        return p if exists else None
    if root:
        base = Path(root)
        cand = base / path
        if cand.exists():
            logger.info("[RANGE] _resolve_path base+path=%s", cand)
            return cand
        # Heuristic: many benchmarks store sources under a 'source' subdir
        cand2 = base / "source" / path
        if cand2.exists():
            logger.info("[RANGE] _resolve_path base/source+path=%s", cand2)
            return cand2
        # As a last resort, find file by suffix match
        target_name = p.as_posix()
        for f in base.rglob(p.name):
            try:
                if f.as_posix().endswith(target_name):
                    logger.info("[RANGE] _resolve_path suffix match=%s", f)
                    return f
            except Exception:
                continue
    return p if p.exists() else None


class _LocalCQ:
    """Lightweight CodeQuery wrapper using cscope/ctags/cqmakedb/cqsearch on local source tree.

    Builds the DB under `<root>/.cqdb` if tools are available. Methods mirror a subset of Buttercup's API.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.db_dir = root / ".cqdb"
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
            return
        # Write cscope.files
        with self.cscope_files.open("w", encoding="utf-8") as f:
            for g in ("**/*.java", "**/*.c", "**/*.cpp", "**/*.cc", "**/*.h", "**/*.hpp"):
                for fp in self.root.rglob(g):
                    if fp.is_file():
                        f.write(str(fp.resolve()) + "\n")
        # Build cscope
        subprocess.run(["cscope", "-bkq"], cwd=self.db_dir, check=False, capture_output=True)
        # Build tags
        subprocess.run(["ctags", "--fields=+i", "-n", "-L", str(self.cscope_files.name)], cwd=self.db_dir, check=False, capture_output=True)
        # Build codequery db
        subprocess.run(["cqmakedb", "-s", self.db.name, "-c", self.cscope_out.name, "-t", self.tags.name, "-p"], cwd=self.db_dir, check=False, capture_output=True)

    def _run_cqsearch(self, *args: str) -> List[tuple[str, Path, int, str]]:
        try:
            proc = subprocess.run(["cqsearch", *args], cwd=self.db_dir, check=True, text=True, capture_output=True)
            out = proc.stdout
        except subprocess.CalledProcessError:
            return []
        res: List[tuple[str, Path, int, str]] = []
        for line in out.splitlines():
            try:
                value, file_line, body = line.split("\t", 2)
                file_str, ln = file_line.split(":", 1)
                res.append((value, Path(file_str), int(ln), body))
            except Exception:
                continue
        return res

    def get_functions(self, name: str) -> List[tuple[str, Path, int]]:
        results: List[tuple[str, Path, int]] = []
        for flag in ("1", "2"):
            rows = self._run_cqsearch("-s", self.db.name, "-p", flag, "-t", name, "-e", "-u")
            for val, fp, ln, _ in rows:
                results.append((val, self._rebase(fp), ln))
        # De-dup by (file,value)
        seen = set()
        uniq: List[tuple[str, Path, int]] = []
        for val, fp, ln in results:
            key = (val, fp)
            if key in seen:
                continue
            seen.add(key)
            uniq.append((val, fp, ln))
        return uniq

    def get_types(self, name: str) -> List[tuple[str, Path, int]]:
        results: List[tuple[str, Path, int]] = []
        for flag in ("1", "3"):
            rows = self._run_cqsearch("-s", self.db.name, "-p", flag, "-t", name, "-e", "-u")
            for val, fp, ln, _ in rows:
                results.append((val, self._rebase(fp), ln))
        seen = set()
        uniq: List[tuple[str, Path, int]] = []
        for val, fp, ln in results:
            key = (val, fp)
            if key in seen:
                continue
            seen.add(key)
            uniq.append((val, fp, ln))
        return uniq

    def get_callers(self, name: str) -> List[tuple[str, Path, int]]:
        rows = self._run_cqsearch("-s", self.db.name, "-p", "6", "-t", name, "-e", "-u")
        return [(val, self._rebase(fp), ln) for val, fp, ln, _ in rows]

    def get_callees(self, name: str, file_path: Optional[Path] = None) -> List[tuple[str, Path, int]]:
        args = ["-s", self.db.name, "-p", "7", "-t", name, "-e", "-u"]
        if file_path:
            args += ["-b", str(file_path)]
        rows = self._run_cqsearch(*args)
        return [(val, self._rebase(fp), ln) for val, fp, ln, _ in rows]

    def _rebase(self, p: Path) -> Path:
        # Our files are absolute real files already; ensure path exists else join relative to root
        if p.exists():
            return p
        cand = self.root / p
        return cand if cand.exists() else p


from shared_tools.codequery import get_codequery, Function as CQFunction, TypeDefinition as CQType

# Replace snippet builders when CQ returns structures

def _snippets_from_cq_functions(funcs: List[CQFunction]) -> List[ContextCodeSnippet]:
    snippets: List[ContextCodeSnippet] = []
    for f in funcs:
        for b in f.bodies:
            snippets.append(
                ContextCodeSnippet(
                    key=CodeSnippetKey(file_path=str(f.file_path)),
                    start_line=b.start_line,
                    end_line=b.end_line,
                    description=f"Implementation of function {f.name} in {f.file_path.as_posix()}",
                    code=b.body,
                    can_patch=True,
                )
            )
    return snippets


def _snippets_from_cq_types(types: List[CQType]) -> List[ContextCodeSnippet]:
    snippets: List[ContextCodeSnippet] = []
    for t in types:
        end_line = t.definition_line + len(t.definition.splitlines())
        # Derive a one-line signature preview for description/context
        signature = ""
        try:
            first_line = (t.definition.splitlines() or [""])[0].strip()
            m = re.search(r"\b(class|interface|enum)\b.*", first_line)
            signature = m.group(0) if m else first_line
        except Exception:
            signature = ""
        snippets.append(
            ContextCodeSnippet(
                key=CodeSnippetKey(file_path=str(t.file_path)),
                start_line=t.definition_line,
                end_line=end_line,
                description=f"Definition of type {t.name}: {signature}" if signature else f"Definition of type {t.name}",
                code=t.definition,
                code_context=signature or None,
                can_patch=True,
            )
        )
    return snippets


def _get_local_cq(root: Optional[str]):
    return get_codequery(root)


@tool
def get_symbol(
    symbol_name: str,
    file_path: str | None,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """
    Get a field/constant declaration by name and track it as a snippet (Java only for now).
    Prefer passing file_path if known; otherwise the source tree will be searched heuristically.
    """
    try:
        root = getattr(state, "project_root", None) or getattr(state, "source_dir", None)
        p = _resolve_path(root, file_path) if file_path else None
        # Heuristic search if path is unknown
        if not p:
            src_dir = Path(getattr(state, "source_dir", root or "."))
            for cand in _rglob_many(src_dir, ("**/*.java",)):
                try:
                    if re.search(rf"\b{re.escape(symbol_name)}\b", _read_text(cand)):
                        p = cand
                        break
                except Exception:
                    continue
        if not p or not p.exists():
            msg = f"Symbol {symbol_name} not found in path {file_path or '(search)'}"
            return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})

        if _lang_from_ext(p) != "java":
            msg = f"get_symbol currently supports Java only; {p} is not a Java file"
            return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})

        snip = _build_field_snippet_java(p, symbol_name)
        if not snip:
            msg = f"Field/constant {symbol_name} not found in {p}"
            return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})

        # Validate patchability against source_dir
        try:
            src = getattr(state, "source_dir", None)
            if src:
                p2 = Path(snip.key.file_path or "")
                snip.can_patch = (p2.exists() and p2.is_file() and str(p2.resolve()).startswith(str(Path(src).resolve())) and _lang_from_ext(p2) is not None)
            else:
                snip.can_patch = False
        except Exception:
            snip.can_patch = False

        msg = f"Found symbol {symbol_name} in {p}"
        # Return snippet without ending the ReAct turn; append to any existing snippets
        merged = _merge_snippets(state, [snip])
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)], "code_snippets": merged})
    except Exception as e:
        return Command(update={"messages": [ToolMessage(content=f"Error: {e}", tool_call_id=tool_call_id)]})

@tool
def ls(
    file_path: str,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """List files in a directory relative to project root (or absolute path).

    Notes for the LLM:
    - If you pass a high-level path like 'source' and see only subdirectories,
      you should usually drill down into likely source roots such as:
      'source/src/main/java', 'source/src/java', or 'source/src'.
    - This tool now lists both subdirectories and Java files to help you decide
      where to look next.
    """
    root = getattr(state, "project_root", None) or getattr(state, "source_dir", None)
    path = _resolve_path(root, file_path) or Path(file_path)
    try:
        if not path.exists():
            msg = _wrap_command_output(["ls", "-la", str(path)], "", f"path does not exist: {path}", returncode=1)
            return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})

        if not path.is_dir():
            msg = _wrap_command_output(["ls", "-la", str(path)], "", f"not a directory: {path}", returncode=1)
            return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})

        entries = sorted(path.iterdir(), key=lambda x: x.name)
        dir_entries = [e.name for e in entries if e.is_dir()]
        java_entries = [e.name for e in entries if e.is_file() and e.suffix.lower() == ".java"]

        lines: list[str] = []
        if dir_entries:
            lines.append("# directories")
            lines.extend(f"[dir] {name}" for name in dir_entries)
        if java_entries:
            lines.append("# java files")
            lines.extend(f"- {name}" for name in java_entries)
        if not lines:
            lines.append("<empty>")

        out = "\n".join(lines)
        msg = _wrap_command_output(["ls", "-la", str(path)], out)
        # Do NOT attach snippets for ls; it's informational only
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    except Exception as e:
        msg = _wrap_command_output(["ls", "-la", str(path)], "", str(e), returncode=1)
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})


@tool
def editor_list_edits(
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """List accumulated overlay edits (as a unified diff)."""
    try:
        diff = dump_overlay_unified_diff(getattr(state, "source_dir", None))
        if not (diff and diff.strip()):
            msg = _wrap_command_output("editor_list_edits", "", "no edits remain", returncode=1)
            return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
        # Attach diff as a non-patchable snippet for visibility
        snippet = ContextCodeSnippet(
            key=CodeSnippetKey(file_path=str(Path(getattr(state, "source_dir", "") or ".") / ".overlay.diff")),
            start_line=1,
            end_line=max(1, len(diff.splitlines())),
            code=diff,
            description="Accumulated overlay edits (unified diff)",
            can_patch=False,
        )
        msg = _wrap_command_output("editor_list_edits", diff, "")
        merged = _merge_snippets(state, [snippet])
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)], "code_snippets": merged})
    except Exception as e:
        msg = _wrap_command_output("editor_list_edits", "", str(e), returncode=1)
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})


@tool
def editor_undo_last_patch(
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """Undo the last applied overlay patch."""
    try:
        res = undo_last_overlay_patch(getattr(state, "source_dir", None))
        # shared_tools.core.Result Ok(int) | Err(error)
        try:
            from shared_tools.core import Ok  # type: ignore
            if isinstance(res, Ok):
                msg = _wrap_command_output("editor_undo_last_patch", f"{res.value}", "")
                return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)], "rollback_done": True})
        except Exception:
            pass
        msg = _wrap_command_output("editor_undo_last_patch", str(res), "")
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)], "rollback_done": True})
    except Exception as e:
        msg = _wrap_command_output("editor_undo_last_patch", "", str(e), returncode=1)
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})


@tool
def editor_undo_n(
    count: int,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """Undo the last N overlay patches (LIFO)."""
    try:
        n = max(1, int(count))
        res = undo_n_overlay_patches(getattr(state, "source_dir", None), n)
        try:
            from shared_tools.core import Ok  # type: ignore
            if isinstance(res, Ok):
                msg = _wrap_command_output("editor_undo_n", f"undone={res.value}", "")
                return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)], "rollback_done": True})
        except Exception:
            pass
        msg = _wrap_command_output("editor_undo_n", str(res), "")
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)], "rollback_done": True})
    except Exception as e:
        msg = _wrap_command_output("editor_undo_n", "", str(e), returncode=1)
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})


@tool
def editor_undo_all(
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """Undo all overlay patches (clear overlay edits)."""
    try:
        res = undo_all_overlay_patches(getattr(state, "source_dir", None))
        try:
            from shared_tools.core import Ok  # type: ignore
            if isinstance(res, Ok):
                msg = _wrap_command_output("editor_undo_all", f"undone_total={res.value}", "")
                return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)], "rollback_done": True})
        except Exception:
            pass
        msg = _wrap_command_output("editor_undo_all", str(res), "")
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)], "rollback_done": True})
    except Exception as e:
        msg = _wrap_command_output("editor_undo_all", "", str(e), returncode=1)
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})

@tool
def grep(
    pattern: str,
    file_path: str | None,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """Search for a regex pattern; if file_path is None, search entire source tree."""
    root = getattr(state, "source_dir", None) or getattr(state, "project_root", None) or os.getcwd()
    matches: List[str] = []
    # Do NOT attach code snippets from grep; only provide file:line hits to inform follow-up requests
    try:
        if file_path:
            target = _resolve_path(root, file_path)
            files = [target] if target and target.exists() else []
        else:
            files = list(_rglob_many(Path(root), ("**/*.java", "**/*.c", "**/*.cpp", "**/*.cc", "**/*.h", "**/*.hpp")))
        kept = 0
        for fp in files:
            if not fp or not fp.exists() or fp.is_dir():
                continue
            lines = _read_lines(fp)
            for i, line in enumerate(lines, start=1):
                try:
                    if re.search(pattern, line):
                        if kept < MAX_GREP_TOTAL_MATCHES:
                            matches.append(f"{fp}:{i}")
                        kept += 1
                        if kept >= MAX_GREP_TOTAL_MATCHES:
                            break
                except re.error:
                    # treat as literal
                    if pattern in line:
                        if kept < MAX_GREP_TOTAL_MATCHES:
                            matches.append(f"{fp}:{i}")
                        kept += 1
                        if kept >= MAX_GREP_TOTAL_MATCHES:
                            break
            if kept >= MAX_GREP_TOTAL_MATCHES:
                break
        stdout = "\n".join(matches) if matches else ""
        rc = 0 if matches else 1
        msg = _wrap_command_output(["grep", "-nHrE", pattern, file_path or root], stdout, returncode=rc)
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    except Exception as e:
        msg = _wrap_command_output(["grep", "-nHrE", pattern, file_path or root], "", str(e), returncode=1)
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})


@tool
def cat(
    file_path: str,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """Read the entire file contents (avoid for large files)."""
    root = getattr(state, "project_root", None) or getattr(state, "source_dir", None)
    p = _resolve_path(root, file_path) or Path(file_path)
    text = _read_text(p)
    msg = _wrap_command_output(["cat", str(p)], text)
    # Informational only: do not attach code snippets
    return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})


@tool
def get_lines(
    file_path: str,
    start: int,
    end: int,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """Get a 1-indexed inclusive range of lines from a file, clamped to a small window, and track it."""
    root = getattr(state, "project_root", None) or getattr(state, "source_dir", None)
    p = _resolve_path(root, file_path) or Path(file_path)
    logger.info("[RANGE] get_lines root=%s file_path=%s resolved=%s exists=%s start=%d end=%d", root, file_path, p, p.exists(), start, end)
    lines = _read_lines(p)
    s_req = max(1, start)
    e_req = min(len(lines), max(end, start))
    # Clamp to a small window (±3 lines ≈ max 7 lines) starting at s_req
    s = s_req
    e = min(e_req, s_req + 6)
    out = "\n".join(lines[s - 1 : e])
    msg = _wrap_command_output(["get_lines", str(p), str(start), str(end)], out)
    snippet = ContextCodeSnippet(
        key=CodeSnippetKey(file_path=str(p)),
        start_line=s,
        end_line=e,
        code=out,
        description=f"Lines {s}-{e} in {str(p)}",
        can_patch=(p.exists() and p.is_file() and (getattr(state, "source_dir", None) and str(p).startswith(str(getattr(state, "source_dir")))) and _lang_from_ext(p) is not None),
    )
    merged = _merge_snippets(state, [snippet])
    return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)], "code_snippets": merged})

@tool
def get_field_refs(
    function_name: str,
    file_path: str,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """Within a Java function's span, find references to class fields/constants (tree-sitter-based) and track small context snippets."""
    root = getattr(state, "project_root", None) or getattr(state, "source_dir", None)
    p = _resolve_path(root, file_path) or Path(file_path)
    if not p.exists():
        msg = f"File not found: {p}"
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    if _lang_from_ext(p) != "java":
        msg = f"get_field_refs supports Java only; given {p}"
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    src = _read_text(p)
    if not src:
        msg = f"Empty or unreadable file: {p}"
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    if not _TS_OK:
        msg = "Tree-sitter not available; cannot resolve field references precisely"
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    method_node = _find_java_method_node(src, function_name)
    if method_node is None:
        msg = f"Method/constructor {function_name} not found in {p}"
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    field_names = _collect_java_field_names(src)
    if not field_names:
        msg = f"No class fields detected in {p}"
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    idents = _collect_identifiers_in_node(src, method_node)
    lines = src.splitlines()
    snippets: List[ContextCodeSnippet] = []
    seen_positions: set[tuple[str, int]] = set()
    for name, line_no in idents:
        if name not in field_names:
            continue
        key = (name, line_no)
        if key in seen_positions:
            continue
        seen_positions.add(key)
        s = max(1, line_no - 3)
        e = min(len(lines), line_no + 3)
        code = "\n".join(lines[s - 1 : e])
        snip = ContextCodeSnippet(
            key=CodeSnippetKey(file_path=str(p)),
            start_line=s,
            end_line=e,
            description=f"Use of field {name} inside {function_name} in {p.name}",
            code=code,
            can_patch=bool(getattr(state, "source_dir", None) and str(p).startswith(str(getattr(state, "source_dir")))),
        )
        snippets.append(snip)
    if not snippets:
        msg = f"No field/constant references found within {function_name} in {p}"
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
        summary = f"Found {len(snippets)} field/constant reference(s) inside {function_name} in {p}"
        merged = _merge_snippets(state, snippets)
        return Command(update={"messages": [ToolMessage(content=summary, tool_call_id=tool_call_id)], "code_snippets": merged})


def _get_function_snippets(function_name: str, file_path: str | None, state: Any) -> List[ContextCodeSnippet]:
    root = getattr(state, "project_root", None) or getattr(state, "source_dir", None)
    cq = _get_local_cq(root)
    if cq:
        try:
            from pathlib import Path as _P
            funcs = cq.get_functions(function_name, file_path=_P(file_path) if file_path else None)
            # Case 1: CodeQuery returns rich Function objects
            try:
                sn = _snippets_from_cq_functions(funcs)  # type: ignore[arg-type]
            except Exception:
                sn = []
            if sn:
                # Validate can_patch based on source_dir and extension
                src = getattr(state, "source_dir", None)
                if src:
                    srcp = Path(src).resolve()
                    for s in sn:
                        try:
                            p = Path(s.key.file_path or "")
                            s.can_patch = (p.exists() and p.is_file() and p.resolve().is_relative_to(srcp) and _lang_from_ext(p) is not None)  # type: ignore[attr-defined]
                        except Exception:
                            try:
                                # Python <3.9 fallback for is_relative_to
                                s.can_patch = (p.exists() and p.is_file() and str(p.resolve()).startswith(str(srcp)) and _lang_from_ext(p) is not None)
                            except Exception:
                                s.can_patch = False
                return sn
            # Case 2: CodeQuery returned tuple rows (value, path, line)
            tuple_snippets: List[ContextCodeSnippet] = []
            try:
                for row in funcs:  # type: ignore[assignment]
                    try:
                        val, fp, ln = row  # type: ignore[misc]
                    except Exception:
                        continue
                    p = Path(str(fp))
                    if _lang_from_ext(p) == "java":
                        snip = _build_snippet_from_java(p, function_name, "function", part="all")
                        if snip:
                            tuple_snippets.append(snip)
                if tuple_snippets:
                    return tuple_snippets
            except Exception:
                pass
        except Exception:
            pass
    # Fallback: heuristic search by name mention
    p = _resolve_path(root, file_path) if file_path else None
    if not p:
        src_dir = Path(getattr(state, "source_dir", root or "."))
        for cand in _rglob_many(src_dir, ("**/*.java",)):
            try:
                if re.search(rf"\b{re.escape(function_name)}\b", _read_text(cand)):
                    p = cand
                    break
            except Exception:
                continue
    if not p or not p.exists():
        return []
    if _lang_from_ext(p) == "java":
        snip = _build_snippet_from_java(p, function_name, "function", part="all")
        if snip:
            try:
                src = getattr(state, "source_dir", None)
                if src:
                    p2 = Path(snip.key.file_path or "")
                    snip.can_patch = (p2.exists() and p2.is_file() and str(p2.resolve()).startswith(str(Path(src).resolve())) and _lang_from_ext(p2) is not None)
            except Exception:
                snip.can_patch = False
        return [snip] if snip else []
    return []


def _get_type_snippets(type_name: str, file_path: str | None, state: Any) -> List[ContextCodeSnippet]:
    root = getattr(state, "project_root", None) or getattr(state, "source_dir", None)
    cq = _get_local_cq(root)
    if cq:
        try:
            from pathlib import Path as _P
            types = cq.get_types(type_name, file_path=_P(file_path) if file_path else None)
            if types:
                try:
                    preview = [
                        (
                            t.name,
                            str(t.file_path),
                            t.definition_line,
                            len(t.definition or ""),
                        )
                        for t in types[:10]
                    ]
                    logger.info("[TOOLS] CQ get_types returned: %s", preview)
                except Exception:
                    pass
            sn = _snippets_from_cq_types(types)
            if sn:
                return sn
        except Exception:
            pass
    # Fallback heuristic
    p = _resolve_path(root, file_path) if file_path else None
    if not p:
        src_dir = Path(getattr(state, "source_dir", root or "."))
        for cand in _rglob_many(src_dir, ("**/*.java",)):
            try:
                if re.search(rf"\bclass\s+{re.escape(type_name)}\b|\binterface\s+{re.escape(type_name)}\b", _read_text(cand)):
                    p = cand
                    break
            except Exception:
                continue
    if not p or not p.exists():
        return []
    if _lang_from_ext(p) == "java":
        snip = _build_snippet_from_java(p, type_name, "type", part="definition")
        if snip:
            try:
                src = getattr(state, "source_dir", None)
                if src:
                    p2 = Path(snip.key.file_path or "")
                    snip.can_patch = (p2.exists() and p2.is_file() and str(p2.resolve()).startswith(str(Path(src).resolve())) and _lang_from_ext(p2) is not None)
            except Exception:
                snip.can_patch = False
        return [snip] if snip else []
    return []


@tool
def get_class(
    class_name: str,
    file_path: str | None,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """Get a Java class/interface/enum full definition (alias of get_type). Prefer passing file_path if known."""
    try:
        snippets = _get_type_snippets(class_name, file_path, state)
        if not snippets:
            msg = f"No definition found for class {class_name} in {file_path}"
            return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
        out = "\n".join(str(s) for s in snippets)
        merged = _merge_snippets(state, snippets)
        return Command(update={"messages": [ToolMessage(content=out, tool_call_id=tool_call_id)], "code_snippets": merged})
    except Exception as e:
        return Command(update={"messages": [ToolMessage(content=f"Error: {e}", tool_call_id=tool_call_id)]})

@tool
def get_function(
    function_name: str,
    file_path: str | None,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """Get a function's definition and track it as snippet(s). Prefer passing file_path if known."""
    try:
        # If this function already exists in tracked snippets for this file, nudge the agent to move on
        root = getattr(state, "project_root", None) or getattr(state, "source_dir", None)
        resolved = _resolve_path(root, file_path) if file_path else None
        if _already_tracked_function(state, function_name, str(resolved) if resolved else None):
            hint = (
                f"Function {function_name} already tracked"
                + (f" in {resolved}" if resolved else "")
                + "; consider get_callees/get_callers/get_field_refs for related context."
            )
            return Command(update={"messages": [ToolMessage(content=hint, tool_call_id=tool_call_id)]})
        snippets = _get_function_snippets(function_name, file_path, state)
        if not snippets:
            msg = f"No definition found for function {function_name} in {file_path}"
            return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
        # Limit to at most 2 function snippets to avoid expanding many overloads
        if len(snippets) > 2:
            snippets = snippets[:2]
        out = "\n".join(str(s) for s in snippets)
        merged = _merge_snippets(state, snippets)
        return Command(update={"messages": [ToolMessage(content=out, tool_call_id=tool_call_id)], "code_snippets": merged})
    except Exception as e:
        logger.exception("get_function error")
        return Command(update={"messages": [ToolMessage(content=f"Error: {e}", tool_call_id=tool_call_id)]})


@tool
def get_type(
    type_name: str,
    file_path: str | None,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """Get a type/class definition and track it as snippet(s). Prefer passing file_path if known."""
    try:
        # Include structured type info from CodeQuery in the tool message (for LLM visibility)
        root = getattr(state, "project_root", None) or getattr(state, "source_dir", None)
        header = ""
        try:
            cq = _get_local_cq(root)
            if cq:
                from pathlib import Path as _P
                types = cq.get_types(type_name, file_path=_P(file_path) if file_path else None)
                if types:
                    infos = []
                    for t in types[:5]:
                        # Try to extract a source signature line for the type
                        sig = ""
                        try:
                            if t.definition:
                                first = (t.definition.splitlines() or [""])[0].strip()
                                sig = first
                            else:
                                # Read a small window around the definition line
                                lines = _read_lines(Path(t.file_path))
                                idx = max(0, (t.definition_line or 1) - 1)
                                window = lines[max(0, idx - 3) : min(len(lines), idx + 3)]
                                for ln in window:
                                    m = re.search(r"\b(class|interface|enum)\b.+{?", ln)
                                    if m:
                                        sig = ln.strip()
                                        break
                        except Exception:
                            pass
                        infos.append(
                            f"<type name=\"{t.name}\" file=\"{t.file_path}\" line=\"{t.definition_line}\" length=\"{len(t.definition or '')}\">\n"
                            + (f"<type_signature>{sig}</type_signature>\n" if sig else "")
                            + "</type>"
                        )
                    header = "<type_info>\n" + "\n".join(infos) + "\n</type_info>\n"
        except Exception:
            pass

        snippets = _get_type_snippets(type_name, file_path, state)
        out = header + "\n".join(str(s) for s in snippets)
        try:
            logger.info("[TOOLS] get_type out:\n%s", (out[:1000] + "..." if len(out) > 1000 else out))
        except Exception:
            pass
        if not snippets:
            msg = header or f"No definition found for type {type_name} in {file_path}"
            return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
        merged = _merge_snippets(state, snippets)
        return Command(update={"messages": [ToolMessage(content=out, tool_call_id=tool_call_id)], "code_snippets": merged})
    except Exception as e:
        logger.exception("get_type error")
        return Command(update={"messages": [ToolMessage(content=f"Error: {e}", tool_call_id=tool_call_id)]})


@tool
def get_callers(
    function_name: str,
    file_path: str | None,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """List callers using local CodeQuery DB; fallback to grep if unavailable. Also track top caller definitions."""
    root = getattr(state, "source_dir", None) or getattr(state, "project_root", None) or os.getcwd()
    cq = _get_local_cq(root)
    if cq:
        try:
            rows = cq.get_callers(function_name)
            if not rows:
                msg = f"No callers found for function {function_name}"
                return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
            # Support both tuple rows and Function objects from shared_tools.codequery
            snippets: List[ContextCodeSnippet] = []
            try:
                from shared_tools.codequery import Function as _CQFunc  # type: ignore
            except Exception:
                _CQFunc = None  # type: ignore

            if _CQFunc and rows and isinstance(rows[0], _CQFunc):  # type: ignore[truthy-bool]
                # rows: List[Function]
                listing_items = []
                for f in rows[:200]:
                    try:
                        listing_items.append(f"- `{getattr(f, 'name', '') or ''}` in `{getattr(f, 'file_path', '')}`")
                    except Exception:
                        continue
                listing = "Found {} callers of function {}:\n{}".format(len(rows), function_name, "\n".join(listing_items))
                # Directly convert top few Function rows into snippets
                snippets.extend(_snippets_from_cq_functions(rows[:5]))  # type: ignore[arg-type]
            else:
                # rows: List[tuple[str, Path, int]]
                listing = "Found {} callers of function {}:\n{}".format(
                    len(rows), function_name, "\n".join(f"- `{val}` in `{fp}`" for val, fp, _ in rows[:200])
                )
                try:
                    for val, fp, ln in rows[:5]:
                        funcs = cq.get_functions(val, file_path=fp, line_number=ln)
                        snippets.extend(_snippets_from_cq_functions(funcs))
                except Exception:
                    pass
            if snippets:
                merged = _merge_snippets(state, snippets)
                return Command(update={
                    "messages": [ToolMessage(content=listing, tool_call_id=tool_call_id)],
                    "code_snippets": merged,
                })
            return Command(update={"messages": [ToolMessage(content=listing, tool_call_id=tool_call_id)]})
        except Exception:
            msg = f"No callers found for function {function_name}"
            return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    # Fallback grep
    calls: List[str] = []
    for fp in _rglob_many(Path(root), ("**/*.java",)):
        lines = _read_lines(fp)
        for i, line in enumerate(lines, start=1):
            if re.search(rf"\b{re.escape(function_name)}\s*\(", line):
                calls.append(f"- `{function_name}` in `{fp}` line {i}")
    if not calls:
        msg = f"No callers found for function {function_name}"
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    listing = f"Found {len(calls)} callers of function {function_name}:\n" + "\n".join(calls[:200])
    return Command(update={"messages": [ToolMessage(content=listing, tool_call_id=tool_call_id)]})


@tool
def get_callees(
    function_name: str,
    file_path: str | None,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    """Use local CodeQuery DB to get callees; fallback to regex in-file scan. Also track top callee definitions."""
    root = getattr(state, "project_root", None) or getattr(state, "source_dir", None) or os.getcwd()
    cq = _get_local_cq(root)
    if cq:
        try:
            p = _resolve_path(root, file_path) if file_path else None
            # Only constrain by file when Java; otherwise -b can over-filter to zero results.
            p_java = p if (p and _lang_from_ext(p) == "java") else None
            rows = cq.get_callees(function_name, p_java)
            if not rows:
                msg = f"No callees found for function {function_name}"
                return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
            # Support both tuple rows and Function objects from shared_tools.codequery
            snippets: List[ContextCodeSnippet] = []
            try:
                from shared_tools.codequery import Function as _CQFunc  # type: ignore
            except Exception:
                _CQFunc = None  # type: ignore

            if _CQFunc and rows and isinstance(rows[0], _CQFunc):  # type: ignore[truthy-bool]
                # rows: List[Function]
                listing_items = []
                for f in rows[:200]:
                    try:
                        listing_items.append(f"- `{getattr(f, 'name', '') or ''}` in `{getattr(f, 'file_path', '')}`")
                    except Exception:
                        continue
                listing = "Found {} callees of function {}:\n{}".format(len(rows), function_name, "\n".join(listing_items))
                # Directly convert top few callee Function rows into snippets
                snippets.extend(_snippets_from_cq_functions(rows[:5]))  # type: ignore[arg-type]
            else:
                # rows: List[tuple[str, Path, int]]
                listing = "Found {} callees of function {}:\n{}".format(
                    len(rows), function_name, "\n".join(f"- `{val}` in `{fp}`" for val, fp, _ in rows[:200])
                )
                try:
                    for val, _fp, _ln in rows[:5]:
                        funcs = cq.get_functions(val)
                        snippets.extend(_snippets_from_cq_functions(funcs))
                except Exception:
                    pass
            # Fallback: if we have rows but no resolved definition snippets, attach an inline call-site/context snippet
            if not snippets and rows:
                try:
                    from pathlib import Path as _P2
                    if _CQFunc and isinstance(rows[0], _CQFunc):  # type: ignore[truthy-bool]
                        f = rows[0]
                        fp = getattr(f, "file_path", None)
                        bodies = list(getattr(f, "bodies", []) or [])
                        if fp:
                            lines = _read_lines(_P2(str(fp)))
                            if bodies:
                                b0 = bodies[0]
                                lo = getattr(b0, "start_line", 1)
                                hi = getattr(b0, "end_line", max(1, len(lines)))
                            else:
                                lo, hi = 1, min(200, len(lines))
                            code = "\n".join(lines[max(1, lo) - 1 : min(len(lines), hi)])
                            snippets.append(
                                ContextCodeSnippet(
                                    key=CodeSnippetKey(file_path=str(fp)),
                                    start_line=max(1, lo),
                                    end_line=min(len(lines), hi),
                                    code=code,
                                    description=f"Callee context for {function_name} in {fp}",
                                    can_patch=True,
                                )
                            )
                    else:
                        val, fp, ln = rows[0]
                        lines = _read_lines(fp)
                        lo = max(1, ln - 5)
                        hi = min(len(lines), ln + 5)
                        code = "\n".join(lines[lo - 1 : hi])
                        snippets.append(
                            ContextCodeSnippet(
                                key=CodeSnippetKey(file_path=str(fp)),
                                start_line=lo,
                                end_line=hi,
                                code=code,
                                description=f"Call site for callee `{val}` around line {ln} in {fp}",
                                can_patch=True,
                            )
                        )
                except Exception:
                    pass
            if snippets:
                merged = _merge_snippets(state, snippets)
                return Command(update={
                    "messages": [ToolMessage(content=listing, tool_call_id=tool_call_id)],
                    "code_snippets": merged,
                })
            return Command(update={"messages": [ToolMessage(content=listing, tool_call_id=tool_call_id)]})
        except Exception:
            msg = f"No callees found for function {function_name}"
            return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    # Fallback heuristic in-file
    p = _resolve_path(root, file_path) if file_path else None
    if not p or not p.exists():
        msg = f"No callees found for function {function_name} (file not found)"
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    text = _read_text(p)
    m = re.search(rf"{re.escape(function_name)}\s*\(.*?\)\s*{{([\s\S]*?)}}", text)
    if not m:
        msg = f"No callees found for function {function_name} in {p}"
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    body = m.group(1)
    callees = sorted(set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", body)))
    callees = [c for c in callees if c != function_name]
    if not callees:
        msg = f"No callees found for function {function_name} in {p}"
        return Command(update={"messages": [ToolMessage(content=msg, tool_call_id=tool_call_id)]})
    listing = "Found {} callees of function {}:\n{}".format(len(callees), function_name, "\n".join(f"- `{c}` in `{p}`" for c in callees[:200]))
    return Command(update={"messages": [ToolMessage(content=listing, tool_call_id=tool_call_id)]})


@tool
def think(reasoning: str) -> str:
    """Think more about the problem and available tools."""
    return (
        "Think carefully: identify exact function/type with get_function/get_type; validate with get_lines; "
        "only then call track_snippet. Reasoning: "
        + reasoning
    )


@tool
def track_snippet(
    file_path: str,
    code_snippet_description: str,
    function_name: str | None,
    type_name: str | None,
    start_line: int | None,
    end_line: int | None,
    *,
    state: Annotated[Any, InjectedState],
    tool_call_id: str,
) -> Command:
    """Track a range of lines from a file as a code snippet, or a function/type by name."""
    try:
        snippets: List[ContextCodeSnippet] | None = None
        if function_name:
            logger.info("[TOOLS] get_function via CodeQuery: %s @ %s", function_name, file_path)
            snippets = _get_function_snippets(function_name, file_path, state)
        elif type_name:
            logger.info("[TOOLS] get_type via CodeQuery: %s @ %s", type_name, file_path)
            snippets = _get_type_snippets(type_name, file_path, state)
        elif start_line is not None and end_line is not None:
            root = getattr(state, "project_root", None) or getattr(state, "source_dir", None)
            p = _resolve_path(root, file_path) or Path(file_path)
            lines = _read_lines(p)
            s = max(1, start_line - 5)
            e = min(len(lines), max(end_line, start_line) + 5)
            # Expand to enclosing Java entity if applicable
            rng = _expand_java_range_to_enclosing_entity(p, s, e)
            if rng:
                s, e = rng
            logger.info("[RANGE] track_snippet root=%s file_path=%s resolved=%s exists=%s s=%d e=%d total=%d", root, file_path, p, p.exists(), s, e, len(lines))
            code = "\n".join(lines[s - 1 : e])
            snippets = [
                ContextCodeSnippet(
                    key=CodeSnippetKey(file_path=str(p)),
                    start_line=s,
                    end_line=e,
                    code=code,
                    description=code_snippet_description,
                    can_patch=(p.exists() and p.is_file() and (getattr(state, "source_dir", None) and str(p.resolve()).startswith(str(Path(getattr(state, "source_dir")).resolve()))) and _lang_from_ext(p) is not None),
                )
            ]
        if not snippets:
            raise ValueError("No code snippets found for request; verify inputs before tracking")
        # Signal the ReAct loop to stop after a successful snippet track
        logger.info("[TOOLS] track_snippet success: %d snippet(s)", len(snippets))
        merged = _merge_snippets(state, snippets)
        return Command(update={"code_snippets": merged}, goto="__end__")
    except Exception as e:
        # Return a benign update without injecting tool messages to the LLM history
        logger.exception("[TOOLS] track_snippet failed: %s", e)
        return Command(update={})


