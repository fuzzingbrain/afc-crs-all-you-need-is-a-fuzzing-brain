# -*- coding: utf-8 -*-
"""
Searcher bridge for patch-agent-tools backed by multi_agent's CodeQuery.

API:
- read_source(file_name, line_number)
- find_references(symbol)
- read_definition(symbol)

All methods return Ok/Err per common.core.Result.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import os
from pathlib import Path
from typing import TypedDict, Iterable, List, Dict

from common.core import Ok, Err, CRSError, Result, requireable, require
from shared_tools.codequery import LocalCodeQuery, get_codequery


# ---------- 类型声明 ----------
class SourceContents(TypedDict):
    start: int          # 起始行（包含）
    end: int            # 结束行（不包含）
    contents: str       # 多行源码字符串


class FileReference(TypedDict):
    line: int
    content: str


class FileReferences(TypedDict):
    file_name: str
    refs: List[FileReference]


# ---------- 同步运行协程 ----------
import asyncio
from typing import Any

def _run_sync(coro: "asyncio.Future[Any]") -> Any:
    """
    在同步环境里执行协程：
      • 若当前无事件循环 → asyncio.run
      • 若已有事件循环 → run_coroutine_threadsafe
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    fut = asyncio.run_coroutine_threadsafe(coro, loop)
    return fut.result()


# ---------- Searcher（仅做包装） ----------
class Searcher:
    """Synchronous façade backed by shared CodeQuery."""

    def __init__(self, repo_root: str | os.PathLike, **kwargs):
        root = str(repo_root)
        cq = get_codequery(root)
        if not cq:
            raise CRSError("CodeQuery not available (requires cscope/ctags/cqmakedb/cqsearch)")
        self._cq: LocalCodeQuery = cq
        self._root = root
        self._globs = self._detect_repo_globs(Path(self._root))

    def _detect_repo_globs(self, root: Path) -> List[str]:
        """Heuristically choose file globs based on repository language.
        Prefer Java-only if the repo appears Java; otherwise include C/C++.
        """
        try:
            # Light heuristics: build files or file prevalence
            build_markers = ["pom.xml", "build.gradle", "build.gradle.kts", ".mvn", "mvnw", ".gradle"]
            if any((root / m).exists() for m in build_markers):
                return ["**/*.java"]
            has_java = next(root.rglob("**/*.java"), None) is not None
            has_c = next(root.rglob("**/*.c"), None) is not None
            has_cpp = next(root.rglob("**/*.cpp"), None) is not None
            if has_java and not (has_c or has_cpp):
                return ["**/*.java"]
        except Exception:
            pass
        # Default: search common source types (Java prioritized first)
        return ["**/*.java"]

    def _resolve_file(self, file_name: str) -> Path | None:
        p = Path(file_name)
        # Accept absolute files directly
        if p.is_absolute():
            return p if p.is_file() else None
        # Try relative to root
        q = Path(self._root) / file_name
        if q.is_file():
            return q
        # Heuristic: strip any benchmark/project/source prefix segments
        s = str(file_name)
        for marker in ("/source/", "\\source\\"):
            if marker in s:
                s = s.split(marker, 1)[1]
                break
        # Suffix search by filename under root
        try:
            tail = Path(s)
            candidates = list(Path(self._root).rglob(tail.name))
            for cand in candidates:
                try:
                    # Accept if the end of the path matches the provided suffix
                    if cand.as_posix().endswith(tail.as_posix()) and cand.is_file():
                        return cand
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def read_source(self, file_name: str, line_number: int, context: int = 3):
        try:
            p = self._resolve_file(file_name)
            if not p:
                return Err(CRSError(f"file not found: {file_name}"))
            if p.is_dir():
                return Err(CRSError(f"read_source error: Is a directory: '{p}'"))
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            # Prefer enclosing function via CQ when possible
            from pathlib import Path as _P
            funcs = self._cq.get_functions("*", file_path=_P(str(p)), line_number=line_number)
            if funcs:
                b = funcs[0].bodies[0]
                start = max(1, b.start_line)
                end = min(len(lines), b.end_line)
            else:
                start = max(1, line_number - context)
                end = min(len(lines), line_number + context)
            contents = "\n".join(lines[start - 1 : end])
            return Ok({"start": start, "end": end, "contents": contents})
        except Exception as e:
            return Err(CRSError(f"read_source error: {e}"))

    def find_references(self, symbol: str, max_results: int = 10):
        try:
            # Hard cap: return at most 20 results even if max_results > 20
            effective_max = min(max_results, 20)
            rows = self._cq.get_callers(symbol)
            out: List[Dict] = []
            if rows:
                from pathlib import Path as _P
                for func in rows[:effective_max]:
                    try:
                        fp = _P(str(func.file_path))
                        lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
                        refs: List[Dict] = []
                        ranges = [(b.start_line, b.end_line) for b in getattr(func, "bodies", [])] or [(1, len(lines))]
                        for lo, hi in ranges:
                            for i in range(max(1, lo), min(len(lines), hi) + 1):
                                line = lines[i - 1]
                                if symbol in line:
                                    refs.append({"line": i, "content": line})
                                    if len(refs) >= effective_max:
                                        break
                            if len(refs) >= effective_max:
                                break
                        if refs:
                            out.append({"file_name": str(fp), "refs": refs})
                            if len(out) >= effective_max:
                                break
                    except Exception:
                        continue
            if out:
                return Ok(out)
            # Fallback: no CQ hits; scan the tree literally
            results: List[Dict] = []
            per_file: Dict[Path, List[Dict]] = {}
            root = Path(self._root)
            for g in self._globs:
                for p in root.rglob(g):
                    try:
                        if not p.is_file():
                            continue
                        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                        refs: List[Dict] = []
                        for i, line in enumerate(lines, start=1):
                            if symbol in line:
                                refs.append({"line": i, "content": line})
                                if len(refs) >= effective_max:
                                    break
                        if refs:
                            per_file[p] = refs
                    except Exception:
                        continue
            for fp, refs in list(per_file.items())[:effective_max]:
                results.append({"file_name": str(fp), "refs": refs})
            return Ok(results)
        except Exception as e:
            return Err(CRSError(f"find_references error: {e}"))

    def read_definition(self, symbol: str, context: int = 3):
        try:
            types = self._cq.get_types(symbol)
            if types:
                t = types[0]
                lines = Path(t.file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
                start = max(1, t.definition_line)
                end = min(len(lines), t.definition_line + len((t.definition or "").splitlines()))
                contents = "\n".join(lines[start - 1 : end])
                return Ok({"start": start, "end": end, "contents": contents})
            funcs = self._cq.get_functions(symbol)
            if funcs:
                b = funcs[0].bodies[0]
                return Ok({"start": b.start_line, "end": b.end_line, "contents": b.body})
            # Fallback: look for a close-by window in probable source files for this repo
            root = Path(self._root)
            for g in self._globs:
                for p in root.rglob(g):
                    try:
                        if not p.is_file():
                            continue
                        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                        for i, line in enumerate(lines, start=1):
                            if symbol in line:
                                s = max(1, i - 5)
                                e = min(len(lines), i + 5)
                                return Ok({"start": s, "end": e, "contents": "\n".join(lines[s - 1 : e])})
                    except Exception:
                        continue
            return Err(CRSError(f"definition not found: {symbol}"))
        except Exception as e:
            return Err(CRSError(f"read_definition error: {e}"))


# -*- coding: utf-8 -*-
"""
Very small smoke-test for tools.searcher.Searcher.

运行方式：
    python -m unittest patch-agent-tools/tests/test_searcher.py
（或直接 `python tests/test_searcher.py`）
"""
import unittest
from pathlib import Path
from tools.searcher import Searcher
from common.core import Ok, Err

REPO_ROOT = Path("/home/qingxiao/patch_benchmark/afc-zookeeper")
SRC_ROOT  = REPO_ROOT / "source"


class SearcherSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.searcher = Searcher(SRC_ROOT)

    def test_read_definition_verifyIPv6(self):
        """应当能定位 verifyIPv6 的定义"""
        res = self.searcher.read_definition("verifyIPv6")
        print(res)
        # todo: fix this
        self.assertIsInstance(res, Ok)
        # 定义片段里应包含函数签名
        self.assertIn("verifyIPv6(", res.value["contents"])

    def test_find_references_verifyIPv6(self):
        """应当能找到 verifyIPv6 的调用 / 定义行"""
        res = self.searcher.find_references("verifyIPv6")
        self.assertIsInstance(res, Ok)
        print(res)
        # 至少有一条引用
        total_refs = sum(len(f["refs"]) for f in res.value)
        self.assertGreater(total_refs, 0)

    def test_read_source_message_tracker(self):
        """读取 MessageTracker.java 指定行附近源码"""
        file_path = (
            "zookeeper-server/src/main/java/"
            "org/apache/zookeeper/server/util/MessageTracker.java"
        )
        # 121 行是 verifyIPv6 定义起始行（见源码）
        res = self.searcher.read_source(file_path, 121)
        print(res)
        # todo: fix this
        self.assertIsInstance(res, Ok)
        self.assertIn("verifyIPv6", res.value["contents"])

if __name__ == "__main__":
    unittest.main()