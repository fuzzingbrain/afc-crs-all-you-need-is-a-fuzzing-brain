# -*- coding: utf-8 -*-
"""
Light-weight async Searcher (Java-oriented).

提供三个主要协程：
    • read_source(file_name, line_number)
    • find_references(symbol, *, max_results=100)
    • read_definition(symbol)

依赖：
    pip install tree_sitter tree_sitter_java orjson
    以及 (可选) joern 的 Python 封装与 CLI 二进制，用于更精确的 Java CPG 查询。
"""

from __future__ import annotations
import asyncio, logging, os, re, orjson
from pathlib import Path
from typing import Dict, List, Optional, TypedDict

from common.core import (                      # 项目已有实现
    Ok, Err, Result, CRSError,
    requireable, require,
    SourceContents, FileReference, FileReferences,
)

# ----------------------------------------------------------------------
# 常量
# ----------------------------------------------------------------------
MAX_SEARCH_RESULTS = 100
CONTEXT_LINES       = 3

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

# ----------------------------------------------------------------------
# Tree-sitter (Java)
# ----------------------------------------------------------------------
import tree_sitter                           # noqa: E402
import tree_sitter_java                      # noqa: E402

# language & parser
TS_JAVA_LANG   = tree_sitter.Language(tree_sitter_java.language())
TS_JAVA_PARSER = tree_sitter.Parser(TS_JAVA_LANG)

# 更通用：捕获声明节点，identifier 在代码里递归查找，避免依赖 method_declarator
TS_JAVA_QUERY = tree_sitter.Query(
    TS_JAVA_LANG,
    """
    (method_declaration)    @decl
    (class_declaration)     @decl
    (interface_declaration) @decl
    """
)
from tree_sitter import QueryCursor          # 游标用来执行查询

# ----------------------------------------------------------------------
# Joern 轻量封装（仅当环境中可用）
# ----------------------------------------------------------------------
try:
    from common import joern                              # noqa: E402
    _JOERN_AVAILABLE = True
except ModuleNotFoundError:
    _JOERN_AVAILABLE = False
    logger.warning("joern module not found – definition search将退化为正则 + tree-sitter")


class DefinitionSite(TypedDict):
    file: Path
    start: int
    end: int


class JoernSearcher:
    """
    极简 Java Joern 搜索：
    - 依赖 'joern' Python 封装提供的 search(repo_root, name) → list[dict]
      若不可用则所有方法返回 Err。
    """
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root

    @requireable
    async def find_lines(self, name: str) -> Result[Dict[Path, List[DefinitionSite]]]:
        if not _JOERN_AVAILABLE:
            return Err(CRSError("joern unavailable"))
        # 示例：joern.search 返回 [{'file': '/abs/path/Foo.java', 'start_line': 42, 'end_line': 60}, ...]
        raw = await asyncio.to_thread(joern.search, self.repo_root, name)
        res: Dict[Path, List[DefinitionSite]] = {}
        for item in raw:
            path = Path(item["file"])
            res[path] = res.get(path, [])
            res[path].append(
                DefinitionSite(file=path, start=item["start_line"], end=item["end_line"])
            )
        return Ok(res)


# ----------------------------------------------------------------------
# 辅助：同步读取源码片段
# ----------------------------------------------------------------------
def _read_source_snippet(path: Path, center_line: int, ctx: int = CONTEXT_LINES) -> SourceContents:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, center_line - ctx)
    end   = min(len(lines) + 1, center_line + ctx + 1)
    snippet = "\n".join(f"{i:>5} | {lines[i-1]}" for i in range(start, end))
    return SourceContents(start=start, end=end, contents=snippet)

def _read_source_range(path: Path, start_line: int, end_line: int) -> SourceContents:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, start_line)
    end_excl = min(len(lines) + 1, end_line + 1)
    snippet = "\n".join(f"{i:>5} | {lines[i-1]}" for i in range(start, end_excl))
    return SourceContents(start=start, end=end_excl, contents=snippet)


# ----------------------------------------------------------------------
# 核心 Searcher
# ----------------------------------------------------------------------
class Searcher:
    def __init__(
        self,
        repo_root: str | os.PathLike,
        include_ext: tuple[str, ...] = (".java", ".c", ".cpp", ".h", ".py")
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.include_ext = {e.lower() for e in include_ext}
        self.joern = JoernSearcher(self.repo_root)

    # ---------- 基础文件迭代 ----------
    def _iter_source_files(self):
        for root, _, files in os.walk(self.repo_root):
            for f in files:
                p = Path(root, f)
                if not self.include_ext or p.suffix.lower() in self.include_ext:
                    yield p
                
    async def _ripgrep_references(self, symbol: str, max_results: int) -> Optional[Dict[str, List[FileReference]]]:
        """
        使用 ripgrep 进行固定字符串(-F)搜索并解析 --json 输出。
        若 rg 不可用/失败，返回 None；若成功但无结果，返回 {}。
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "rg",
                "-m", str(max_results),
                "--json",
                "-n",
                "-F",
                "-e", symbol,
                "-t", "java",
                "-t", "c",
                "-t", "cpp",
                str(self.repo_root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.debug("ripgrep not installed, fallback to python scan")
            return None

        stdout, stderr = await proc.communicate()
        if proc.returncode not in (0, 1):  # 0 有匹配，1 无匹配
            err = (stderr or b"").decode(errors="replace")
            logger.debug(f"ripgrep failed: rc={proc.returncode} msg={err[:300]}")
            return None

        results: Dict[str, List[FileReference]] = {}
        try:
            for line in stdout.splitlines():
                if not line:
                    continue
                obj = orjson.loads(line)
                if obj.get("type") != "match":
                    continue
                data = obj["data"]
                fpath = Path(data["path"]["text"])
                try:
                    rel = str(fpath.relative_to(self.repo_root))
                except ValueError:
                    rel = str(fpath)
                lno = int(data["line_number"])
                content = data["lines"]["text"].rstrip()
                results.setdefault(rel, []).append(FileReference(line=lno, content=content))
        except Exception as e:
            logger.debug(f"ripgrep json parse error: {e}")
            return None

        return results
    
    @requireable
    async def read_source_range(self, file_name: str, start_line: int, end_line: int) -> Result[SourceContents]:
        path = (self.repo_root / file_name).resolve()
        if not path.is_file():
            return Err(CRSError(f"file does not exist: {file_name}"))
        if start_line < 1 or end_line < start_line:
            return Err(CRSError("invalid range"))
        return Ok(await asyncio.to_thread(_read_source_range, path, start_line, end_line))

    # ==================================================================
    # 公共 API
    # ==================================================================
    @requireable
    async def read_source(self, file_name: str, line_number: int) -> Result[SourceContents]:
        path = (self.repo_root / file_name).resolve()
        if not path.is_file():
            return Err(CRSError(f"file does not exist: {file_name}"))
        if line_number < 1:
            return Err(CRSError("line_number must start from 1"))

        # 先按定义范围读（Java）
        if path.suffix.lower() == ".java":
            extent = await asyncio.to_thread(self._get_java_enclosing_extent, path, line_number)
            if extent:
                start, end = extent
                # print(f"read_source: {path}:{start}-{end}")
                # 读取闭区间 [start, end]
                return Ok(await asyncio.to_thread(_read_source_range, path, start, end))

        # 找不到范围则回退到原来的“中心行上下固定行数”
        return Ok(await asyncio.to_thread(_read_source_snippet, path, line_number))

    # ---------- find_references ----------
    @requireable
    async def find_references(
        self, symbol: str, *, max_results: int = MAX_SEARCH_RESULTS
    ) -> Result[List[FileReferences]]:
        if not symbol:
            return Err(CRSError("symbol must not be empty"))

        # 优先：ripgrep 固定字符串搜索（更快，行为类似 CRS 的兜底路径）
        rg_results = await self._ripgrep_references(symbol, max_results)
        if rg_results is not None:
            if rg_results:
                # print(rg_results)
                return Ok([FileReferences(file_name=f, refs=r) for f, r in rg_results.items()])
            # 有 rg 且执行成功但无结果，直接返回 Err 与现有语义一致
            return Err(CRSError("no references found"))

        # 回退：原有逐文件扫描（字面量匹配）
        pattern = re.compile(re.escape(symbol))
        results: Dict[str, List[FileReference]] = {}
        total = 0
        for path in self._iter_source_files():
            refs: List[FileReference] = []
            for i, line in enumerate(
                path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1
            ):
                if pattern.search(line):
                    refs.append(FileReference(line=i, content=line.rstrip()))
                    total += 1
                    if total >= max_results:
                        break
            if refs:
                rel = str(path.relative_to(self.repo_root))
                results[rel] = refs
            if total >= max_results:
                break
        if not results:
            return Err(CRSError("no references found"))
        return Ok([FileReferences(file_name=f, refs=r) for f, r in results.items()])

    # ---------- read_definition ----------
    @requireable
    async def read_definition(self, symbol: str, *, context: int = CONTEXT_LINES) -> Result[SourceContents]:
        # 1) Joern（若可用）
        match await self.joern.find_lines(symbol):
            case Ok(defs) if defs:
                logger.info("read_definition: joern")
                path, site = next(iter(defs.items()))
                first = site[0]
                joern_file = Path(first["file"])
                # 新增：重映射 .class/临时路径到仓库相对 .java
                remapped = self._remap_joern_file(joern_file)
                if remapped:
                    return await self.read_source(remapped, first["start"])
                # 映射失败则继续用 tree-sitter 搜索
                logger.debug(f"joern file not in repo, remap failed: {joern_file}")

        # 2) 仅用 tree-sitter（禁用正则回退）
        ts_match = await asyncio.to_thread(self._find_by_tree_sitter, symbol)
        if ts_match:
            logger.info("read_definition: tree-sitter")
            rel, line = ts_match
            return await self.read_source(rel, line)

        logger.info("read_definition: not found (tree-sitter only; regex disabled)")
        return Err(CRSError("definition not found (tree-sitter only; regex disabled)"))

    # ==================================================================
    # 内部助手
    # ==================================================================
    def _first_identifier(self, node) -> Optional[object]:
        # BFS/DFS 均可，这里用小型 DFS
        stack = [node]
        while stack:
            cur = stack.pop()
            try:
                if getattr(cur, "type", None) == "identifier":
                    return cur
                # named_children 在旧版本也可用；若不可用，退回 children
                children = getattr(cur, "named_children", None) or getattr(cur, "children", None) or []
                # 统一转为 list 迭代
                stack.extend(list(children))
            except Exception:
                continue
        return None

    def _find_by_tree_sitter(self, symbol: str) -> Optional[tuple[str, int]]:

        for path in self._iter_source_files():
            if path.suffix.lower() != ".java":
                continue

            src = path.read_bytes()
            tree = TS_JAVA_PARSER.parse(src)

            cur = QueryCursor(TS_JAVA_QUERY)
            captures = cur.captures(tree.root_node)

            # 获取 declaration 节点
            decl_nodes = captures.get("decl", [])

            for idx, decl in enumerate(decl_nodes, 1):

                # 只处理类、接口和方法声明
                if decl.type not in ("method_declaration", "class_declaration", "interface_declaration"):
                    continue

                # 找 declaration 下的 identifier（名称）
                id_node = None
                for child in decl.children:
                    if child.type == "identifier":
                        id_node = child
                        break

                if not id_node:
                    continue

                name = src[id_node.start_byte:id_node.end_byte].decode(errors="ignore")

                if name == symbol:
                    line = id_node.start_point.row + 1
                    logger.info(f"tree-sitter hit: {path}:{line} ({decl.type})")
                    return path, line

        return None

    def _get_java_enclosing_extent(self, path: Path, line_start: int) -> Optional[tuple[int, int]]:
        if path.suffix.lower() != ".java":
            return None
        try:
            src = path.read_bytes()
        except Exception:
            return None
        tree = TS_JAVA_PARSER.parse(src)

        best: Optional[tuple[int, int]] = None
        best_len = 10**9

        cur = QueryCursor(TS_JAVA_QUERY)
        captures = cur.captures(tree.root_node)
        # 兼容 earlier 逻辑：从 captures 中拿到声明节点列表
        decl_nodes = captures.get("decl", []) if hasattr(captures, "get") else [node for node, _ in captures]

        for decl in decl_nodes:
            try:
                start = getattr(decl, "start_point", None).row + 1
                end   = getattr(decl, "end_point", None).row + 1
            except Exception:
                # 若 decl 是 (node, idx) 形式
                node = decl[0] if isinstance(decl, (tuple, list)) else decl
                start = node.start_point.row + 1
                end   = node.end_point.row + 1

            if start <= line_start <= end:
                span = end - start
                if span < best_len:
                    best = (start, end)
                    best_len = span

        return best

    def _remap_joern_file(self, abs_path: Path) -> Optional[str]:
        """
        将 Joern 返回的绝对路径映射为仓库内的相对 .java 路径。
        - 若原路径已在仓库内：直接返回相对路径
        - 若为临时 .class 路径：根据包路径推断 .java，并在仓库下搜寻
        - 若无法映射：返回 None
        """
        try:
            # 已在仓库内
            return str(abs_path.relative_to(self.repo_root))
        except ValueError:
            pass

        # 仅处理 .class → .java 的常见情况
        if abs_path.suffix == ".class":
            parts = abs_path.parts
            # 常见包名顶层
            pkg_roots = {"org", "com", "net", "io", "edu", "java", "javax"}
            idx = next((i for i, p in enumerate(parts) if p in pkg_roots), None)
            if idx is not None:
                # 组装 org/.../Foo.java 这种后缀
                pkg_suffix = Path(*parts[idx:]).with_suffix(".java")
                # 在仓库内搜索该后缀
                try:
                    cand = next((p for p in self.repo_root.rglob(str(pkg_suffix)) if p.is_file()), None)
                except Exception:
                    cand = None
                if cand:
                    return str(cand.relative_to(self.repo_root))

            # 退化：仅按文件名搜索
            stem = abs_path.stem + ".java"
            try:
                cand2 = next((p for p in self.repo_root.rglob(stem) if p.is_file()), None)
            except Exception:
                cand2 = None
            if cand2:
                return str(cand2.relative_to(self.repo_root))

        # 其它情况：尝试按同名文件名兜底
        try:
            cand3 = next((p for p in self.repo_root.rglob(abs_path.name) if p.is_file()), None)
        except Exception:
            cand3 = None
        if cand3:
            return str(cand3.relative_to(self.repo_root))

        return None
