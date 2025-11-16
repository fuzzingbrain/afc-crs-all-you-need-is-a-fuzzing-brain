import re
import asyncio
from typing import Literal, Optional, List, Tuple
from common.core import CRSError, Result, Ok, Err, requireable, require
from pathlib import Path
import os
import subprocess
import tempfile

# 常量定义
HUNK_HEADER_RE = re.compile(r"\A@@\s-(\d*),\d*\s\+\d*,\d*\s@@")
NEW_SENTINEL = "+~NEW~+"
GAP_CHAR = "+~GAP~+"

# 类型定义
EditType = Literal['+', '-', '']

# 补丁处理函数（最简实现）
def is_hunk_header(line: str) -> bool:
    """检查是否为hunk头部"""
    return HUNK_HEADER_RE.match(line) is not None

def is_edit_line(line: str) -> bool:
    """检查是否为编辑行"""
    return line.startswith("+") or line.startswith("-")

def remove_extra_whitespace(patch: str) -> str:
    """移除多余的空白字符"""
    return patch.strip()

def extract_file_path_from_patch(patch: str) -> str:
    """从补丁中提取文件路径"""
    lines = patch.splitlines()
    for line in lines:
        if line.startswith("--- a/"):
            return line[6:]  # 去掉 "--- a/" 前缀
    return None

def cleanup_patch(patch: str) -> Result[str]:
    """清理补丁格式"""
    # 最简实现：直接返回清理后的补丁
    # print(f"Cleaning up patch: {patch}")
    return Ok(remove_extra_whitespace(patch))

class Edit:
    """表示一个编辑操作"""
    def __init__(self, file: str, lines: tuple, old_lines: tuple, before: list, after: list):
        self.file = file
        self.lines = lines  # (start, end) 新行号范围
        self.old_lines = old_lines  # (start, end) 旧行号范围
        self.before = before  # 原始内容
        self.after = after  # 新内容

class VFS:
    """虚拟文件系统基类"""
    def __init__(self, base_path: str = "."):
        """初始化VFS，base_path是文件系统的根目录"""
        self.base_path = Path(base_path).resolve()
    
    def read(self, path: str) -> bytes:
        """读取文件内容"""
        full_path = self.base_path / path
        try:
            if not full_path.exists():
                raise FileNotFoundError(f"File not found: {path}")
            if not full_path.is_file():
                raise IsADirectoryError(f"Path is a directory: {path}")
            return full_path.read_bytes()
        except Exception as e:
            raise CRSError(f"Failed to read file {path}: {e}")
    
    def write(self, path: str, content: bytes) -> None:
        """写入文件内容"""
        full_path = self.base_path / path
        try:
            # 确保父目录存在
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_bytes(content)
        except Exception as e:
            raise CRSError(f"Failed to write file {path}: {e}")
    
    def is_file(self, path: str) -> bool:
        """检查是否为文件"""
        full_path = self.base_path / path
        return full_path.is_file()
    
    def exists(self, path: str) -> bool:
        """检查路径是否存在"""
        full_path = self.base_path / path
        return full_path.exists()

class EditableOverlayFS(VFS):
    """可编辑的覆盖文件系统"""
    def __init__(self, parent: VFS):
        self.parent = parent
        self.files = {}  # 存储修改过的文件
        # 继承父类的base_path
        super().__init__(parent.base_path)
    
    def read(self, path: str) -> bytes:
        """读取文件，优先从覆盖层读取"""
        if path in self.files:
            return self.files[path]
        return self.parent.read(path)
    
    def write(self, path: str, content: bytes) -> None:
        """写入文件到覆盖层"""
        self.files[path] = content

    def is_file(self, path: str) -> bool:
        """检查是否为文件"""
        if path in self.files:
            return True
        return self.parent.is_file(path)
    
    def exists(self, path: str) -> bool:
        """检查路径是否存在"""
        if path in self.files:
            return True
        return self.parent.exists(path)
    
    def commit(self) -> None:
        """将覆盖层的修改提交到父文件系统"""
        for path, content in self.files.items():
            self.parent.write(path, content)
        self.files.clear()
    
    def rollback(self) -> None:
        """回滚覆盖层的修改"""
        self.files.clear()
    
    def get_modified_files(self) -> List[str]:
        """获取修改过的文件列表"""
        return list(self.files.keys())


class Hunk:
    """表示一个补丁块"""
    def __init__(self, relpath: str, elines: list[tuple[EditType, str]], line_number: int):
        self.relpath = relpath
        self.elines = elines  # [(edit_type, content), ...]
        self.line_number = line_number

def is_file_header(line: str) -> bool:
    """检查是否为文件头部"""
    return line.startswith("--- ") or line.startswith("+++ ")

def parse_hunks(relpath: str, patch: str) -> list[Hunk]:
    """解析补丁为多个hunk"""
    hunks: list[Hunk] = []
    this_hunk = None
    
    for line in patch.splitlines():
        if is_file_header(line):
            continue
        if match := HUNK_HEADER_RE.match(line):
            if this_hunk:
                hunks.append(this_hunk)
            line_no = int(match.groups()[0])
            this_hunk = Hunk(relpath, [], line_no)
        elif this_hunk is not None:
            edit_type = '+' if line.startswith("+") else ('-' if line.startswith("-") else "")
            this_hunk.elines.append((edit_type, line[1:]))
    
    if this_hunk:
        hunks.append(this_hunk)
    return hunks

def check_fuzzy_match(orig_line: Optional[str], new_line: Optional[str]) -> Result[None]:
    """检查模糊匹配是否有效"""
    if new_line == NEW_SENTINEL:
        return Ok(None)
    
    orig_l = orig_line.strip() if orig_line else ""
    new_l = new_line.strip() if new_line else ""
    
    # 检查括号匹配
    other = {"{": "}", "}": "{", "(": ")", ")": "("}
    for char in "}{)(":
        orig_count = orig_l.count(char)
        new_count = new_l.count(char)
        change = "inserted" if new_count > orig_count else "removed"
        
        if orig_count != new_count:
            if orig_line is not None and new_line is not None:
                return Err(CRSError(
                    f"The patch context lines have introduced a typographic error. "
                    f"The context you provided {change} `{char}`. Please double check the source code!",
                    extra={
                        "original_line": orig_l,
                        "provided_line": new_l,
                    }
                ))
            elif orig_line is None:
                if new_l.count(other[char]) == new_count:
                    continue
                return Err(CRSError(f"Unmatched {char} in new line: {new_l}"))
    
    return Ok(None)

class SimpleMatcher:
    """简单的字符串匹配器，用于替代复杂的Smith-Waterman算法"""
    
    def align(self, orig_lines: List[str], hunk_lines: List[str], start_line: int) -> List[Tuple[Optional[int], Optional[int]]]:
        """简单的对齐算法"""
        alignment = []
        orig_idx = max(0, start_line - 1)  # 从hunk指定的行号开始
        hunk_idx = 0
        
        # 简单的贪心匹配
        while hunk_idx < len(hunk_lines) and orig_idx < len(orig_lines):
            hunk_line = hunk_lines[hunk_idx]
            
            if hunk_line == NEW_SENTINEL:
                # 新行，不匹配原始行
                alignment.append((None, hunk_idx))
                hunk_idx += 1
            elif hunk_line.startswith(" "):
                # 上下文行，尝试匹配
                context_content = hunk_line[1:]  # 去掉前导空格
                if orig_idx < len(orig_lines) and orig_lines[orig_idx].strip() == context_content.strip():
                    alignment.append((orig_idx, hunk_idx))
                    orig_idx += 1
                    hunk_idx += 1
                else:
                    # 尝试在附近找到匹配
                    found = False
                    for search_range in range(1, min(10, len(orig_lines) - orig_idx)):
                        if orig_idx + search_range < len(orig_lines):
                            if orig_lines[orig_idx + search_range].strip() == context_content.strip():
                                # 跳过中间的行
                                for i in range(orig_idx, orig_idx + search_range):
                                    alignment.append((i, None))
                                alignment.append((orig_idx + search_range, hunk_idx))
                                orig_idx = orig_idx + search_range + 1
                                hunk_idx += 1
                                found = True
                                break
                    if not found:
                        # 如果找不到匹配，跳过这行
                        alignment.append((None, hunk_idx))
                        hunk_idx += 1
            else:
                # 删除行，匹配原始行
                if orig_idx < len(orig_lines):
                    alignment.append((orig_idx, hunk_idx))
                    orig_idx += 1
                    hunk_idx += 1
                else:
                    alignment.append((None, hunk_idx))
                    hunk_idx += 1
        
        # 处理剩余的行
        while hunk_idx < len(hunk_lines):
            alignment.append((None, hunk_idx))
            hunk_idx += 1
            
        return alignment

def apply_hunk(vfs: VFS, hunk: Hunk) -> Result[Edit]:
    """应用单个hunk到文件"""
    orig_bytes = vfs.read(hunk.relpath)
    orig_lines = orig_bytes.decode(errors="replace").splitlines()
    
    # 准备hunk行，将新增行标记为NEW_SENTINEL
    hunk_lines = []
    for edit_type, content in hunk.elines:
        if edit_type == '+':
            hunk_lines.append(NEW_SENTINEL)
        else:
            hunk_lines.append(content)
    
    if len(orig_lines) == 0:
        # 空文件，所有行都是新增的
        arange = [(None, i) for i in range(len(hunk_lines))]
    else:
        # 使用简单匹配器进行对齐
        matcher = SimpleMatcher()
        arange = matcher.align(orig_lines, hunk_lines, hunk.line_number)
    
    # 检查模糊匹配的有效性
    for orig_idx, hunk_idx in arange:
        require(check_fuzzy_match(
            orig_lines[orig_idx] if orig_idx is not None else None,
            hunk_lines[hunk_idx] if hunk_idx is not None else None,
        ))
    
    # 构建新文件内容
    orig_lines_bytes = orig_bytes.splitlines(keepends=True)
    new_lines = orig_lines_bytes[0:arange[0][0]] if arange and arange[0][0] is not None else []
    
    last_orig_line = -1
    for orig_line, patch_line in arange:
        if orig_line is not None:  # 有原始行
            last_orig_line = orig_line
            # 除非这行要被删除
            if patch_line is not None and hunk.elines[patch_line][0] == '-':
                continue
            new_lines.append(orig_lines_bytes[orig_line])  # 添加原始行
        elif patch_line is not None:  # 新增行
            new_lines.append(hunk.elines[patch_line][1].encode() + b"\n")
    
    if last_orig_line == -1 and len(orig_lines) > 0:
        return Err(CRSError('no good match found, please add more context lines'))
    
    new_lines += orig_lines_bytes[last_orig_line + 1:]
    new_content = b"".join(new_lines)
    
    # 创建编辑对象
    edit = apply_as_edit(vfs, hunk.relpath, new_content)
    return Ok(edit)

def apply_as_edit(vfs: VFS, relpath: str, new_content: bytes) -> Edit:
    """将新内容应用到文件并创建Edit对象"""
    old_content = vfs.read(relpath)
    vfs.write(relpath, new_content)
    
    # 计算编辑的行号范围（简化实现）
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    
    # 简单的行号计算
    lines = (0, len(new_lines))
    old_lines_range = (0, len(old_lines))
    before = old_lines
    after = new_lines
    
    return Edit(relpath, lines, old_lines_range, before, after)

def virtual_diff(path: str, a: bytes, b: bytes) -> Result[str]:
    """使用系统diff命令生成diff"""
    try:
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='_a') as tmp_a:
            tmp_a.write(a)
            tmp_a_path = tmp_a.name
        
        try:
            # 运行diff命令 - 修复：text=False，因为input是bytes
            result = subprocess.run([
                'diff', '-u',
                '--label', f'a/{path}', tmp_a_path,
                '--label', f'b/{path}', '-'
            ], input=b, capture_output=True, text=False, check=False)
            
            if result.returncode > 1:  # 0=相同, 1=不同, 2+=错误
                return Err(CRSError(f"diff command error: {result.stderr.decode(errors='replace')}"))
            
            return Ok(result.stdout.decode(errors="replace"))
        finally:
            os.unlink(tmp_a_path)
            
    except Exception as e:
        return Err(CRSError(f"Failed to generate diff: {e}"))

def fuzzy_patch(vfs: VFS, path: str, patch: str) -> Result[tuple]:
    """完整的模糊补丁应用函数"""
    path = os.path.normpath(path)
    patch = require(cleanup_patch(patch))
    hunks = parse_hunks(path, patch)
    # print(f"Elines: {hunks[0].elines}")
    # print(f"Line number: {hunks[0].line_number}")
    # print(f"Relpath: {hunks[0].relpath}")
    
    # 创建临时覆盖文件系统
    patch_vfs = EditableOverlayFS(vfs)
    edits: list[Edit] = []
    
    # 逐个应用hunk
    for i, hunk in enumerate(hunks):
        match apply_hunk(patch_vfs, hunk):
            case Ok(edit): 
                edits.append(edit)
            case Err(err):
                return Err(CRSError(
                    f"Error in hunk index {i} (line {hunk.line_number}): {err.message}", 
                    extra=err.extra
                ))
    
    # 将修改写回主VFS
    patch_chunks: list[str] = []
    for path, content in patch_vfs.files.items():
        ref = vfs.read(path)
        vdiff = require(virtual_diff(path, ref, content))
        patch_chunks.append(vdiff)
        # 写回主VFS
        vfs.write(path, content)
    
    diff_patch = "\n".join(patch_chunks)
    # print(f"Diff patch: {diff_patch}")
    # for edit in edits:
    #     print(f"Edits: {edit.lines}")
    #     print(f"Old lines: {edit.old_lines}")
    #     print(f"Before: {edit.before}")
    #     print(f"After: {edit.after}")
    #     print(f"File: {edit.file}")


    return Ok((diff_patch, edits))