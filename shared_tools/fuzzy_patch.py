import re
import asyncio
from typing import Literal, Optional, List, Tuple
from .core import CRSError, Result, Ok, Err, requireable, require
from pathlib import Path
import os
import subprocess
import tempfile

HUNK_HEADER_RE = re.compile(r"\A@@\s-(\d*),\d*\s\+\d*,\d*\s@@")
NEW_SENTINEL = "+~NEW~+"
GAP_CHAR = "+~GAP~+"

EditType = Literal['+', '-', '']

def is_hunk_header(line: str) -> bool:
    return HUNK_HEADER_RE.match(line) is not None

def is_edit_line(line: str) -> bool:
    return line.startswith("+") or line.startswith("-")

def remove_extra_whitespace(patch: str) -> str:
    return patch.strip()

def extract_file_path_from_patch(patch: str) -> str:
    lines = patch.splitlines()
    for line in lines:
        if line.startswith("--- a/"):
            return line[6:]
    return None

def cleanup_patch(patch: str) -> Result[str]:
    return Ok(remove_extra_whitespace(patch))

class Edit:
    def __init__(self, file: str, lines: tuple, old_lines: tuple, before: list, after: list):
        self.file = file
        self.lines = lines
        self.old_lines = old_lines
        self.before = before
        self.after = after

class VFS:
    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path).resolve()
    def read(self, path: str) -> bytes:
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
        full_path = self.base_path / path
        try:
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_bytes(content)
        except Exception as e:
            raise CRSError(f"Failed to write file {path}: {e}")
    def is_file(self, path: str) -> bool:
        full_path = self.base_path / path
        return full_path.is_file()
    def exists(self, path: str) -> bool:
        full_path = self.base_path / path
        return full_path.exists()

class EditableOverlayFS(VFS):
    def __init__(self, parent: VFS):
        self.parent = parent
        self.files = {}
        super().__init__(parent.base_path)
    def read(self, path: str) -> bytes:
        if path in self.files:
            return self.files[path]
        return self.parent.read(path)
    def write(self, path: str, content: bytes) -> None:
        self.files[path] = content
    def is_file(self, path: str) -> bool:
        if path in self.files:
            return True
        return self.parent.is_file(path)
    def exists(self, path: str) -> bool:
        if path in self.files:
            return True
        return self.parent.exists(path)
    def commit(self) -> None:
        for path, content in self.files.items():
            self.parent.write(path, content)
        self.files.clear()
    def rollback(self) -> None:
        self.files.clear()
    def get_modified_files(self) -> List[str]:
        return list(self.files.keys())

class Hunk:
    def __init__(self, relpath: str, elines: list[tuple[EditType, str]], line_number: int):
        self.relpath = relpath
        self.elines = elines
        self.line_number = line_number

def is_file_header(line: str) -> bool:
    return line.startswith("--- ") or line.startswith("+++ ")

def parse_hunks(relpath: str, patch: str) -> list[Hunk]:
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
    if new_line == NEW_SENTINEL:
        return Ok(None)
    orig_l = orig_line.strip() if orig_line else ""
    new_l = new_line.strip() if new_line else ""
    other = {"{": "}", "}": "{", "(": ")", ")": "("}
    for char in "}{)(":
        orig_count = orig_l.count(char)
        new_count = new_l.count(char)
        change = "inserted" if new_count > orig_count else "removed"
        if orig_count != new_count:
            if orig_line is not None and new_line is not None:
                return Err(CRSError(
                    f"The patch context lines have introduced a typographic error. The context you provided {change} `{char}`.",
                    extra={"original_line": orig_l, "provided_line": new_l}
                ))
            elif orig_line is None:
                if new_l.count(other[char]) == new_count:
                    continue
                return Err(CRSError(f"Unmatched {char} in new line: {new_l}"))
    return Ok(None)

class SimpleMatcher:
    def align(self, orig_lines: List[str], hunk_lines: List[str], start_line: int) -> List[Tuple[Optional[int], Optional[int]]]:
        alignment = []
        orig_idx = max(0, start_line - 1)
        hunk_idx = 0
        while hunk_idx < len(hunk_lines) and orig_idx < len(orig_lines):
            hunk_line = hunk_lines[hunk_idx]
            if hunk_line == NEW_SENTINEL:
                alignment.append((None, hunk_idx)); hunk_idx += 1; continue
            if hunk_line.startswith(" "):
                context_content = hunk_line[1:]
                if orig_idx < len(orig_lines) and orig_lines[orig_idx].strip() == context_content.strip():
                    alignment.append((orig_idx, hunk_idx)); orig_idx += 1; hunk_idx += 1; continue
                found = False
                for search_range in range(1, min(10, len(orig_lines) - orig_idx)):
                    if orig_idx + search_range < len(orig_lines):
                        if orig_lines[orig_idx + search_range].strip() == context_content.strip():
                            for i in range(orig_idx, orig_idx + search_range):
                                alignment.append((i, None))
                            alignment.append((orig_idx + search_range, hunk_idx))
                            orig_idx = orig_idx + search_range + 1
                            hunk_idx += 1
                            found = True
                            break
                if not found:
                    alignment.append((None, hunk_idx)); hunk_idx += 1; continue
            else:
                if orig_idx < len(orig_lines):
                    alignment.append((orig_idx, hunk_idx)); orig_idx += 1; hunk_idx += 1
                else:
                    alignment.append((None, hunk_idx)); hunk_idx += 1
        while hunk_idx < len(hunk_lines):
            alignment.append((None, hunk_idx)); hunk_idx += 1
        return alignment

def apply_hunk(vfs: VFS, hunk: Hunk) -> Result[Edit]:
    orig_bytes = vfs.read(hunk.relpath)
    orig_lines = orig_bytes.decode(errors="replace").splitlines()
    hunk_lines = []
    for edit_type, content in hunk.elines:
        if edit_type == '+':
            hunk_lines.append(NEW_SENTINEL)
        else:
            hunk_lines.append(content)
    if len(orig_lines) == 0:
        arange = [(None, i) for i in range(len(hunk_lines))]
    else:
        matcher = SimpleMatcher()
        arange = matcher.align(orig_lines, hunk_lines, hunk.line_number)
    for orig_idx, hunk_idx in arange:
        require(check_fuzzy_match(
            orig_lines[orig_idx] if orig_idx is not None else None,
            hunk_lines[hunk_idx] if hunk_idx is not None else None,
        ))
    orig_lines_bytes = orig_bytes.splitlines(keepends=True)
    new_lines = orig_lines_bytes[0:arange[0][0]] if arange and arange[0][0] is not None else []
    last_orig_line = -1
    for orig_line, patch_line in arange:
        if orig_line is not None:
            last_orig_line = orig_line
            if patch_line is not None and hunk.elines[patch_line][0] == '-':
                continue
            new_lines.append(orig_lines_bytes[orig_line])
        elif patch_line is not None:
            new_lines.append(hunk.elines[patch_line][1].encode() + b"\n")
    if last_orig_line == -1 and len(orig_lines) > 0:
        return Err(CRSError('no good match found, please add more context lines'))
    new_lines += orig_lines_bytes[last_orig_line + 1:]
    new_content = b"".join(new_lines)
    edit = apply_as_edit(vfs, hunk.relpath, new_content)
    return Ok(edit)

def apply_as_edit(vfs: VFS, relpath: str, new_content: bytes) -> Edit:
    old_content = vfs.read(relpath)
    vfs.write(relpath, new_content)
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    lines = (0, len(new_lines))
    old_lines_range = (0, len(old_lines))
    before = old_lines
    after = new_lines
    return Edit(relpath, lines, old_lines_range, before, after)

def virtual_diff(path: str, a: bytes, b: bytes) -> Result[str]:
    try:
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='_a') as tmp_a:
            tmp_a.write(a)
            tmp_a_path = tmp_a.name
        try:
            result = subprocess.run([
                'diff', '-u',
                '--label', f'a/{path}', tmp_a_path,
                '--label', f'b/{path}', '-'
            ], input=b, capture_output=True, text=False, check=False)
            if result.returncode > 1:
                return Err(CRSError(f"diff command error: {result.stderr.decode(errors='replace')}"))
            return Ok(result.stdout.decode(errors="replace"))
        finally:
            os.unlink(tmp_a_path)
    except Exception as e:
        return Err(CRSError(f"Failed to generate diff: {e}"))

def fuzzy_patch(vfs: VFS, path: str, patch: str) -> Result[tuple]:
    path = os.path.normpath(path)
    patch = require(cleanup_patch(patch))
    hunks = parse_hunks(path, patch)
    patch_vfs = EditableOverlayFS(vfs)
    edits: list[Edit] = []
    for i, hunk in enumerate(hunks):
        match apply_hunk(patch_vfs, hunk):
            case Ok(edit): 
                edits.append(edit)
            case Err(err):
                return Err(CRSError(
                    f"Error in hunk index {i} (line {hunk.line_number}): {err.message}", 
                    extra=err.extra
                ))
    patch_chunks: list[str] = []
    for path, content in patch_vfs.files.items():
        ref = vfs.read(path)
        vdiff = require(virtual_diff(path, ref, content))
        patch_chunks.append(vdiff)
        vfs.write(path, content)
    diff_patch = "\n".join(patch_chunks)
    return Ok((diff_patch, edits))


