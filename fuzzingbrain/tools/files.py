# SPDX-License-Identifier: Apache-2.0
"""
File tools: Read, Grep, Glob.

Three primitives for reading a checked-out source tree. They depend on nothing
but the filesystem -- no build, no call graph, no database -- so an agent keeps
them when the introspector build fails or when a run is deliberately scoped to
analysis only.

Names and parameter shapes follow the Claude Code tools of the same names, so a
model does not have to learn a second convention. Three deliberate differences:

- Paths are workspace-relative, not absolute. Agents never see host paths, and
  every path is resolved and checked to land inside the task workspace.
- ``Glob`` sorts by path, not by modification time. Analysis runs should give the
  same answer twice.
- ``.aixcc`` and ``.git`` are refused. Workspace preparation is what actually
  removes them; this is the second line.

Context comes from :func:`set_code_viewer_context`, shared with the older code
viewer tools, so callers set it once.
"""

import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from .code_viewer import _ensure_context, _repo_path, _workspace_path

__all__ = [
    "read_file_impl",
    "grep_impl",
    "glob_impl",
    "FILE_TOOLS",
]


# Paths an agent must never read, whatever the mode. Workspace preparation
# deletes .aixcc outright -- an answer file naming the CWE, the file and the
# line is not something to leave to a deny-list -- and remove_git deletes .git.
# This check stands in case either step is skipped or a new caller appears.
_DENIED_PARTS = {".aixcc", ".git"}

_READ_DEFAULT_LIMIT = 2000
_READ_MAX_LIMIT = 5000
_LINE_CLIP = 2000
_GREP_DEFAULT_HEAD = 50
_GLOB_DEFAULT_HEAD = 1000
_BINARY_SNIFF = 8192


def _err(message: str, **extra: Any) -> Dict[str, Any]:
    out = {"success": False, "error": message}
    out.update(extra)
    return out


def _root() -> Path:
    """The directory agent paths are relative to: the repo checkout."""
    repo = _repo_path.get()
    if repo is not None and repo.exists():
        return repo
    return _workspace_path.get()


def _resolve(rel_path: str) -> Path | Dict[str, Any]:
    """Resolve an agent-supplied path, or return an error dict.

    Rejects absolute paths, traversal out of the workspace, and denied
    directories. ``Path.resolve`` follows symlinks first, so a link inside the
    repo pointing at the host filesystem is caught here too.
    """
    if not rel_path or not str(rel_path).strip():
        return _err("path is required")

    candidate = Path(rel_path)
    if candidate.is_absolute():
        return _err(
            f"Path must be relative to the repository root, got an absolute path: {rel_path}"
        )

    root = _root()
    if root is None:
        return _err("Workspace context is not set")

    full = (root / candidate).resolve()
    workspace = _workspace_path.get().resolve()

    try:
        full.relative_to(workspace)
    except ValueError:
        return _err(f"Path resolves outside the workspace: {rel_path}")

    try:
        parts = set(full.relative_to(workspace).parts)
    except ValueError:  # pragma: no cover - guarded above
        parts = set()
    denied = parts & _DENIED_PARTS
    if denied:
        return _err(
            f"Path is not readable in this run: {rel_path} "
            f"(contains {sorted(denied)[0]})"
        )

    return full


def _is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"\0" in fh.read(_BINARY_SNIFF)
    except OSError:
        return False


def _rel(path: Path) -> str:
    root = _root()
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# =============================================================================
# Read
# =============================================================================


def read_file_impl(
    file_path: str,
    offset: int = 1,
    limit: int = _READ_DEFAULT_LIMIT,
) -> Dict[str, Any]:
    """Read a file and return numbered lines."""
    err = _ensure_context()
    if err:
        return err

    resolved = _resolve(file_path)
    if isinstance(resolved, dict):
        return resolved

    if not resolved.exists():
        return _err(f"File not found: {file_path}")
    if resolved.is_dir():
        return _err(f"That path is a directory, not a file: {file_path}")
    if _is_binary(resolved):
        return _err(
            f"File looks binary, so reading it as text would be meaningless: {file_path}"
        )

    try:
        offset = max(1, int(offset))
    except (TypeError, ValueError):
        offset = 1
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = _READ_DEFAULT_LIMIT
    limit = max(1, min(limit, _READ_MAX_LIMIT))

    try:
        with open(resolved, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        return _err(f"Could not read {file_path}: {exc}")

    total = len(lines)
    if offset > total and total:
        return _err(
            f"offset {offset} is past the end of {file_path}, which has {total} lines"
        )

    window = lines[offset - 1 : offset - 1 + limit]
    width = len(str(offset + len(window) - 1)) if window else 1
    rendered = "\n".join(
        f"{str(offset + i).rjust(width)}\t{line[:_LINE_CLIP]}"
        for i, line in enumerate(window)
    )

    last = offset + len(window) - 1
    truncated = last < total
    if truncated:
        rendered += (
            f"\n\n... showing lines {offset}-{last} of {total}. "
            f"Call Read again with offset={last + 1} for more."
        )

    return {
        "success": True,
        "file_path": _rel(resolved),
        "content": rendered,
        "start_line": offset,
        "end_line": last,
        "total_lines": total,
        "truncated": truncated,
    }


# =============================================================================
# Grep
# =============================================================================


def _rg_available() -> bool:
    try:
        return (
            subprocess.run(["which", "rg"], capture_output=True, timeout=10).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


def grep_impl(
    pattern: str,
    glob: Optional[str] = None,
    output_mode: str = "content",
    context_lines: int = 0,
    before_context: int = 0,
    after_context: int = 0,
    head_limit: int = _GREP_DEFAULT_HEAD,
    case_insensitive: bool = False,
    multiline: bool = False,
) -> Dict[str, Any]:
    """Search file contents by regular expression."""
    err = _ensure_context()
    if err:
        return err

    if not pattern:
        return _err("pattern is required")

    modes = {"content", "files_with_matches", "count"}
    if output_mode not in modes:
        return _err(f"output_mode must be one of {sorted(modes)}, got {output_mode!r}")

    root = _root()
    if root is None or not root.exists():
        return _err("Workspace context is not set")

    if not _rg_available():
        return _err("ripgrep (rg) is not installed, so content search is unavailable")

    try:
        head_limit = max(1, int(head_limit))
    except (TypeError, ValueError):
        head_limit = _GREP_DEFAULT_HEAD

    cmd: List[str] = ["rg", "--color=never", "--no-messages"]
    for part in sorted(_DENIED_PARTS):
        cmd += ["--glob", f"!{part}", "--glob", f"!{part}/**"]
    if glob:
        cmd += ["--glob", glob]
    if case_insensitive:
        cmd.append("-i")
    if multiline:
        cmd += ["--multiline", "--multiline-dotall"]

    if output_mode == "files_with_matches":
        cmd.append("--files-with-matches")
    elif output_mode == "count":
        cmd.append("--count-matches")
    else:
        cmd += ["--line-number", "--no-heading", "--with-filename"]
        before = before_context or context_lines
        after = after_context or context_lines
        if before:
            cmd += ["--before-context", str(int(before))]
        if after:
            cmd += ["--after-context", str(int(after))]

    cmd += ["--regexp", pattern, "."]

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return _err(f"Search timed out after 120s for pattern: {pattern}")
    except OSError as exc:
        return _err(f"Could not run ripgrep: {exc}")

    # rg exits 1 when there are simply no matches; only >1 is a real failure.
    if proc.returncode > 1:
        detail = (proc.stderr or "").strip().splitlines()
        return _err(
            "ripgrep failed: " + (detail[0] if detail else f"exit {proc.returncode}")
        )

    raw = [line for line in proc.stdout.split("\n") if line.strip()]

    if output_mode == "files_with_matches":
        files = [line.lstrip("./") for line in raw]
        return {
            "success": True,
            "pattern": pattern,
            "output_mode": output_mode,
            "files": files[:head_limit],
            "count": len(files),
            "truncated": len(files) > head_limit,
        }

    if output_mode == "count":
        counts = []
        for line in raw:
            path, _, num = line.rpartition(":")
            if path and num.isdigit():
                counts.append({"file": path.lstrip("./"), "count": int(num)})
        counts.sort(key=lambda c: (-c["count"], c["file"]))
        total = sum(c["count"] for c in counts)
        return {
            "success": True,
            "pattern": pattern,
            "output_mode": output_mode,
            "counts": counts[:head_limit],
            "files_with_matches": len(counts),
            "total_matches": total,
            "truncated": len(counts) > head_limit,
        }

    # content mode. rg separates a matching line from its path and number with
    # ':' and a context line with '-'; both forms have to parse, which is what
    # the previous implementation got wrong.
    line_re = re.compile(
        r"^(?P<file>.+?)(?P<sep>[:-])(?P<line>\d+)(?P=sep)(?P<text>.*)$"
    )
    matches: List[Dict[str, Any]] = []
    for line in raw:
        if line == "--":
            continue
        m = line_re.match(line)
        if not m:
            continue
        matches.append(
            {
                "file": m.group("file").lstrip("./"),
                "line": int(m.group("line")),
                "text": m.group("text")[:_LINE_CLIP],
                "is_match": m.group("sep") == ":",
            }
        )

    hit_count = sum(1 for m in matches if m["is_match"])
    return {
        "success": True,
        "pattern": pattern,
        "output_mode": output_mode,
        "matches": matches[:head_limit],
        "count": hit_count,
        "truncated": len(matches) > head_limit,
    }


# =============================================================================
# Glob
# =============================================================================


def glob_impl(pattern: str, head_limit: int = _GLOB_DEFAULT_HEAD) -> Dict[str, Any]:
    """Find files by name pattern."""
    err = _ensure_context()
    if err:
        return err

    if not pattern:
        return _err("pattern is required")
    if Path(pattern).is_absolute():
        return _err(f"pattern must be relative to the repository root, got: {pattern}")

    root = _root()
    if root is None or not root.exists():
        return _err("Workspace context is not set")

    try:
        head_limit = max(1, int(head_limit))
    except (TypeError, ValueError):
        head_limit = _GLOB_DEFAULT_HEAD

    try:
        found = [p for p in root.glob(pattern) if p.is_file()]
    except (ValueError, OSError) as exc:
        return _err(f"Invalid pattern {pattern!r}: {exc}")

    files: List[str] = []
    for path in found:
        rel = _rel(path)
        if set(Path(rel).parts) & _DENIED_PARTS:
            continue
        files.append(rel)
    files.sort()

    return {
        "success": True,
        "pattern": pattern,
        "files": files[:head_limit],
        "count": len(files),
        "truncated": len(files) > head_limit,
    }


# Kept for callers that build the LLM tool list directly rather than over MCP.
FILE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "Read",
            "description": (
                "Read a file from the task workspace. Returns numbered lines, so "
                "you can cite an exact location. Use offset and limit to page "
                "through a long file rather than pulling all of it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path relative to the repository root, e.g. 'pngrutil.c'",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "First line to return, 1-indexed (default 1)",
                    },
                    "limit": {
                        "type": "integer",
                        "description": f"How many lines to return (default {_READ_DEFAULT_LIMIT})",
                    },
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "Grep",
            "description": (
                "Search file contents by regular expression. output_mode "
                "'files_with_matches' returns paths only and is the cheapest way "
                "to narrow down; 'content' returns matching lines with numbers; "
                "'count' returns per-file totals."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regular expression to search for",
                    },
                    "glob": {
                        "type": "string",
                        "description": "Restrict to files matching this pattern, e.g. '*.c'",
                    },
                    "output_mode": {
                        "type": "string",
                        "enum": ["content", "files_with_matches", "count"],
                        "description": "What to return (default 'content')",
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "Lines of context on both sides of a match",
                    },
                    "before_context": {
                        "type": "integer",
                        "description": "Lines of context before a match",
                    },
                    "after_context": {
                        "type": "integer",
                        "description": "Lines of context after a match",
                    },
                    "head_limit": {
                        "type": "integer",
                        "description": f"Cap on returned entries (default {_GREP_DEFAULT_HEAD})",
                    },
                    "case_insensitive": {
                        "type": "boolean",
                        "description": "Match case-insensitively",
                    },
                    "multiline": {
                        "type": "boolean",
                        "description": "Let the pattern span line breaks",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "Glob",
            "description": (
                "Find files by name pattern, for example '**/*.c' or "
                "'contrib/oss-fuzz/*'. Returns workspace-relative paths sorted by path."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern relative to the repository root",
                    },
                    "head_limit": {
                        "type": "integer",
                        "description": f"Cap on returned paths (default {_GLOB_DEFAULT_HEAD})",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
]
