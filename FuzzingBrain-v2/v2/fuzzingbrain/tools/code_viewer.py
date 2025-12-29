"""
Code Viewer Tools

Tools for AI Agent to view source code, diffs, and search code.
These tools operate directly on the workspace filesystem.

Usage:
    # Set workspace context first
    set_code_viewer_context("/path/to/workspace")

    # Then use tools
    get_diff()  # Read the diff file
    get_file_content("src/main.c")  # Read a file from repo
    search_code("malloc")  # Search for patterns in repo
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from . import tools_mcp


# Global context for code viewer tools
_workspace_path: Optional[Path] = None
_repo_path: Optional[Path] = None
_diff_path: Optional[Path] = None


def set_code_viewer_context(
    workspace_path: str,
    repo_subdir: str = "repo",
    diff_filename: str = "diff.patch",
) -> None:
    """
    Set the context for code viewer tools.

    Args:
        workspace_path: Path to the workspace directory
        repo_subdir: Subdirectory name for the repo (default: "repo")
        diff_filename: Name of the diff file (default: "diff.patch")
    """
    global _workspace_path, _repo_path, _diff_path
    _workspace_path = Path(workspace_path)
    _repo_path = _workspace_path / repo_subdir
    _diff_path = _workspace_path / diff_filename


def get_code_viewer_context() -> Dict[str, Optional[str]]:
    """Get the current code viewer context."""
    return {
        "workspace_path": str(_workspace_path) if _workspace_path else None,
        "repo_path": str(_repo_path) if _repo_path else None,
        "diff_path": str(_diff_path) if _diff_path else None,
    }


def _ensure_context() -> Optional[Dict[str, Any]]:
    """Ensure context is set, return error dict if not."""
    if _workspace_path is None:
        return {
            "success": False,
            "error": "Code viewer context not set. Call set_code_viewer_context() first.",
        }
    if not _workspace_path.exists():
        return {
            "success": False,
            "error": f"Workspace path does not exist: {_workspace_path}",
        }
    return None


# =============================================================================
# Diff Tools
# =============================================================================

@tools_mcp.tool
def get_diff() -> Dict[str, Any]:
    """
    Read the diff file for the current task.

    Returns the git diff/patch content showing what code changes were made.
    This is essential for delta-scan mode to understand what was modified.

    Returns:
        Dict with 'content' containing the diff text, or 'error' if failed.
    """
    err = _ensure_context()
    if err:
        return err

    if _diff_path is None or not _diff_path.exists():
        return {
            "success": False,
            "error": f"Diff file not found: {_diff_path}",
        }

    try:
        content = _diff_path.read_text(encoding='utf-8', errors='replace')
        return {
            "success": True,
            "content": content,
            "path": str(_diff_path),
            "size": len(content),
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to read diff file: {e}",
        }


def get_diff_impl() -> Dict[str, Any]:
    """Direct call version of get_diff (bypasses MCP FunctionTool wrapper)."""
    err = _ensure_context()
    if err:
        return err

    if _diff_path is None or not _diff_path.exists():
        return {
            "success": False,
            "error": f"Diff file not found: {_diff_path}",
        }

    try:
        content = _diff_path.read_text(encoding='utf-8', errors='replace')
        return {
            "success": True,
            "content": content,
            "path": str(_diff_path),
            "size": len(content),
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to read diff file: {e}",
        }


# =============================================================================
# File Content Tools
# =============================================================================

@tools_mcp.tool
def get_file_content(
    file_path: str,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Read the content of a file from the repository.

    Args:
        file_path: Relative path to the file within the repo
                   (e.g., "src/png.c", "include/pngconf.h")
        start_line: Optional starting line number (1-indexed)
        end_line: Optional ending line number (1-indexed, inclusive)

    Returns:
        Dict with 'content' containing the file text,
        'lines' containing line count, or 'error' if failed.

    Example:
        get_file_content("src/png.c")  # Read entire file
        get_file_content("src/png.c", 100, 150)  # Read lines 100-150
    """
    err = _ensure_context()
    if err:
        return err

    if _repo_path is None or not _repo_path.exists():
        return {
            "success": False,
            "error": f"Repo path does not exist: {_repo_path}",
        }

    # Handle both absolute and relative paths
    target_path = Path(file_path)
    if target_path.is_absolute():
        full_path = target_path
    else:
        full_path = _repo_path / file_path

    if not full_path.exists():
        return {
            "success": False,
            "error": f"File not found: {file_path}",
        }

    if not full_path.is_file():
        return {
            "success": False,
            "error": f"Path is not a file: {file_path}",
        }

    # Security check: ensure file is within workspace
    try:
        full_path.resolve().relative_to(_workspace_path.resolve())
    except ValueError:
        return {
            "success": False,
            "error": f"Access denied: file is outside workspace",
        }

    try:
        with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()

        total_lines = len(lines)

        # Apply line range if specified
        if start_line is not None or end_line is not None:
            start_idx = (start_line - 1) if start_line else 0
            end_idx = end_line if end_line else total_lines

            # Clamp to valid range
            start_idx = max(0, start_idx)
            end_idx = min(total_lines, end_idx)

            selected_lines = lines[start_idx:end_idx]
            content = "".join(selected_lines)

            return {
                "success": True,
                "content": content,
                "path": str(full_path.relative_to(_repo_path)),
                "total_lines": total_lines,
                "start_line": start_idx + 1,
                "end_line": end_idx,
                "lines_returned": len(selected_lines),
            }
        else:
            content = "".join(lines)
            return {
                "success": True,
                "content": content,
                "path": str(full_path.relative_to(_repo_path)),
                "total_lines": total_lines,
            }

    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to read file: {e}",
        }


def get_file_content_impl(
    file_path: str,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
) -> Dict[str, Any]:
    """Direct call version of get_file_content (bypasses MCP FunctionTool wrapper)."""
    err = _ensure_context()
    if err:
        return err

    if _repo_path is None or not _repo_path.exists():
        return {
            "success": False,
            "error": f"Repo path does not exist: {_repo_path}",
        }

    # Handle both absolute and relative paths
    target_path = Path(file_path)
    if target_path.is_absolute():
        full_path = target_path
    else:
        full_path = _repo_path / file_path

    if not full_path.exists():
        return {
            "success": False,
            "error": f"File not found: {file_path}",
        }

    if not full_path.is_file():
        return {
            "success": False,
            "error": f"Path is not a file: {file_path}",
        }

    # Security check: ensure file is within workspace
    try:
        full_path.resolve().relative_to(_workspace_path.resolve())
    except ValueError:
        return {
            "success": False,
            "error": f"Access denied: file is outside workspace",
        }

    try:
        with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()

        total_lines = len(lines)

        if start_line is not None or end_line is not None:
            start_idx = (start_line - 1) if start_line else 0
            end_idx = end_line if end_line else total_lines
            start_idx = max(0, start_idx)
            end_idx = min(total_lines, end_idx)
            selected_lines = lines[start_idx:end_idx]
            content = "".join(selected_lines)

            return {
                "success": True,
                "content": content,
                "path": str(full_path.relative_to(_repo_path)),
                "total_lines": total_lines,
                "start_line": start_idx + 1,
                "end_line": end_idx,
                "lines_returned": len(selected_lines),
            }
        else:
            content = "".join(lines)
            return {
                "success": True,
                "content": content,
                "path": str(full_path.relative_to(_repo_path)),
                "total_lines": total_lines,
            }

    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to read file: {e}",
        }


# =============================================================================
# Code Search Tools
# =============================================================================

@tools_mcp.tool
def search_code(
    pattern: str,
    file_pattern: Optional[str] = None,
    max_results: int = 50,
    context_lines: int = 2,
) -> Dict[str, Any]:
    """
    Search for a pattern in the repository source code.

    Uses grep/ripgrep to find matches across the codebase.

    Args:
        pattern: Search pattern (supports regex)
                 Example: "malloc\\s*\\(" for malloc calls
                 Example: "buffer_overflow" for literal string
        file_pattern: Optional glob pattern to filter files
                      Example: "*.c" for C files only
                      Example: "src/*.h" for headers in src/
        max_results: Maximum number of matches to return (default: 50)
        context_lines: Number of context lines around matches (default: 2)

    Returns:
        Dict with 'matches' containing list of match results,
        each with 'file', 'line', 'content', and 'context'.

    Example:
        search_code("memcpy")  # Find all memcpy calls
        search_code("TODO|FIXME", "*.c")  # Find TODO/FIXME in C files
    """
    err = _ensure_context()
    if err:
        return err

    if _repo_path is None or not _repo_path.exists():
        return {
            "success": False,
            "error": f"Repo path does not exist: {_repo_path}",
        }

    try:
        # Build grep command
        # Try ripgrep first, fallback to grep
        cmd = []

        # Check for ripgrep
        rg_available = subprocess.run(
            ["which", "rg"],
            capture_output=True,
        ).returncode == 0

        if rg_available:
            cmd = [
                "rg",
                "--no-heading",
                "--line-number",
                "--color=never",
                f"--context={context_lines}",
                f"--max-count={max_results}",
            ]
            if file_pattern:
                cmd.extend(["--glob", file_pattern])
            cmd.append(pattern)
        else:
            # Fallback to grep
            cmd = [
                "grep",
                "-rn",
                f"-C{context_lines}",
                f"-m{max_results}",
                "-E",  # Extended regex
            ]
            if file_pattern:
                cmd.extend(["--include", file_pattern])
            cmd.append(pattern)
            cmd.append(".")

        result = subprocess.run(
            cmd,
            cwd=str(_repo_path),
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Parse results
        matches = []
        current_match = None
        context_before = []

        for line in result.stdout.split('\n'):
            if not line.strip():
                if current_match:
                    matches.append(current_match)
                    current_match = None
                    context_before = []
                continue

            # Parse line format: file:line:content or file-line-content (context)
            # ripgrep: file:line:content (match) or file-line-content (context)
            match = re.match(r'^([^:]+):(\d+)[:-](.*)$', line)
            if match:
                file_path, line_no, content = match.groups()
                is_match_line = ':' in line[:len(file_path)+len(line_no)+2]

                if is_match_line or current_match is None:
                    if current_match:
                        matches.append(current_match)

                    current_match = {
                        "file": file_path,
                        "line": int(line_no),
                        "content": content.strip(),
                        "context": context_before + [content.strip()],
                    }
                    context_before = []
                else:
                    # Context line
                    if current_match:
                        current_match["context"].append(content.strip())
                    else:
                        context_before.append(content.strip())

        if current_match:
            matches.append(current_match)

        # Limit results
        matches = matches[:max_results]

        return {
            "success": True,
            "pattern": pattern,
            "file_pattern": file_pattern,
            "matches": matches,
            "count": len(matches),
            "truncated": len(matches) >= max_results,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Search timed out (60s limit)",
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Search failed: {e}",
        }


def search_code_impl(
    pattern: str,
    file_pattern: Optional[str] = None,
    max_results: int = 50,
    context_lines: int = 2,
) -> Dict[str, Any]:
    """Direct call version of search_code (bypasses MCP FunctionTool wrapper)."""
    err = _ensure_context()
    if err:
        return err

    if _repo_path is None or not _repo_path.exists():
        return {
            "success": False,
            "error": f"Repo path does not exist: {_repo_path}",
        }

    try:
        cmd = []
        rg_available = subprocess.run(
            ["which", "rg"],
            capture_output=True,
        ).returncode == 0

        if rg_available:
            cmd = [
                "rg",
                "--no-heading",
                "--line-number",
                "--color=never",
                f"--context={context_lines}",
                f"--max-count={max_results}",
            ]
            if file_pattern:
                cmd.extend(["--glob", file_pattern])
            cmd.append(pattern)
        else:
            cmd = [
                "grep",
                "-rn",
                f"-C{context_lines}",
                f"-m{max_results}",
                "-E",
            ]
            if file_pattern:
                cmd.extend(["--include", file_pattern])
            cmd.append(pattern)
            cmd.append(".")

        result = subprocess.run(
            cmd,
            cwd=str(_repo_path),
            capture_output=True,
            text=True,
            timeout=60,
        )

        matches = []
        current_match = None
        context_before = []

        for line in result.stdout.split('\n'):
            if not line.strip():
                if current_match:
                    matches.append(current_match)
                    current_match = None
                    context_before = []
                continue

            match = re.match(r'^([^:]+):(\d+)[:-](.*)$', line)
            if match:
                file_path, line_no, content = match.groups()
                is_match_line = ':' in line[:len(file_path)+len(line_no)+2]

                if is_match_line or current_match is None:
                    if current_match:
                        matches.append(current_match)

                    current_match = {
                        "file": file_path,
                        "line": int(line_no),
                        "content": content.strip(),
                        "context": context_before + [content.strip()],
                    }
                    context_before = []
                else:
                    if current_match:
                        current_match["context"].append(content.strip())
                    else:
                        context_before.append(content.strip())

        if current_match:
            matches.append(current_match)

        matches = matches[:max_results]

        return {
            "success": True,
            "pattern": pattern,
            "file_pattern": file_pattern,
            "matches": matches,
            "count": len(matches),
            "truncated": len(matches) >= max_results,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Search timed out (60s limit)",
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Search failed: {e}",
        }


# =============================================================================
# List Files Tool
# =============================================================================

@tools_mcp.tool
def list_files(
    directory: str = "",
    pattern: Optional[str] = None,
    recursive: bool = False,
) -> Dict[str, Any]:
    """
    List files in the repository.

    Args:
        directory: Subdirectory to list (relative to repo root, default: root)
        pattern: Optional glob pattern to filter files (e.g., "*.c", "*.h")
        recursive: If True, list files recursively

    Returns:
        Dict with 'files' containing list of file paths.

    Example:
        list_files()  # List root directory
        list_files("src")  # List src/ directory
        list_files("src", "*.c", recursive=True)  # Find all C files in src/
    """
    err = _ensure_context()
    if err:
        return err

    if _repo_path is None or not _repo_path.exists():
        return {
            "success": False,
            "error": f"Repo path does not exist: {_repo_path}",
        }

    target_dir = _repo_path / directory if directory else _repo_path

    if not target_dir.exists():
        return {
            "success": False,
            "error": f"Directory not found: {directory}",
        }

    if not target_dir.is_dir():
        return {
            "success": False,
            "error": f"Path is not a directory: {directory}",
        }

    try:
        files = []
        dirs = []

        if recursive and pattern:
            # Use glob for recursive pattern matching
            for path in target_dir.rglob(pattern):
                if path.is_file():
                    rel_path = str(path.relative_to(_repo_path))
                    files.append(rel_path)
        elif recursive:
            for path in target_dir.rglob("*"):
                rel_path = str(path.relative_to(_repo_path))
                if path.is_file():
                    files.append(rel_path)
                elif path.is_dir():
                    dirs.append(rel_path + "/")
        elif pattern:
            for path in target_dir.glob(pattern):
                if path.is_file():
                    rel_path = str(path.relative_to(_repo_path))
                    files.append(rel_path)
        else:
            for path in target_dir.iterdir():
                rel_path = str(path.relative_to(_repo_path))
                if path.is_file():
                    files.append(rel_path)
                elif path.is_dir():
                    dirs.append(rel_path + "/")

        # Sort for consistent output
        files.sort()
        dirs.sort()

        return {
            "success": True,
            "directory": directory or ".",
            "files": files,
            "directories": dirs,
            "file_count": len(files),
            "dir_count": len(dirs),
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to list files: {e}",
        }


def list_files_impl(
    directory: str = "",
    pattern: Optional[str] = None,
    recursive: bool = False,
) -> Dict[str, Any]:
    """Direct call version of list_files (bypasses MCP FunctionTool wrapper)."""
    err = _ensure_context()
    if err:
        return err

    if _repo_path is None or not _repo_path.exists():
        return {
            "success": False,
            "error": f"Repo path does not exist: {_repo_path}",
        }

    target_dir = _repo_path / directory if directory else _repo_path

    if not target_dir.exists():
        return {
            "success": False,
            "error": f"Directory not found: {directory}",
        }

    if not target_dir.is_dir():
        return {
            "success": False,
            "error": f"Path is not a directory: {directory}",
        }

    try:
        files = []
        dirs = []

        if recursive and pattern:
            for path in target_dir.rglob(pattern):
                if path.is_file():
                    rel_path = str(path.relative_to(_repo_path))
                    files.append(rel_path)
        elif recursive:
            for path in target_dir.rglob("*"):
                rel_path = str(path.relative_to(_repo_path))
                if path.is_file():
                    files.append(rel_path)
                elif path.is_dir():
                    dirs.append(rel_path + "/")
        elif pattern:
            for path in target_dir.glob(pattern):
                if path.is_file():
                    rel_path = str(path.relative_to(_repo_path))
                    files.append(rel_path)
        else:
            for path in target_dir.iterdir():
                rel_path = str(path.relative_to(_repo_path))
                if path.is_file():
                    files.append(rel_path)
                elif path.is_dir():
                    dirs.append(rel_path + "/")

        files.sort()
        dirs.sort()

        return {
            "success": True,
            "directory": directory or ".",
            "files": files,
            "directories": dirs,
            "file_count": len(files),
            "dir_count": len(dirs),
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to list files: {e}",
        }


# =============================================================================
# Tool definitions for LLM function calling
# =============================================================================

CODE_VIEWER_TOOLS = [
    {
        "name": "get_diff",
        "description": "Read the diff/patch file for the current task. Essential for delta-scan mode to understand what code changes were made.",
        "parameters": {
            "type": "object",
            "properties": {},
        }
    },
    {
        "name": "get_file_content",
        "description": "Read the content of a file from the repository. Can read entire file or specific line range.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Relative path to the file within the repo (e.g., 'src/png.c')"
                },
                "start_line": {
                    "type": "integer",
                    "description": "Optional starting line number (1-indexed)"
                },
                "end_line": {
                    "type": "integer",
                    "description": "Optional ending line number (1-indexed, inclusive)"
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "search_code",
        "description": "Search for a pattern in the repository source code using grep/ripgrep. Supports regex patterns.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Search pattern (supports regex)"
                },
                "file_pattern": {
                    "type": "string",
                    "description": "Optional glob pattern to filter files (e.g., '*.c' for C files)"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of matches to return (default: 50)"
                },
                "context_lines": {
                    "type": "integer",
                    "description": "Number of context lines around matches (default: 2)"
                }
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "list_files",
        "description": "List files in the repository directory. Can filter by pattern and search recursively.",
        "parameters": {
            "type": "object",
            "properties": {
                "directory": {
                    "type": "string",
                    "description": "Subdirectory to list (relative to repo root, default: root)"
                },
                "pattern": {
                    "type": "string",
                    "description": "Optional glob pattern to filter files (e.g., '*.c', '*.h')"
                },
                "recursive": {
                    "type": "boolean",
                    "description": "If true, list files recursively"
                }
            }
        }
    }
]


__all__ = [
    # Context
    "set_code_viewer_context",
    "get_code_viewer_context",
    # MCP Tools
    "get_diff",
    "get_file_content",
    "search_code",
    "list_files",
    # Direct-call functions
    "get_diff_impl",
    "get_file_content_impl",
    "search_code_impl",
    "list_files_impl",
    # Tool definitions for LLM
    "CODE_VIEWER_TOOLS",
]
