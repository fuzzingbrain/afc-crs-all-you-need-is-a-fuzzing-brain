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
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from . import tools_mcp


# =============================================================================
# Context for code viewer tools
# Using ContextVar for async task isolation (each asyncio.Task has its own context)
# =============================================================================

_workspace_path: ContextVar[Optional[Path]] = ContextVar('cv_workspace_path', default=None)
_repo_path: ContextVar[Optional[Path]] = ContextVar('cv_repo_path', default=None)
_diff_path: ContextVar[Optional[Path]] = ContextVar('cv_diff_path', default=None)
_search_paths: ContextVar[List[Path]] = ContextVar('cv_search_paths', default=[])


def set_code_viewer_context(
    workspace_path: str,
    repo_subdir: str = "repo",
    diff_filename: str = "diff.patch",
    project_name: str = "",
) -> None:
    """
    Set the context for code viewer tools.

    Uses ContextVar for proper isolation in async/parallel execution.

    Args:
        workspace_path: Path to the workspace directory
        repo_subdir: Subdirectory name for the repo (default: "repo")
        diff_filename: Name of the diff file (default: "diff.patch")
        project_name: Project name for additional search paths (e.g., "curl")
    """
    ws_path = Path(workspace_path)
    _workspace_path.set(ws_path)
    _repo_path.set(ws_path / repo_subdir)
    _diff_path.set(ws_path / diff_filename)

    # Build search paths list - strict paths only
    search_paths = []

    # 1. Main repo directory (always included)
    repo_path = ws_path / repo_subdir
    if repo_path.exists():
        search_paths.append(repo_path)

    # 2. fuzz-tooling/build/out/ (fuzzer source code, if exists)
    fuzz_build_path = ws_path / "fuzz-tooling" / "build" / "out"
    if fuzz_build_path.exists():
        search_paths.append(fuzz_build_path)

    # 3. fuzz-tooling/projects/{project_name}/ (project-specific fuzzer config, if exists)
    if project_name:
        fuzz_project_path = ws_path / "fuzz-tooling" / "projects" / project_name
        if fuzz_project_path.exists():
            search_paths.append(fuzz_project_path)

    _search_paths.set(search_paths)


def get_code_viewer_context() -> Dict[str, Optional[str]]:
    """Get the current code viewer context."""
    ws = _workspace_path.get()
    repo = _repo_path.get()
    diff = _diff_path.get()
    return {
        "workspace_path": str(ws) if ws else None,
        "repo_path": str(repo) if repo else None,
        "diff_path": str(diff) if diff else None,
    }


def _ensure_context() -> Optional[Dict[str, Any]]:
    """Ensure context is set, return error dict if not."""
    ws = _workspace_path.get()
    if ws is None:
        return {
            "success": False,
            "error": "Code viewer context not set. Call set_code_viewer_context() first.",
        }
    if not ws.exists():
        return {
            "success": False,
            "error": f"Workspace path does not exist: {ws}",
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

    diff_path = _diff_path.get()
    if diff_path is None or not diff_path.exists():
        return {
            "success": False,
            "error": f"Diff file not found: {diff_path}",
        }

    try:
        content = diff_path.read_text(encoding='utf-8', errors='replace')
        return {
            "success": True,
            "content": content,
            "path": str(diff_path),
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

    diff_path = _diff_path.get()
    if diff_path is None or not diff_path.exists():
        return {
            "success": False,
            "error": f"Diff file not found: {diff_path}",
        }

    try:
        content = diff_path.read_text(encoding='utf-8', errors='replace')
        return {
            "success": True,
            "content": content,
            "path": str(diff_path),
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

    repo_path = _repo_path.get()
    workspace_path = _workspace_path.get()
    if repo_path is None or not repo_path.exists():
        return {
            "success": False,
            "error": f"Repo path does not exist: {repo_path}",
        }

    # Handle both absolute and relative paths
    target_path = Path(file_path)
    if target_path.is_absolute():
        full_path = target_path
    else:
        full_path = repo_path / file_path

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
        full_path.resolve().relative_to(workspace_path.resolve())
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
                "path": str(full_path.relative_to(repo_path)),
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
                "path": str(full_path.relative_to(repo_path)),
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

    repo_path = _repo_path.get()
    workspace_path = _workspace_path.get()
    if repo_path is None or not repo_path.exists():
        return {
            "success": False,
            "error": f"Repo path does not exist: {repo_path}",
        }

    # Handle both absolute and relative paths
    target_path = Path(file_path)
    if target_path.is_absolute():
        full_path = target_path
    else:
        full_path = repo_path / file_path

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
        full_path.resolve().relative_to(workspace_path.resolve())
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
                "path": str(full_path.relative_to(repo_path)),
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
                "path": str(full_path.relative_to(repo_path)),
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

    # Get all search paths
    search_paths = _search_paths.get()
    if not search_paths:
        # Fallback to repo_path only
        repo_path = _repo_path.get()
        if repo_path is None or not repo_path.exists():
            return {
                "success": False,
                "error": f"Repo path does not exist: {repo_path}",
            }
        search_paths = [repo_path]

    try:
        # Check for ripgrep
        rg_available = subprocess.run(
            ["which", "rg"],
            capture_output=True,
        ).returncode == 0

        all_matches = []
        ws_path = _workspace_path.get()

        for search_path in search_paths:
            if not search_path.exists():
                continue

            # Build grep command
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
                cwd=str(search_path),
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=60,
            )

            # Parse results
            current_match = None
            context_before = []

            for line in result.stdout.split('\n'):
                if not line.strip():
                    if current_match:
                        all_matches.append(current_match)
                        current_match = None
                        context_before = []
                    continue

                # Parse line format: file:line:content or file-line-content (context)
                match = re.match(r'^([^:]+):(\d+)[:-](.*)$', line)
                if match:
                    file_path_str, line_no, content = match.groups()
                    is_match_line = ':' in line[:len(file_path_str)+len(line_no)+2]

                    # Make file path relative to workspace for clarity
                    full_file_path = search_path / file_path_str
                    if ws_path and full_file_path.is_relative_to(ws_path):
                        display_path = str(full_file_path.relative_to(ws_path))
                    else:
                        display_path = file_path_str

                    # Truncate very long lines (e.g., minified JSON/JS)
                    MAX_LINE_LEN = 500
                    content_stripped = content.strip()
                    if len(content_stripped) > MAX_LINE_LEN:
                        content_stripped = content_stripped[:MAX_LINE_LEN] + "...[truncated]"

                    if is_match_line or current_match is None:
                        if current_match:
                            all_matches.append(current_match)

                        current_match = {
                            "file": display_path,
                            "line": int(line_no),
                            "content": content_stripped,
                            "context": context_before + [content_stripped],
                        }
                        context_before = []
                    else:
                        # Context line
                        if current_match:
                            current_match["context"].append(content_stripped)
                        else:
                            context_before.append(content_stripped)

            if current_match:
                all_matches.append(current_match)

            # Stop early if we have enough results
            if len(all_matches) >= max_results:
                break

        # Limit results
        all_matches = all_matches[:max_results]

        return {
            "success": True,
            "pattern": pattern,
            "file_pattern": file_pattern,
            "matches": all_matches,
            "count": len(all_matches),
            "truncated": len(all_matches) >= max_results,
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
    """Direct call version of search_code (bypasses MCP FunctionTool wrapper).

    Uses the same multi-path search logic as search_code.
    """
    err = _ensure_context()
    if err:
        return err

    # Get all search paths
    search_paths = _search_paths.get()
    if not search_paths:
        # Fallback to repo_path only
        repo_path = _repo_path.get()
        if repo_path is None or not repo_path.exists():
            return {
                "success": False,
                "error": f"Repo path does not exist: {repo_path}",
            }
        search_paths = [repo_path]

    try:
        rg_available = subprocess.run(
            ["which", "rg"],
            capture_output=True,
        ).returncode == 0

        all_matches = []
        ws_path = _workspace_path.get()

        for search_path in search_paths:
            if not search_path.exists():
                continue

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
                cwd=str(search_path),
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=60,
            )

            current_match = None
            context_before = []

            for line in result.stdout.split('\n'):
                if not line.strip():
                    if current_match:
                        all_matches.append(current_match)
                        current_match = None
                        context_before = []
                    continue

                match = re.match(r'^([^:]+):(\d+)[:-](.*)$', line)
                if match:
                    file_path_str, line_no, content = match.groups()
                    is_match_line = ':' in line[:len(file_path_str)+len(line_no)+2]

                    # Make file path relative to workspace for clarity
                    full_file_path = search_path / file_path_str
                    if ws_path and full_file_path.is_relative_to(ws_path):
                        display_path = str(full_file_path.relative_to(ws_path))
                    else:
                        display_path = file_path_str

                    # Truncate very long lines (e.g., minified JSON/JS)
                    MAX_LINE_LEN = 500
                    content_stripped = content.strip()
                    if len(content_stripped) > MAX_LINE_LEN:
                        content_stripped = content_stripped[:MAX_LINE_LEN] + "...[truncated]"

                    if is_match_line or current_match is None:
                        if current_match:
                            all_matches.append(current_match)

                        current_match = {
                            "file": display_path,
                            "line": int(line_no),
                            "content": content_stripped,
                            "context": context_before + [content_stripped],
                        }
                        context_before = []
                    else:
                        if current_match:
                            current_match["context"].append(content_stripped)
                        else:
                            context_before.append(content_stripped)

            if current_match:
                all_matches.append(current_match)

            # Stop early if we have enough results
            if len(all_matches) >= max_results:
                break

        all_matches = all_matches[:max_results]

        return {
            "success": True,
            "pattern": pattern,
            "file_pattern": file_pattern,
            "matches": all_matches,
            "count": len(all_matches),
            "truncated": len(all_matches) >= max_results,
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

    repo_path = _repo_path.get()
    if repo_path is None or not repo_path.exists():
        return {
            "success": False,
            "error": f"Repo path does not exist: {repo_path}",
        }

    target_dir = repo_path / directory if directory else repo_path

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
                    rel_path = str(path.relative_to(repo_path))
                    files.append(rel_path)
        elif recursive:
            for path in target_dir.rglob("*"):
                rel_path = str(path.relative_to(repo_path))
                if path.is_file():
                    files.append(rel_path)
                elif path.is_dir():
                    dirs.append(rel_path + "/")
        elif pattern:
            for path in target_dir.glob(pattern):
                if path.is_file():
                    rel_path = str(path.relative_to(repo_path))
                    files.append(rel_path)
        else:
            for path in target_dir.iterdir():
                rel_path = str(path.relative_to(repo_path))
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

    repo_path = _repo_path.get()
    if repo_path is None or not repo_path.exists():
        return {
            "success": False,
            "error": f"Repo path does not exist: {repo_path}",
        }

    target_dir = repo_path / directory if directory else repo_path

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
                    rel_path = str(path.relative_to(repo_path))
                    files.append(rel_path)
        elif recursive:
            for path in target_dir.rglob("*"):
                rel_path = str(path.relative_to(repo_path))
                if path.is_file():
                    files.append(rel_path)
                elif path.is_dir():
                    dirs.append(rel_path + "/")
        elif pattern:
            for path in target_dir.glob(pattern):
                if path.is_file():
                    rel_path = str(path.relative_to(repo_path))
                    files.append(rel_path)
        else:
            for path in target_dir.iterdir():
                rel_path = str(path.relative_to(repo_path))
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
