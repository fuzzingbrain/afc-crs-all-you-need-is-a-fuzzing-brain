# SPDX-License-Identifier: Apache-2.0
"""Patch workspace helpers (git init, reset, diff)."""
from __future__ import annotations

import logging
import os
import subprocess
from typing import Any, Dict, Iterable, Optional

logger = logging.getLogger(__name__)

_DEFAULT_COMMIT_EMAIL = "fuzzingbrain@example.com"
_DEFAULT_COMMIT_NAME = "fuzzing brain"


def ensure_patch_workspace_git(project_src_dir: str) -> bool:
    """Initialise ``project_src_dir`` as a git repo with one baseline commit.

    Safe to call repeatedly: a no-op when a ``.git`` directory already
    exists. Used at the top of patch application so that
    :func:`reset_project_source_code` has something to reset to.

    Returns:
        ``True`` on success (or if already initialised), ``False`` if
        any git command failed.
    """
    git_dir = os.path.join(project_src_dir, ".git")
    if os.path.exists(git_dir):
        return True

    logger.info("Initialising patch workspace git repo at %s", project_src_dir)
    try:
        subprocess.run(["git", "init"], cwd=project_src_dir, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", _DEFAULT_COMMIT_EMAIL],
            cwd=project_src_dir, check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", _DEFAULT_COMMIT_NAME],
            cwd=project_src_dir, check=True, capture_output=True,
        )
        subprocess.run(["git", "add", "."], cwd=project_src_dir, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "Initial commit before applying patches"],
            cwd=project_src_dir, check=True, capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.warning("Failed to initialise patch workspace git repo: %s", exc)
        return False
    return True


def reset_project_source_code(project_src_dir: str) -> bool:
    """Run ``git reset --hard HEAD`` in the patch workspace."""
    logger.info("Resetting patch workspace %s to HEAD", project_src_dir)
    try:
        subprocess.run(
            ["git", "reset", "--hard", "HEAD"],
            cwd=project_src_dir,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.error("Failed to reset patch workspace: %s", exc)
        return False
    return True


def generate_diff(
    project_src_dir: str,
    focus: str,
    function_metadata: Optional[Dict[str, Any]],
) -> str:
    """Return ``git diff`` output, optionally restricted to the files in ``function_metadata``.

    When ``function_metadata`` is empty or provides no file paths, this
    returns the full repository diff. When it does provide file paths,
    we run ``git diff -- <rel>`` for each unique file; if none of them
    produce output we still fall back to a full repo diff so the caller
    always gets something meaningful when there are real changes.
    """
    if not function_metadata:
        logger.debug("No function metadata; returning full diff")
        return _git_diff(project_src_dir)

    file_paths = {
        metadata["file_path"]
        for metadata in function_metadata.values()
        if isinstance(metadata, dict) and "file_path" in metadata
    }
    if not file_paths:
        logger.debug("No file paths in metadata; returning full diff")
        return _git_diff(project_src_dir)

    combined: list[str] = []
    processed: set = set()
    for file_path in file_paths:
        rel_path = _normalise_rel_path(file_path, project_src_dir, focus)
        if rel_path in processed:
            continue
        processed.add(rel_path)
        logger.debug("Generating diff for %s", rel_path)
        piece = _git_diff(project_src_dir, rel_path)
        if piece:
            combined.append(piece)

    if combined:
        return "\n".join(combined)

    logger.debug("Per-file diffs empty; falling back to full diff")
    return _git_diff(project_src_dir)


def _git_diff(cwd: str, path: Optional[str] = None) -> str:
    """Run ``git diff`` (optionally scoped to ``path``) and return stdout."""
    cmd = ["git", "diff"]
    if path is not None:
        cmd.extend(["--", path])
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    except (subprocess.SubprocessError, OSError) as exc:
        logger.error("git diff %s failed: %s", path or "(all)", exc)
        return ""
    return result.stdout or ""


def _normalise_rel_path(file_path: str, project_src_dir: str, focus: str) -> str:
    """Turn any ``file_path`` into a repo-relative path anchored at ``project_src_dir``."""
    if os.path.isabs(file_path):
        try:
            rel = os.path.relpath(file_path, project_src_dir)
        except ValueError:
            rel = file_path
    else:
        rel = file_path

    if not os.path.exists(os.path.join(project_src_dir, rel)) and rel.startswith(f"{focus}/"):
        rel = rel[len(focus) + 1:]
    return rel
