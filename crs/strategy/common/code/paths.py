"""Path fix-ups for source files inside a patched workspace.

When the patch pipeline copies a project source tree into a sibling
working directory (``foo_patch_1234``) and then rewrites files, the
LLM sometimes returns paths pointing at the *original* tree. These
helpers rewrite such paths to point inside the patched tree.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def fix_patch_file_path(project_src_dir: str, file_path: str) -> str:
    """Return ``file_path`` rewritten so it lives inside ``project_src_dir``.

    If ``file_path`` already starts with ``project_src_dir`` it is
    returned unchanged. Otherwise the function walks up to the common
    ancestor (typically ``.../patch_workspace``), drops the original
    project-dir prefix, and rebuilds the remainder under the patched
    tree. As a fallback it returns ``{project_src_dir}/{basename}``.

    Args:
        project_src_dir: Root of the patched source tree on disk.
        file_path: A path the caller thinks refers to a file inside
            ``project_src_dir`` but which may still reference the
            original (pre-copy) tree.

    Returns:
        A path guaranteed to be under ``project_src_dir``.
    """
    if file_path.startswith(project_src_dir):
        return file_path

    try:
        common_root = os.path.commonpath([project_src_dir, file_path])
        rel_parts = os.path.relpath(file_path, common_root).split(os.sep)

        if len(rel_parts) > 1:
            corrected = os.path.join(project_src_dir, *rel_parts[1:])
        else:
            corrected = os.path.join(project_src_dir, rel_parts[0])

        if os.path.exists(corrected):
            return corrected
        return os.path.join(project_src_dir, os.path.basename(file_path))
    except ValueError as exc:
        # os.path.commonpath raises ValueError when paths have different drives
        logger.debug("fix_patch_file_path fallback for %s: %s", file_path, exc)
        return os.path.join(project_src_dir, os.path.basename(file_path))
