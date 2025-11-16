from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Tuple, List

from shared_tools.editor import Editor, VFS, EditableOverlayFS
from shared_tools.fuzzy_patch import extract_file_path_from_patch
from shared_tools.core import Ok, Err, CRSError, Result

_editors: Dict[str, Editor] = {}

def _get_or_create_editor(source_dir: str | None) -> Editor:
    if not source_dir:
        raise CRSError("source_dir is required for overlay editor")
    key = str(Path(source_dir).resolve())
    ed = _editors.get(key)
    if ed is None:
        base = VFS(key)
        overlay = EditableOverlayFS(base)
        ed = Editor(overlay)
        _editors[key] = ed
    return ed

def _split_unified_diff(diff_text: str) -> List[str]:
    s = diff_text.strip()
    # Split by file headers --- a/... +++ b/...
    parts = re.split(r"(?m)^(?=---\s+a\/)", s)
    return [p.strip() for p in parts if p.strip()]

def apply_unified_diff_overlay(source_dir: str | None, diff_text: str) -> Result[int]:
    try:
        ed = _get_or_create_editor(source_dir)
        blocks = _split_unified_diff(diff_text)
        applied = 0
        for block in blocks:
            rel = extract_file_path_from_patch(block)
            if not rel:
                return Err(CRSError("failed to extract file path from diff block"))
            result = ed.apply_patch(rel, block)
            if isinstance(result, Ok):
                applied += 1
            elif isinstance(result, Err):
                return Err(CRSError(f"overlay apply failed for {rel}: {result.error}", extra=getattr(result, 'extra', None)))
            else:
                return Err(CRSError(f"overlay apply failed for {rel}: unknown result"))
        return Ok(applied)
    except CRSError as e:
        return Err(e)
    except Exception as e:
        return Err(CRSError(f"overlay apply exception: {e}"))

def undo_last_overlay_patch(source_dir: str | None) -> Result[int]:
    try:
        ed = _get_or_create_editor(source_dir)
        return ed.undo_last_patch()
    except CRSError as e:
        return Err(e)
    except Exception as e:
        return Err(CRSError(f"overlay undo exception: {e}"))

def dump_overlay_unified_diff(source_dir: str | None) -> str:
    try:
        ed = _get_or_create_editor(source_dir)
        return ed.dump_unified_diff()
    except Exception:
        return ""


def materialize_overlay_to_dir(source_dir: str | None, dest_dir: str) -> Result[int]:
    """Write overlay-edited files into dest_dir, preserving relative paths."""
    try:
        ed = _get_or_create_editor(source_dir)
        vfs = ed.vfs
        if not isinstance(vfs, EditableOverlayFS):
            return Err(CRSError("overlay not initialized"))
        count = 0
        for rel, content in (vfs.files or {}).items():
            out_path = Path(dest_dir) / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(content)
            count += 1
        return Ok(count)
    except CRSError as e:
        return Err(e)
    except Exception as e:
        return Err(CRSError(f"overlay materialize exception: {e}"))


def undo_n_overlay_patches(source_dir: str | None, n: int) -> Result[int]:
    """Undo up to n overlay patches (LIFO). Returns Ok(applied_count) or Err."""
    if n <= 0:
        return Ok(0)
    try:
        count = 0
        for _ in range(n):
            res = undo_last_overlay_patch(source_dir)
            if isinstance(res, Ok):
                # value could be 0/1 depending on Editor semantics; treat Ok as success
                count += 1
                # If diff empty after undo, stop early
                if not (dump_overlay_unified_diff(source_dir) or "").strip():
                    break
            elif isinstance(res, Err):
                # Stop on error
                return Err(res.error if isinstance(res.error, CRSError) else CRSError(str(res)))
            else:
                break
        return Ok(count)
    except CRSError as e:
        return Err(e)
    except Exception as e:
        return Err(CRSError(f"overlay undo_n exception: {e}"))


def undo_all_overlay_patches(source_dir: str | None, safety_limit: int = 200) -> Result[int]:
    """Undo all overlay patches until no edits remain or safety limit reached."""
    try:
        total = 0
        limit = max(1, safety_limit)
        while total < limit:
            diff = dump_overlay_unified_diff(source_dir)
            if not (diff and diff.strip()):
                break
            res = undo_last_overlay_patch(source_dir)
            if isinstance(res, Ok):
                total += 1
            elif isinstance(res, Err):
                return Err(res.error if isinstance(res.error, CRSError) else CRSError(str(res)))
            else:
                break
        return Ok(total)
    except CRSError as e:
        return Err(e)
    except Exception as e:
        return Err(CRSError(f"overlay undo_all exception: {e}"))

