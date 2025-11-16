import re
from typing import TypedDict, Optional, NotRequired
from .core import CRSError, Result, Ok, Err, requireable, require
from .fuzzy_patch import fuzzy_patch, cleanup_patch, is_hunk_header, is_edit_line, remove_extra_whitespace
from .fuzzy_patch import Edit, VFS, EditableOverlayFS

HUNK_HEADER_RE = re.compile(r"^@@\s-(\d+),?\d*\s\+(\d+),?\d*\s@@")

def check_file(vfs: VFS, path: str) -> Result[bool]:
    if vfs.is_file(path):
        return Ok(True)
    return Err(CRSError("file not found"))

class Editor:
    Patch = TypedDict('Patch', {
        'edits': list[Edit],
        'path': str,
        'patch': str,
        'desc': NotRequired[str]
    })

    vfs: EditableOverlayFS
    patches: list['Editor.Patch']

    def __init__(self, vfs: Optional[EditableOverlayFS] = None, patches: Optional[list['Editor.Patch']] = None):
        self.vfs = vfs  # type: ignore[assignment]
        self.patches = patches or []

    @property
    def patch_num(self) -> int:
        return len(self.patches)

    @requireable
    def apply(self, relpath: str, patch: str) -> Result[None]:
        if not self.vfs:
            return Err(CRSError("VFS not initialized"))
        require(check_file(self.vfs, relpath))
        _, edits = require(fuzzy_patch(self.vfs, relpath, patch))
        self.patches.append({"edits": edits, "path": relpath, "patch": patch})
        return Ok(None)

    @requireable
    def apply_patch(self, path: str, patch: str) -> Result[dict]:
        ERROR_NOTE = (
            "this patch was not applied and does not need to be undone\n"
            f"there are still {self.patch_num} patches currently applied"
        )
        patch = remove_extra_whitespace(patch)
        lines = patch.splitlines()
        hunks = list(map(is_hunk_header, lines)).count(True)
        if hunks == 0:
            return Err(CRSError(
                "Invalid patch format. Make sure it includes the hunk headers with approximate line numbers, i.e. `@@ -l,s +l,s @@`",
                extra={"note": ERROR_NOTE}
            ))
        edits = list(map(is_edit_line, lines)).count(True)
        if edits == 0:
            return Err(CRSError(
                "Patch contains no changes. Make sure it is in patch format, with + indicating added lines and - indicating removed lines.",
                extra={"note": ERROR_NOTE}
            ))
        match self.apply(path, patch):
            case Ok():
                pass
            case Err(e):
                extra = {"note": ERROR_NOTE}
                if e.extra:
                    extra.update(e.extra)
                return Err(CRSError(f"patch did NOT apply successfully: {e.message}", extra=extra))
        return Ok({
            "note": f"applied to the current list of patches (now have {self.patch_num} patches)\n"
                   "you may want to check that the change compiles successfully before continuing!"
        })

    def rewind_to(self, patch_num: int) -> None:
        if not self.vfs:
            raise CRSError("VFS not initialized")
        for patch in reversed(self.patches[patch_num:]):
            for edit in reversed(patch["edits"]):
                path = edit.file
                current_content = self.vfs.read(path)
                new_lines = current_content.decode('utf-8').splitlines(keepends=True)
                before_lines = []
                for line in edit.before:
                    if isinstance(line, bytes):
                        before_lines.append(line.decode('utf-8'))
                    else:
                        before_lines.append(line)
                result_lines = (
                    new_lines[:edit.lines[0]] +
                    before_lines +
                    new_lines[edit.lines[1]:]
                )
                result_content = ''.join(result_lines).encode('utf-8')
                self.vfs.write(path, result_content)
        self.patches = self.patches[:patch_num]

    def undo_last_patch(self) -> Result[int]:
        if self.patch_num == 0:
            return Err(CRSError("no edits remain to undo"))
        self.rewind_to(-1)
        return Ok(self.patch_num)

    class EditsList(TypedDict):
        edits: list[str]

    def list_edits(self) -> Result['Editor.EditsList']:
        if self.patch_num == 0:
            return Err(CRSError("no edits remain"))
        return Ok(Editor.EditsList(edits=[p['patch'] for p in self.patches]))

    # Utility: dump all applied patches as one concatenated diff
    def dump_unified_diff(self) -> str:
        return "".join([p['patch'] for p in self.patches])


