# SPDX-License-Identifier: Apache-2.0
"""
Workspace sanitisation.

An AIxCC challenge ships its own answer. Checking out ``delta_ref`` -- which for
the official challenges is the branch head -- puts ``.aixcc/vulns/<v>/`` in the
tree, and that directory holds ``vuln.yaml`` naming the CWE, the file and the
exact line range, a reference POV blob, and the reference patch. An agent with a
working file tool needs one call to read it.

The codebase already excluded ``.aixcc`` when generating the diff, with a comment
saying it prevents cheating. That covered one path out of several: file reads,
searches and ``git show`` were all still open. This module closes the rest by
deleting the directory rather than filtering it, because a deny-list has to be
remembered by every present and future tool while a missing directory does not.

``.git`` is separate and optional. Deleting it also removes the answer, since
``git show <ref>:.aixcc/...`` recovers anything the working tree no longer has,
but it costs the ability to regenerate a delta diff in that workspace -- so it
is a switch, and it refuses to run before the diff exists.

Sanitisation runs on the Python side only. Every entry point -- the shell
wrapper, the API server, a direct ``python -m fuzzingbrain.main`` -- ends up in
:func:`fuzzingbrain.main.setup_workspace`, so one call site covers all of them.
"""

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

__all__ = [
    "ANSWER_DIR",
    "GIT_DIR",
    "SanitizeReport",
    "WorkspaceGuardError",
    "assert_workspace_clean",
    "sanitize_workspace",
]

ANSWER_DIR = ".aixcc"
GIT_DIR = ".git"

# Source trees inside a task workspace: the checkout plus the per-sanitizer
# copies the analyzer builder makes from it.
_TREE_GLOBS = ("repo", "repo-*")


class WorkspaceGuardError(RuntimeError):
    """Raised when a workspace still holds something an agent must not see."""


@dataclass
class SanitizeReport:
    """What sanitisation removed, for the run banner and the logs."""

    answer_paths: List[str] = field(default_factory=list)
    git_paths: List[str] = field(default_factory=list)
    git_skipped_reason: Optional[str] = None

    @property
    def removed_anything(self) -> bool:
        return bool(self.answer_paths or self.git_paths)


def _trees(workspace: Path) -> List[Path]:
    seen: List[Path] = []
    for pattern in _TREE_GLOBS:
        for path in sorted(workspace.glob(pattern)):
            if path.is_dir() and path not in seen:
                seen.append(path)
    return seen


def _find(workspace: Path, name: str) -> List[Path]:
    """Every directory called ``name`` inside a source tree, nested included."""
    hits: List[Path] = []
    for tree in _trees(workspace):
        candidate = tree / name
        if candidate.is_dir():
            hits.append(candidate)
        # Nested copies: a vendored dependency can carry its own .aixcc or .git.
        for nested in tree.rglob(name):
            if nested.is_dir() and nested != candidate and nested not in hits:
                hits.append(nested)
    return hits


def _rel(workspace: Path, path: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def sanitize_workspace(
    workspace: Path,
    remove_git: bool = False,
    diff_ready: Optional[bool] = None,
) -> SanitizeReport:
    """Delete the answer directory, and optionally the git history.

    Args:
        workspace: The task workspace, holding ``repo/`` and any ``repo-*/`` copies.
        remove_git: Also delete ``.git``. Off by default: local development wants
            git, and reusing a workspace for a second delta run needs it.
        diff_ready: Whether the delta diff has already been generated. When
            ``remove_git`` is set and this is ``False``, git is kept and the
            reason is recorded -- deleting it first would make the diff
            impossible to produce, and failing later is worse than not deleting.

    Returns:
        A :class:`SanitizeReport` describing what was removed.
    """
    workspace = Path(workspace)
    report = SanitizeReport()

    for path in _find(workspace, ANSWER_DIR):
        shutil.rmtree(path, ignore_errors=True)
        if not path.exists():
            report.answer_paths.append(_rel(workspace, path))

    if remove_git:
        if diff_ready is False:
            report.git_skipped_reason = (
                "the delta diff has not been generated yet, and git is what "
                "generates it"
            )
        else:
            for path in _find(workspace, GIT_DIR):
                shutil.rmtree(path, ignore_errors=True)
                if not path.exists():
                    report.git_paths.append(_rel(workspace, path))

    return report


def assert_workspace_clean(workspace: Path, require_no_git: bool = False) -> None:
    """Fail loudly if a source tree still holds answers, or history when banned.

    Called before the build so a violation stops the run. This is deliberately
    an exception rather than a warning: the failure mode this whole module exists
    to prevent is a run that looks successful and quietly produced nothing
    trustworthy, and a warning in a log nobody reads reproduces exactly that.
    """
    workspace = Path(workspace)

    leftovers = [_rel(workspace, p) for p in _find(workspace, ANSWER_DIR)]
    if leftovers:
        raise WorkspaceGuardError(
            f"{ANSWER_DIR} is still present in the workspace: {leftovers}. "
            "It contains the vulnerability location, a reference POV and the "
            "reference patch, so any finding from this run would be worthless. "
            "Workspace sanitisation did not run, or ran before the checkout."
        )

    if require_no_git:
        history = [_rel(workspace, p) for p in _find(workspace, GIT_DIR)]
        if history:
            raise WorkspaceGuardError(
                f"remove_git is set but {GIT_DIR} is still present: {history}. "
                f"`git show <ref>:{ANSWER_DIR}/...` recovers the answer from "
                "history, so deleting the working copy alone is not enough."
            )


def format_banner(
    report: SanitizeReport,
    remove_git: bool,
    network_blocked: bool,
    confined_to: str,
) -> List[str]:
    """The lines a run prints about its own posture.

    A finished run should be able to prove from its log what was enforced,
    rather than leaving anyone to guess afterwards.
    """
    answers = (
        f"removed ({len(report.answer_paths)} path"
        f"{'s' if len(report.answer_paths) != 1 else ''})"
        if report.answer_paths
        else "not present"
    )
    if not remove_git:
        git = "kept (remove_git off)"
    elif report.git_skipped_reason:
        git = f"kept -- {report.git_skipped_reason}"
    else:
        git = (
            f"removed ({len(report.git_paths)} path"
            f"{'s' if len(report.git_paths) != 1 else ''})"
            if report.git_paths
            else "not present"
        )

    return [
        f"  {ANSWER_DIR:<14} {answers}",
        f"  {GIT_DIR:<14} {git}",
        f"  {'agent network':<14} "
        f"{'blocked' if network_blocked else 'allowed (no agent tool performs network I/O today)'}",
        f"  {'workspace':<14} confined to {confined_to}",
    ]
