# SPDX-License-Identifier: Apache-2.0
"""Tests for workspace sanitisation."""

import pytest

from fuzzingbrain.core.workspace_guard import (
    WorkspaceGuardError,
    assert_workspace_clean,
    format_banner,
    sanitize_workspace,
)


def _answer_dir(tree):
    """The shape a real challenge checkout has: location, POV and patch."""
    vuln = tree / ".aixcc" / "vulns" / "vuln_001"
    (vuln / "blobs").mkdir(parents=True)
    (vuln / "patches").mkdir(parents=True)
    (vuln / "vuln.yaml").write_text(
        "cwes:\n  - CWE-122\nlocations:\n  - path_from_root: 'HTMLparser.c'\n"
        "    startLine: 3577\npov:\n  harness: 'html'\n"
    )
    (vuln / "blobs" / "blob.bin").write_bytes(b"\x89PNG crash")
    (vuln / "patches" / "good_patch.diff").write_text("--- a/x\n+++ b/x\n")
    (tree / ".aixcc" / "challenge.yaml").write_text("challenge_type: delta\n")


@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "libpng_task"
    for name in ("repo", "repo-address", "repo-coverage"):
        tree = ws / name
        (tree / "src").mkdir(parents=True)
        (tree / "pngrutil.c").write_text("int png_handle_iCCP(void) { return 0; }\n")
        (tree / ".git").mkdir()
        (tree / ".git" / "config").write_text("[core]\n")
        _answer_dir(tree)
    (ws / "diff").mkdir()
    (ws / "diff" / "ref.diff").write_text("diff --git a/pngrutil.c b/pngrutil.c\n")
    return ws


# ------------------------------------------------------------------ .aixcc


def test_answers_are_removed_from_every_tree(workspace):
    report = sanitize_workspace(workspace)
    for name in ("repo", "repo-address", "repo-coverage"):
        assert not (workspace / name / ".aixcc").exists()
    assert len(report.answer_paths) == 3
    assert report.removed_anything is True


def test_source_survives_sanitisation(workspace):
    sanitize_workspace(workspace)
    assert (workspace / "repo" / "pngrutil.c").read_text().startswith("int png_handle")
    assert (workspace / "diff" / "ref.diff").exists()


def test_nested_answer_directories_are_removed(workspace):
    nested = workspace / "repo" / "third_party" / "dep"
    nested.mkdir(parents=True)
    _answer_dir(nested)
    sanitize_workspace(workspace)
    assert not nested.joinpath(".aixcc").exists()


def test_answers_are_removed_even_without_remove_git(workspace):
    """.aixcc is not a switch. It goes whatever else the run asks for."""
    sanitize_workspace(workspace, remove_git=False)
    assert not (workspace / "repo" / ".aixcc").exists()
    assert (workspace / "repo" / ".git").exists()


def test_sanitising_a_clean_workspace_is_a_no_op(tmp_path):
    ws = tmp_path / "clean"
    (ws / "repo").mkdir(parents=True)
    (ws / "repo" / "main.c").write_text("int main(void){return 0;}\n")
    report = sanitize_workspace(ws, remove_git=True)
    assert report.removed_anything is False
    assert (ws / "repo" / "main.c").exists()


# ------------------------------------------------------------------ .git


def test_remove_git_deletes_history(workspace):
    report = sanitize_workspace(workspace, remove_git=True, diff_ready=True)
    for name in ("repo", "repo-address", "repo-coverage"):
        assert not (workspace / name / ".git").exists()
    assert len(report.git_paths) == 3


def test_git_is_kept_when_the_diff_is_not_ready(workspace):
    """Deleting history before the diff exists would make it unproducible."""
    report = sanitize_workspace(workspace, remove_git=True, diff_ready=False)
    assert (workspace / "repo" / ".git").exists()
    assert report.git_paths == []
    assert "diff" in report.git_skipped_reason
    assert not (workspace / "repo" / ".aixcc").exists(), "answers still go"


# ------------------------------------------------------------------ assertion


def test_assert_rejects_a_workspace_holding_answers(workspace):
    with pytest.raises(WorkspaceGuardError) as exc:
        assert_workspace_clean(workspace)
    assert ".aixcc" in str(exc.value)
    assert "repo" in str(exc.value)


def test_assert_passes_after_sanitisation(workspace):
    sanitize_workspace(workspace)
    assert_workspace_clean(workspace)


def test_assert_rejects_history_when_remove_git_is_set(workspace):
    sanitize_workspace(workspace, remove_git=True, diff_ready=False)
    with pytest.raises(WorkspaceGuardError) as exc:
        assert_workspace_clean(workspace, require_no_git=True)
    assert "git show" in str(exc.value)


def test_assert_ignores_history_when_remove_git_is_off(workspace):
    sanitize_workspace(workspace)
    assert_workspace_clean(workspace, require_no_git=False)


# ------------------------------------------------------------------ banner


def test_banner_states_what_was_enforced(workspace):
    report = sanitize_workspace(workspace, remove_git=True, diff_ready=True)
    lines = format_banner(
        report, remove_git=True, network_blocked=True, confined_to="libpng_task/repo"
    )
    text = "\n".join(lines)
    assert "removed (3 paths)" in text
    assert "blocked" in text
    assert "libpng_task/repo" in text


def test_banner_explains_a_kept_git(workspace):
    report = sanitize_workspace(workspace, remove_git=True, diff_ready=False)
    text = "\n".join(
        format_banner(report, remove_git=True, network_blocked=False, confined_to="x")
    )
    assert "kept -- the delta diff" in text
    assert "no agent tool performs network I/O today" in text


def test_banner_does_not_claim_removal_when_nothing_was_there(tmp_path):
    ws = tmp_path / "clean"
    (ws / "repo").mkdir(parents=True)
    report = sanitize_workspace(ws)
    text = "\n".join(
        format_banner(report, remove_git=False, network_blocked=False, confined_to="x")
    )
    assert "not present" in text
    assert "remove_git off" in text


# ------------------------------------------------------------------ copies


def test_builder_copies_exclude_answers_and_history(workspace, tmp_path):
    """The per-sanitizer copy must not be the path that reintroduces them."""
    import shutil

    dest = tmp_path / "repo-memory"
    shutil.copytree(
        workspace / "repo",
        dest,
        symlinks=True,
        ignore=shutil.ignore_patterns(".aixcc", ".git"),
    )
    assert (dest / "pngrutil.c").exists()
    assert not (dest / ".aixcc").exists()
    assert not (dest / ".git").exists()
