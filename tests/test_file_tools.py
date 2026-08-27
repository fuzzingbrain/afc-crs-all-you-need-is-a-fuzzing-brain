# SPDX-License-Identifier: Apache-2.0
"""Tests for the Read / Grep / Glob file tools."""

import shutil

import pytest

from fuzzingbrain.tools import files as F
from fuzzingbrain.tools.code_viewer import set_code_viewer_context

RG = shutil.which("rg")
needs_rg = pytest.mark.skipif(RG is None, reason="ripgrep is not installed")


@pytest.fixture
def workspace(tmp_path):
    """A workspace shaped like a real task: repo/, diff/, and answers to hide."""
    ws = tmp_path / "task"
    repo = ws / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / ".aixcc" / "vulns" / "vuln_001").mkdir(parents=True)
    (repo / ".git").mkdir()

    (repo / "png.c").write_text(
        "\n".join(
            f"line {i} keyword_length" if i % 10 == 0 else f"line {i}"
            for i in range(1, 61)
        )
        + "\n"
    )
    (repo / "src" / "util.c").write_text("int helper(void) { return 0; }\n")
    (repo / "src" / "util.h").write_text("int helper(void);\n")
    (repo / ".aixcc" / "vulns" / "vuln_001" / "vuln.yaml").write_text(
        "metadata_spec_version: v1\nstartLine: 1425\nharness: 'png_read_fuzzer'\n"
    )
    (repo / ".git" / "config").write_text("[core]\n")
    (repo / "blob.bin").write_bytes(b"\x00\x01\x02binary\x00")

    (ws / "diff").mkdir()
    (ws / "diff" / "ref.diff").write_text("diff --git a/png.c b/png.c\n")

    (tmp_path / "outside.txt").write_text("host secret\n")

    set_code_viewer_context(
        str(ws), repo_subdir="repo", diff_filename="diff/ref.diff", project_name="png"
    )
    return ws


# ---------------------------------------------------------------- Read


def test_read_returns_numbered_lines(workspace):
    r = F.read_file_impl("png.c", 10, 2)
    assert r["success"] is True
    assert r["content"].splitlines()[0] == "10\tline 10 keyword_length"
    assert r["start_line"] == 10 and r["end_line"] == 11
    assert r["total_lines"] == 60


def test_read_reports_truncation_with_next_offset(workspace):
    r = F.read_file_impl("png.c", 1, 5)
    assert r["truncated"] is True
    assert "offset=6" in r["content"]


def test_read_whole_file_is_not_marked_truncated(workspace):
    r = F.read_file_impl("png.c", 1, 60)
    assert r["truncated"] is False
    assert "showing lines" not in r["content"]


def test_read_rejects_offset_past_end(workspace):
    r = F.read_file_impl("png.c", 5000, 1)
    assert r["success"] is False
    assert "past the end" in r["error"]


def test_read_missing_file_is_an_error_not_empty_success(workspace):
    r = F.read_file_impl("nope.c")
    assert r["success"] is False
    assert "not found" in r["error"].lower()


def test_read_directory_is_an_error(workspace):
    r = F.read_file_impl("src")
    assert r["success"] is False
    assert "directory" in r["error"].lower()


def test_read_refuses_binary(workspace):
    r = F.read_file_impl("blob.bin")
    assert r["success"] is False
    assert "binary" in r["error"].lower()


@pytest.mark.parametrize(
    "path",
    [
        ".aixcc/vulns/vuln_001/vuln.yaml",
        ".git/config",
    ],
)
def test_read_refuses_answer_and_history_paths(workspace, path):
    r = F.read_file_impl(path)
    assert r["success"] is False
    assert "not readable" in r["error"]


def test_read_refuses_traversal(workspace):
    r = F.read_file_impl("../../outside.txt")
    assert r["success"] is False
    assert "outside the workspace" in r["error"]


def test_read_refuses_absolute_path(workspace):
    r = F.read_file_impl("/etc/passwd")
    assert r["success"] is False
    assert "relative" in r["error"]


def test_read_refuses_symlink_escape(workspace):
    link = workspace / "repo" / "escape.txt"
    link.symlink_to(workspace.parent / "outside.txt")
    r = F.read_file_impl("escape.txt")
    assert r["success"] is False
    assert "outside the workspace" in r["error"]


# ---------------------------------------------------------------- Grep


@needs_rg
def test_grep_content_parses_match_and_context_lines(workspace):
    r = F.grep_impl(
        "keyword_length", glob="*.c", output_mode="content", context_lines=1
    )
    assert r["success"] is True
    assert r["count"] == 6, "one match every tenth line of a 60 line file"
    kinds = {m["is_match"] for m in r["matches"]}
    assert kinds == {True, False}, "context lines use '-' and must parse too"


@needs_rg
def test_grep_files_with_matches(workspace):
    r = F.grep_impl("helper", output_mode="files_with_matches")
    assert r["success"] is True
    assert sorted(r["files"]) == ["src/util.c", "src/util.h"]


@needs_rg
def test_grep_count_sorts_by_hits(workspace):
    r = F.grep_impl("line", output_mode="count")
    assert r["success"] is True
    assert r["counts"][0]["file"] == "png.c"
    assert r["total_matches"] >= 60


@needs_rg
def test_grep_never_reaches_answers_or_history(workspace):
    for pattern in ("metadata_spec_version", "startLine", "core"):
        r = F.grep_impl(pattern, output_mode="files_with_matches")
        assert r["success"] is True
        assert r["files"] == [], f"{pattern} leaked from a denied directory"


@needs_rg
def test_grep_head_limit_flags_truncation(workspace):
    r = F.grep_impl("line", output_mode="content", head_limit=3)
    assert len(r["matches"]) == 3
    assert r["truncated"] is True


def test_grep_rejects_unknown_output_mode(workspace):
    r = F.grep_impl("x", output_mode="everything")
    assert r["success"] is False
    assert "output_mode" in r["error"]


def test_grep_requires_a_pattern(workspace):
    assert F.grep_impl("")["success"] is False


# ---------------------------------------------------------------- Glob


def test_glob_matches_and_sorts_by_path(workspace):
    r = F.glob_impl("**/*.c")
    assert r["success"] is True
    assert r["files"] == ["png.c", "src/util.c"]


def test_glob_directory_pattern(workspace):
    r = F.glob_impl("src/*")
    assert sorted(r["files"]) == ["src/util.c", "src/util.h"]


def test_glob_hides_denied_directories(workspace):
    assert F.glob_impl(".aixcc/**/*")["files"] == []
    assert F.glob_impl(".git/*")["files"] == []


def test_glob_head_limit_flags_truncation(workspace):
    r = F.glob_impl("**/*", head_limit=1)
    assert len(r["files"]) == 1
    assert r["truncated"] is True
    assert r["count"] > 1


def test_glob_omits_directories_by_default(workspace):
    r = F.glob_impl("*")
    assert "src" not in r["files"]
    assert "directories" not in r


def test_glob_include_dirs_exposes_the_tree(workspace):
    r = F.glob_impl("*", include_dirs=True)
    assert "src/" in r["directories"]
    assert r["dir_count"] >= 1
    assert "png.c" in r["files"], "files still come back alongside directories"


def test_glob_include_dirs_still_hides_denied_directories(workspace):
    r = F.glob_impl("*", include_dirs=True)
    assert ".aixcc/" not in r["directories"]
    assert ".git/" not in r["directories"]


def test_glob_refuses_absolute_pattern(workspace):
    r = F.glob_impl("/etc/*")
    assert r["success"] is False
    assert "relative" in r["error"]


# ---------------------------------------------------------------- context


def test_tools_fail_clearly_without_context():
    from contextvars import copy_context

    def run():
        from fuzzingbrain.tools.code_viewer import _workspace_path

        _workspace_path.set(None)
        return (
            F.read_file_impl("x.c")["error"],
            F.grep_impl("x")["error"],
            F.glob_impl("*")["error"],
        )

    for err in copy_context().run(run):
        assert "context" in err.lower()


# ---------------------------------------------------------------- audit trail


def test_tool_args_are_rendered_for_the_log():
    """Every MCP call is logged with its arguments, so a run is auditable
    from the log alone -- including an attempt to read the answers."""
    from fuzzingbrain.agents.base import format_tool_args

    assert format_tool_args({}) == ""
    assert (
        format_tool_args({"file_path": "png.c", "offset": 10, "limit": 2})
        == "file_path='png.c', offset=10, limit=2"
    )
    assert ".aixcc" in format_tool_args({"file_path": ".aixcc/vulns/v/vuln.yaml"})


def test_long_tool_args_are_clipped_not_dumped():
    from fuzzingbrain.agents.base import format_tool_args

    rendered = format_tool_args({"content": "A" * 5000, "fuzzer": "html"})
    assert len(rendered) < 250, "a POV blob must not end up in a log line"
    assert "fuzzer='html'" in rendered


def test_non_scalar_tool_args_are_summarised_by_type():
    from fuzzingbrain.agents.base import format_tool_args

    assert format_tool_args({"data": {"a": 1}}) == "data=<dict>"
    assert format_tool_args({"flag": True, "none": None}) == "flag=True, none=None"


# ---------------------------------------------------------------- portability


@needs_rg
def test_grep_falls_back_to_grep_without_ripgrep(workspace):
    """A host without ripgrep still gets search, with the same answers."""
    from unittest.mock import patch

    with patch.object(F, "_rg_available", lambda: False):
        r = F.grep_impl("helper", output_mode="files_with_matches")
    assert r["success"] is True
    assert sorted(r["files"]) == ["src/util.c", "src/util.h"]


@needs_rg
def test_both_search_backends_agree(workspace):
    from unittest.mock import patch

    with patch.object(F, "_rg_available", lambda: True):
        rg = F.grep_impl("keyword_length", output_mode="count")
    with patch.object(F, "_rg_available", lambda: False):
        posix = F.grep_impl("keyword_length", output_mode="count")
    assert rg["counts"] == posix["counts"]
    assert rg["total_matches"] == posix["total_matches"]


@needs_rg
def test_grep_fallback_still_refuses_denied_directories(workspace):
    from unittest.mock import patch

    with patch.object(F, "_rg_available", lambda: False):
        r = F.grep_impl("metadata_spec_version", output_mode="files_with_matches")
    assert r["files"] == []


def test_grep_finds_dotfiles(workspace):
    """ripgrep skips hidden files by default; a source tree keeps content in
    them, and a dotfile's name must survive the path cleanup."""
    (workspace / "repo" / ".clang-format").write_text("BasedOnStyle: LLVM\nhelper\n")
    r = F.grep_impl("helper", output_mode="files_with_matches")
    assert ".clang-format" in r["files"], "leading dot must not be stripped"


def test_rg_detection_does_not_shell_out():
    """shutil.which, not a `which` subprocess: `which` is not a command
    everywhere, and it costs a process either way."""
    import inspect

    assert "shutil.which" in inspect.getsource(F._rg_available)
