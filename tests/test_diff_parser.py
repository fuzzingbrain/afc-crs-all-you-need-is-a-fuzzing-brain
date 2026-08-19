# SPDX-License-Identifier: Apache-2.0
"""
Adversarial tests for the unified-diff parser and reachability plumbing.

Unified-diff parsing is a swamp of off-by-ones and header edge cases, so these
tests feed shapes designed to expose them: implicit hunk counts, zero-count
(pure add / pure delete) hunks, multi-hunk files, binary markers, rename headers,
new/deleted-file modes, and functions whose boundaries sit exactly on a hunk
edge. Several assert the *excerpt* boundary: a hunk ending on the line just
before a function must not be pulled into that function's diff excerpt.
"""

from fuzzingbrain.analysis.diff_parser import (
    parse_diff,
    _is_source_file,
    _extract_hunk_content_for_function,
    get_all_changes,
    DiffHunk,
)


# --------------------------------------------------------------------------
# DiffHunk.new_lines: the raw line-range math
# --------------------------------------------------------------------------


def test_new_lines_span_matches_count():
    h = DiffHunk(old_start=10, old_count=3, new_start=10, new_count=3, content="")
    assert list(h.new_lines) == [10, 11, 12]  # not [10..13]


def test_new_lines_zero_count_is_empty():
    """A pure-deletion hunk adds no new lines; new_lines must be empty."""
    h = DiffHunk(old_start=5, old_count=2, new_start=4, new_count=0, content="")
    assert list(h.new_lines) == []


# --------------------------------------------------------------------------
# parse_diff: header / hunk-count edge cases
# --------------------------------------------------------------------------

_SIMPLE = """diff --git a/foo.c b/foo.c
index 111..222 100644
--- a/foo.c
+++ b/foo.c
@@ -1,3 +1,4 @@
 int main() {
+    int x = 0;
     return 0;
 }
"""


def test_parse_extracts_paths_and_hunk_range():
    diffs = parse_diff(_SIMPLE)
    assert len(diffs) == 1
    d = diffs[0]
    assert d.old_path == "foo.c" and d.new_path == "foo.c"
    assert not d.is_binary and not d.is_new_file and not d.is_deleted
    assert len(d.hunks) == 1
    h = d.hunks[0]
    assert (h.new_start, h.new_count) == (1, 4)
    assert d.changed_lines == [1, 2, 3, 4]


def test_implicit_counts_default_to_one():
    """'@@ -5 +5 @@' (no comma) means count 1, per the diff spec.

    A parser that treats a missing count as 0 would drop the changed line.
    """
    diff = "diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n@@ -5 +5 @@\n-old\n+new\n"
    d = parse_diff(diff)[0]
    h = d.hunks[0]
    assert (h.new_start, h.new_count) == (5, 1)
    assert d.changed_lines == [5]


def test_multiple_hunks_in_one_file_all_captured():
    diff = (
        "diff --git a/m.c b/m.c\n"
        "--- a/m.c\n"
        "+++ b/m.c\n"
        "@@ -1,2 +1,3 @@\n"
        " a\n"
        "+b\n"
        " c\n"
        "@@ -20,2 +21,3 @@\n"
        " d\n"
        "+e\n"
        " f\n"
    )
    d = parse_diff(diff)[0]
    assert len(d.hunks) == 2
    assert d.hunks[0].new_start == 1 and d.hunks[1].new_start == 21
    # changed_lines is the union across hunks
    assert set(d.changed_lines) == {1, 2, 3, 21, 22, 23}


def test_two_files_split_correctly():
    diff = _SIMPLE + (
        "diff --git a/bar.c b/bar.c\n"
        "--- a/bar.c\n"
        "+++ b/bar.c\n"
        "@@ -1,1 +1,2 @@\n"
        " y\n"
        "+z\n"
    )
    diffs = parse_diff(diff)
    assert [d.path for d in diffs] == ["foo.c", "bar.c"]


def test_new_file_mode_flagged_and_path_is_new():
    diff = (
        "diff --git a/new.c b/new.c\n"
        "new file mode 100644\n"
        "index 000..111\n"
        "--- /dev/null\n"
        "+++ b/new.c\n"
        "@@ -0,0 +1,2 @@\n"
        "+line1\n"
        "+line2\n"
    )
    d = parse_diff(diff)[0]
    assert d.is_new_file is True
    assert d.path == "new.c"
    assert set(d.changed_lines) == {1, 2}


def test_deleted_file_uses_old_path_and_is_flagged():
    diff = (
        "diff --git a/gone.c b/gone.c\n"
        "deleted file mode 100644\n"
        "--- a/gone.c\n"
        "+++ /dev/null\n"
        "@@ -1,2 +0,0 @@\n"
        "-a\n"
        "-b\n"
    )
    d = parse_diff(diff)[0]
    assert d.is_deleted is True
    assert d.path == "gone.c"  # deletion reports the OLD path


def test_binary_file_detected_and_no_hunks():
    diff = (
        "diff --git a/img.png b/img.png\n"
        "index 111..222 100644\n"
        "Binary files a/img.png and b/img.png differ\n"
    )
    d = parse_diff(diff)[0]
    assert d.is_binary is True
    assert d.hunks == []


def test_empty_diff_yields_no_files():
    assert parse_diff("") == []
    assert parse_diff("\n\n   \n") == []


def test_rename_header_keeps_distinct_old_and_new_paths():
    diff = (
        "diff --git a/old_name.c b/new_name.c\n"
        "similarity index 90%\n"
        "rename from old_name.c\n"
        "rename to new_name.c\n"
        "--- a/old_name.c\n"
        "+++ b/new_name.c\n"
        "@@ -1,1 +1,2 @@\n"
        " a\n"
        "+b\n"
    )
    d = parse_diff(diff)[0]
    assert d.old_path == "old_name.c"
    assert d.new_path == "new_name.c"
    assert d.path == "new_name.c"  # modification -> new path


# --------------------------------------------------------------------------
# _is_source_file: extension gate
# --------------------------------------------------------------------------


def test_source_file_extensions():
    for p in ["a.c", "b.h", "c.cc", "d.cpp", "e.cxx", "f.hpp", "g.java", "DIR/A.C"]:
        assert _is_source_file(p), p
    for p in ["readme.md", "Makefile", "a.py", "b.txt", "c.o", "noext"]:
        assert not _is_source_file(p), p


# --------------------------------------------------------------------------
# _extract_hunk_content_for_function: overlap boundary (regression)
# --------------------------------------------------------------------------


def test_excerpt_excludes_hunk_ending_just_before_function():
    """A hunk touching lines 7-9 must NOT be attributed to a function at 10-20.

    Regression: the overlap check used new_start+new_count (one past the last
    touched line), so a hunk ending exactly on func_start-1 leaked into the
    excerpt with zero real overlap.
    """
    func_start, func_end = 10, 20
    adjacent = DiffHunk(
        old_start=7, old_count=3, new_start=7, new_count=3, content="+adjacent"
    )  # touches 7,8,9
    inside = DiffHunk(
        old_start=15, old_count=1, new_start=15, new_count=1, content="+inside"
    )  # touches 15
    excerpt, changed = _extract_hunk_content_for_function(
        [adjacent, inside], func_start, func_end
    )
    assert "adjacent" not in excerpt  # the adjacent hunk is excluded
    assert "inside" in excerpt
    assert changed == [15]


def test_excerpt_includes_hunk_touching_first_function_line():
    """A hunk that reaches func_start itself DOES overlap and stays in."""
    func_start, func_end = 10, 20
    touching = DiffHunk(
        old_start=8, old_count=3, new_start=8, new_count=3, content="+touch"
    )  # touches 8,9,10 -> line 10 is inside
    excerpt, changed = _extract_hunk_content_for_function(
        [touching], func_start, func_end
    )
    assert "touch" in excerpt
    assert changed == [10]


def test_excerpt_zero_count_deletion_hunk_does_not_overlap():
    """A pure-deletion hunk (new_count=0) at the function start adds no new
    lines and must not be counted as overlapping."""
    func_start, func_end = 10, 20
    deletion = DiffHunk(
        old_start=10, old_count=2, new_start=10, new_count=0, content="-removed"
    )
    excerpt, changed = _extract_hunk_content_for_function(
        [deletion], func_start, func_end
    )
    assert changed == []
    assert excerpt == ""


# --------------------------------------------------------------------------
# get_all_changes: uses the analysis client + sorts, does not filter
# --------------------------------------------------------------------------


class _FakeClient:
    """Minimal analysis client double: files->functions, reachability map."""

    def __init__(self, functions_by_file, reachability):
        self._funcs = functions_by_file
        self._reach = reachability

    def get_functions_by_file(self, path):
        return self._funcs.get(path, [])

    def get_reachability(self, fuzzer, func_name):
        return self._reach.get(func_name, {"reachable": False, "distance": None})


def test_get_all_changes_keeps_unreachable_and_sorts_reachable_first():
    """get_all_changes must return unreachable functions too (they are only a
    scoring factor), with reachable ones sorted ahead by distance."""
    diff = (
        "diff --git a/s.c b/s.c\n"
        "--- a/s.c\n"
        "+++ b/s.c\n"
        "@@ -1,1 +1,1 @@\n"
        "-x\n"
        "+y\n"
        "@@ -50,1 +50,1 @@\n"
        "-p\n"
        "+q\n"
    )
    client = _FakeClient(
        functions_by_file={
            "s.c": [
                {"name": "near", "start_line": 1, "end_line": 5, "file_path": "s.c"},
                {"name": "far", "start_line": 48, "end_line": 55, "file_path": "s.c"},
            ]
        },
        reachability={
            "near": {"reachable": True, "distance": 5},
            "far": {"reachable": False, "distance": None},
        },
    )
    changes = get_all_changes(diff, "fuzz", client)
    names = [c.function_name for c in changes]
    assert set(names) == {"near", "far"}  # unreachable NOT dropped
    assert names[0] == "near"  # reachable sorts first
    assert changes[0].static_reachable is True
    assert changes[1].static_reachable is False


def test_get_all_changes_skips_functions_without_overlap():
    """A function whose line range doesn't intersect any changed line is out."""
    diff = "diff --git a/s.c b/s.c\n--- a/s.c\n+++ b/s.c\n@@ -1,1 +1,1 @@\n-x\n+y\n"
    client = _FakeClient(
        functions_by_file={
            "s.c": [
                {"name": "hit", "start_line": 1, "end_line": 3, "file_path": "s.c"},
                {
                    "name": "miss",
                    "start_line": 100,
                    "end_line": 200,
                    "file_path": "s.c",
                },
            ]
        },
        reachability={"hit": {"reachable": True, "distance": 0}},
    )
    changes = get_all_changes(diff, "fuzz", client)
    assert [c.function_name for c in changes] == ["hit"]


def test_get_all_changes_survives_client_reachability_errors():
    """If reachability lookup throws, the change is still reported (unreachable),
    not dropped and not propagated as an exception."""
    diff = "diff --git a/s.c b/s.c\n--- a/s.c\n+++ b/s.c\n@@ -1,1 +1,1 @@\n-x\n+y\n"

    class Boom(_FakeClient):
        def get_reachability(self, fuzzer, func_name):
            raise RuntimeError("analysis server down")

    client = Boom(
        functions_by_file={
            "s.c": [{"name": "f", "start_line": 1, "end_line": 3, "file_path": "s.c"}]
        },
        reachability={},
    )
    changes = get_all_changes(diff, "fuzz", client)
    assert len(changes) == 1
    assert changes[0].static_reachable is False


def test_get_all_changes_ignores_non_source_files():
    diff = (
        "diff --git a/readme.md b/readme.md\n"
        "--- a/readme.md\n"
        "+++ b/readme.md\n"
        "@@ -1,1 +1,1 @@\n"
        "-x\n"
        "+y\n"
    )
    client = _FakeClient(functions_by_file={}, reachability={})
    assert get_all_changes(diff, "fuzz", client) == []
