# SPDX-License-Identifier: Apache-2.0
"""
Adversarial tests for the directory-level function extraction façade.

The façade walks a tree, skips excluded dirs, tolerates unparseable files, and
groups results by name keeping duplicates. These tests probe the exact-match
(not substring) nature of the exclusion filter, the "duplicate names across
files are all kept" contract, resilience to a garbage file mid-walk, and the
language dispatch (java -> NotImplementedError, unknown -> ValueError).
"""

from pathlib import Path

import pytest

from fuzzingbrain.analysis.function_extraction import (
    _should_exclude,
    extract_functions_from_file,
    extract_functions_from_directory,
    get_function_metadata,
    find_function_by_name,
    DEFAULT_EXCLUDE_DIRS,
)


# --------------------------------------------------------------------------
# _should_exclude: exact directory-name match, not substring
# --------------------------------------------------------------------------

def test_excludes_when_a_path_component_is_an_excluded_dir():
    assert _should_exclude(Path("proj/third_party/zlib/z.c"), DEFAULT_EXCLUDE_DIRS)
    assert _should_exclude(Path("proj/build/gen.c"), DEFAULT_EXCLUDE_DIRS)
    assert _should_exclude(Path("proj/deps/a/b/c.c"), DEFAULT_EXCLUDE_DIRS)


def test_does_not_exclude_substring_dir_names():
    """'buildsystem' contains 'build' but is not the excluded dir 'build'."""
    assert not _should_exclude(Path("proj/buildsystem/x.c"), DEFAULT_EXCLUDE_DIRS)
    assert not _should_exclude(Path("proj/external_api/x.c"), DEFAULT_EXCLUDE_DIRS)


def test_does_not_exclude_when_only_the_filename_resembles_a_dir():
    """A file named 'deps.c' is fine; only a *directory* 'deps' is excluded."""
    assert not _should_exclude(Path("proj/src/deps.c"), DEFAULT_EXCLUDE_DIRS)


def test_exclusion_is_case_sensitive():
    """'Build' (capitalized) is not the excluded lowercase 'build' — documents
    the current, case-sensitive behavior so a future change is a conscious one."""
    assert not _should_exclude(Path("proj/Build/x.c"), DEFAULT_EXCLUDE_DIRS)


def test_custom_exclude_set_overrides_default():
    assert _should_exclude(Path("proj/secret/x.c"), {"secret"})
    assert not _should_exclude(Path("proj/build/x.c"), {"secret"})


# --------------------------------------------------------------------------
# extract_functions_from_directory
# --------------------------------------------------------------------------

def test_directory_walk_finds_functions_and_skips_excluded(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "third_party").mkdir()
    (tmp_path / "src" / "a.c").write_text("int a(void){ return 1; }")
    (tmp_path / "src" / "b.h").write_text("static int b(void){ return 2; }")
    # This one is inside an excluded dir and must be skipped
    (tmp_path / "third_party" / "z.c").write_text("int z(void){ return 0; }")

    names = {f.name for f in extract_functions_from_directory(tmp_path)}
    assert names == {"a", "b"}
    assert "z" not in names


def test_directory_walk_tolerates_unreadable_file(tmp_path):
    """A file that makes the parser explode must not abort the whole walk."""
    good = tmp_path / "good.c"
    good.write_text("int good(void){ return 0; }")
    # A directory named like a .c file: rglob yields it, open() will fail (IsADir)
    (tmp_path / "trap.c").mkdir()

    names = {f.name for f in extract_functions_from_directory(tmp_path)}
    assert "good" in names  # walk survived the trap


def test_directory_walk_respects_extension_filter(tmp_path):
    (tmp_path / "keep.c").write_text("int keep(void){ return 0; }")
    (tmp_path / "skip.cpp").write_text("int skip(void){ return 0; }")
    names = {f.name for f in extract_functions_from_directory(tmp_path, extensions=[".c"])}
    assert names == {"keep"}  # .cpp not in the filter


# --------------------------------------------------------------------------
# get_function_metadata / find_function_by_name: duplicates kept, filtering
# --------------------------------------------------------------------------

def test_metadata_keeps_duplicate_named_functions_across_files(tmp_path):
    """Two files each define 'init' — both must be retained under one key."""
    (tmp_path / "m1.c").write_text("int init(void){ return 1; }")
    (tmp_path / "m2.c").write_text("int init(void){ return 2; }")
    meta = get_function_metadata(["init"], tmp_path)
    assert set(meta.keys()) == {"init"}
    assert len(meta["init"]) == 2


def test_metadata_filters_to_requested_names_only(tmp_path):
    (tmp_path / "s.c").write_text(
        "int wanted(void){ return 0; }\nint unwanted(void){ return 1; }"
    )
    meta = get_function_metadata(["wanted"], tmp_path)
    assert set(meta.keys()) == {"wanted"}
    assert "unwanted" not in meta


def test_find_function_by_name_missing_returns_empty_list(tmp_path):
    (tmp_path / "s.c").write_text("int present(void){ return 0; }")
    assert find_function_by_name("absent", tmp_path) == []
    assert [f.name for f in find_function_by_name("present", tmp_path)] == ["present"]


# --------------------------------------------------------------------------
# Language dispatch
# --------------------------------------------------------------------------

def test_java_not_implemented(tmp_path):
    f = tmp_path / "X.java"
    f.write_text("class X {}")
    with pytest.raises(NotImplementedError):
        extract_functions_from_file(f, language="java")
    with pytest.raises(NotImplementedError):
        extract_functions_from_directory(tmp_path, language="java")


def test_unknown_language_raises_value_error(tmp_path):
    f = tmp_path / "x.rs"
    f.write_text("fn main(){}")
    with pytest.raises(ValueError):
        extract_functions_from_file(f, language="rust")
    with pytest.raises(ValueError):
        extract_functions_from_directory(tmp_path, language="rust")
