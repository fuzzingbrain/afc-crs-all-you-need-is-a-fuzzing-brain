# SPDX-License-Identifier: Apache-2.0
"""Tests for the build_check parallel build-verification script's discovery.

The build execution itself is covered by tests/test_builder_engine.py (the shared
engine/orchestrator); here we only pin the script's bug-discovery + filtering,
hermetically against a synthetic bench tree.
"""

import importlib.util
from pathlib import Path

_BUILD_CHECK = Path(__file__).resolve().parent.parent / "scripts" / "build_check.py"


def _load_build_check():
    spec = importlib.util.spec_from_file_location("build_check", _BUILD_CHECK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_bench(tmp_path, bugs):
    """bugs: list of (project, bug_id, language)."""
    for project, bug_id, lang in bugs:
        d = tmp_path / "bugs" / project / bug_id
        d.mkdir(parents=True)
        (d / "bench.yaml").write_text(
            f"bug_id: {bug_id}\nproject: {project}\n"
            f"target:\n  language: {lang}\n"
        )
    return tmp_path


def test_discover_returns_all_bugs(tmp_path):
    bc = _load_build_check()
    _make_bench(tmp_path, [
        ("net-snmp", "netsnmp-a", "c"),
        ("mongoose", "mongoose-b", "c"),
        ("graal", "graal-c", "jvm"),
    ])
    found = {b for b, _ in bc.discover(tmp_path, None, None)}
    assert found == {"netsnmp-a", "mongoose-b", "graal-c"}


def test_discover_filters_by_language_with_cpp_normalization(tmp_path):
    bc = _load_build_check()
    _make_bench(tmp_path, [
        ("p1", "c-bug", "c"),
        ("p2", "cpp-bug", "cpp"),     # cpp must normalize to c++
        ("p3", "jvm-bug", "jvm"),
    ])
    ids = {b for b, _ in bc.discover(tmp_path, {"c++"}, None)}
    assert ids == {"cpp-bug"}         # only the c++ one, via cpp->c++ mapping


def test_discover_filters_by_explicit_ids(tmp_path):
    bc = _load_build_check()
    _make_bench(tmp_path, [
        ("p1", "keep-me", "c"),
        ("p2", "drop-me", "c"),
    ])
    ids = {b for b, _ in bc.discover(tmp_path, None, {"keep-me"})}
    assert ids == {"keep-me"}


def test_discover_returns_bug_dirs(tmp_path):
    bc = _load_build_check()
    _make_bench(tmp_path, [("net-snmp", "netsnmp-a", "c")])
    (_id, bug_dir), = bc.discover(tmp_path, None, None)
    assert bug_dir == tmp_path / "bugs" / "net-snmp" / "netsnmp-a"
    assert (bug_dir / "bench.yaml").is_file()


def test_force_rmtree_is_noop_on_missing(tmp_path):
    bc = _load_build_check()
    bc._force_rmtree(tmp_path / "does-not-exist")   # must not raise
