# SPDX-License-Identifier: Apache-2.0
"""A self-describing workspace yields its project name without --project.

The importer/local-workspace path does not pass --project, so V2 must read it
from fuzz-tooling/projects/<name>/. Without this the builder gets
project_name=None and dies before building.
"""

from fuzzingbrain.main import _detect_workspace_project


def _make_ws(tmp_path, *projects):
    pdir = tmp_path / "fuzz-tooling" / "projects"
    pdir.mkdir(parents=True)
    for p in projects:
        (pdir / p).mkdir()
    return tmp_path


def test_single_project_is_detected(tmp_path):
    ws = _make_ws(tmp_path, "net-snmp")
    assert _detect_workspace_project(str(ws)) == "net-snmp"


def test_ambiguous_returns_none(tmp_path):
    ws = _make_ws(tmp_path, "net-snmp", "libpng")
    # Two projects -> caller must pass --project explicitly.
    assert _detect_workspace_project(str(ws)) is None


def test_no_projects_dir_returns_none(tmp_path):
    assert _detect_workspace_project(str(tmp_path)) is None


def test_empty_projects_dir_returns_none(tmp_path):
    ws = _make_ws(tmp_path)
    assert _detect_workspace_project(str(ws)) is None


def test_ignores_stray_files(tmp_path):
    ws = _make_ws(tmp_path, "net-snmp")
    (ws / "fuzz-tooling" / "projects" / "README.md").write_text("x")
    assert _detect_workspace_project(str(ws)) == "net-snmp"
