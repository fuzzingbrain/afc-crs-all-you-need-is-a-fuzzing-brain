# SPDX-License-Identifier: Apache-2.0
"""
Diff paths versus the function index.

The index stores whatever DWARF recorded ("url.c", "../lib/nonblock.c",
"/src/curl/lib/url.c"); a diff names files repo-relative ("lib/url.c").
The old lookup used the diff path as an unescaped, unanchored regex, so
"lib/url.c" matched nothing and every delta run reported "No functions
changed in diff" against a 24k-function index.
"""

from types import SimpleNamespace
import re
from unittest.mock import patch


from fuzzingbrain.analyzer.server import (
    AnalysisServer,
    file_basename_pattern,
    select_by_path_suffix,
)
from fuzzingbrain.core.docker_limits import (
    RUN_LABEL,
    kill_run_containers,
    run_label_args,
)


def test_pattern_matches_basename_wherever_the_index_put_it():
    pat = re.compile(file_basename_pattern("lib/url.c"))
    for stored in ("url.c", "../lib/url.c", "/src/curl/lib/url.c"):
        assert pat.search(stored), stored


def test_pattern_is_anchored_and_escaped():
    pat = re.compile(file_basename_pattern("lib/url.c"))
    for other in ("curl_url.c", "urlapi.c", "url.cc", "urlXc"):
        assert not pat.search(other), other


def test_empty_or_dotty_path_yields_no_pattern():
    assert file_basename_pattern("") is None
    assert file_basename_pattern("../") is None


def test_suffix_narrows_when_directories_can_agree():
    docs = [
        {"file_path": "url.c"},
        {"file_path": "tests/url.c"},
        {"file_path": "/src/curl/lib/url.c"},
    ]
    assert select_by_path_suffix(docs, "lib/url.c") == [docs[2]]


def test_suffix_keeps_everything_when_only_basenames_agree():
    docs = [{"file_path": "url.c"}, {"file_path": "tests/url.c"}]
    assert select_by_path_suffix(docs, "lib/url.c") == docs
    assert select_by_path_suffix(docs, "url.c") == docs


def test_sync_lookup_finds_functions_for_a_repo_relative_diff_path(tmp_path):
    from fuzzingbrain.graph import CallGraph
    from fuzzingbrain.graph.schema import create

    db = create(tmp_path / "g.sqlite")
    db.executemany(
        "INSERT INTO functions (name, file_path, start_line, end_line) VALUES (?,?,?,?)",
        [("Curl_getn_scheme_handler", "url.c", 10, 20), ("curl_url", "urlapi.c", 5, 9),
         ("tests_url", "tests/url.c", 1, 3)],
    )
    db.commit()
    db.close()
    server = SimpleNamespace(graph=CallGraph(tmp_path / "g.sqlite"),
                             _public=AnalysisServer._public)
    got = AnalysisServer._get_functions_by_file_sync(server, "lib/url.c")
    # Same basename, never "urlapi.c"; neither candidate shares "lib/", so the
    # directory cannot narrow them and both are kept.
    assert [f["name"] for f in got] == ["Curl_getn_scheme_handler", "tests_url"]
    assert "id" not in got[0]
    assert AnalysisServer._get_functions_by_file_sync(server, "") == []


def test_run_label_args():
    assert run_label_args("abc") == ["--label", f"{RUN_LABEL}=abc"]
    assert run_label_args("") == []


def test_kill_run_containers_kills_only_what_the_label_lists():
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["docker", "ps"]:
            return SimpleNamespace(stdout="aaa\nbbb\n", returncode=0)
        return SimpleNamespace(stdout="", returncode=0)

    with patch("fuzzingbrain.core.docker_limits.subprocess.run", side_effect=fake_run):
        assert kill_run_containers("t1") == 2
    assert calls[0] == ["docker", "ps", "-q", "--filter", f"label={RUN_LABEL}=t1"]
    assert calls[1] == ["docker", "kill", "aaa", "bbb"]


def test_kill_run_containers_is_a_no_op_without_matches():
    with patch(
        "fuzzingbrain.core.docker_limits.subprocess.run",
        return_value=SimpleNamespace(stdout="", returncode=0),
    ) as run:
        assert kill_run_containers("t1") == 0
        assert run.call_count == 1
    assert kill_run_containers("") == 0
