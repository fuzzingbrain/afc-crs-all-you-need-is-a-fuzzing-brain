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
from unittest.mock import patch
import re

from bson import ObjectId

from fuzzingbrain.analyzer.server import (
    AnalysisServer,
    file_basename_pattern,
    select_by_path_suffix,
)
from fuzzingbrain.core.docker_limits import (
    TASK_LABEL,
    kill_task_containers,
    task_label_args,
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


class _Collection:
    """Enough of a pymongo collection to answer one regex find."""

    def __init__(self, docs):
        self.docs = docs

    def find(self, query):
        pat = re.compile(query["file_path"]["$regex"])
        return [
            dict(d)
            for d in self.docs
            if d["task_id"] == query["task_id"] and pat.search(d["file_path"])
        ]


def test_sync_lookup_finds_functions_for_a_repo_relative_diff_path():
    tid = ObjectId()
    docs = [
        {"_id": 1, "task_id": tid, "name": "Curl_getn_scheme_handler", "file_path": "url.c"},
        {"_id": 2, "task_id": tid, "name": "curl_url", "file_path": "urlapi.c"},
        {"_id": 3, "task_id": ObjectId(), "name": "other_task", "file_path": "url.c"},
    ]
    server = SimpleNamespace(
        task_id=tid,
        repos=SimpleNamespace(functions=SimpleNamespace(collection=_Collection(docs))),
    )
    got = AnalysisServer._get_functions_by_file_sync(server, "lib/url.c")
    assert [f["name"] for f in got] == ["Curl_getn_scheme_handler"]
    assert "_id" not in got[0]
    assert AnalysisServer._get_functions_by_file_sync(server, "") == []


def test_task_label_args():
    assert task_label_args("abc") == ["--label", f"{TASK_LABEL}=abc"]
    assert task_label_args("") == []


def test_kill_task_containers_kills_only_what_the_label_lists():
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["docker", "ps"]:
            return SimpleNamespace(stdout="aaa\nbbb\n", returncode=0)
        return SimpleNamespace(stdout="", returncode=0)

    with patch("fuzzingbrain.core.docker_limits.subprocess.run", side_effect=fake_run):
        assert kill_task_containers("t1") == 2
    assert calls[0] == ["docker", "ps", "-q", "--filter", f"label={TASK_LABEL}=t1"]
    assert calls[1] == ["docker", "kill", "aaa", "bbb"]


def test_kill_task_containers_is_a_no_op_without_matches():
    with patch(
        "fuzzingbrain.core.docker_limits.subprocess.run",
        return_value=SimpleNamespace(stdout="", returncode=0),
    ) as run:
        assert kill_task_containers("t1") == 0
        assert run.call_count == 1
    assert kill_task_containers("") == 0
