# SPDX-License-Identifier: Apache-2.0
"""get_fuzzer_source must find the harness, or say so usefully.

Its own description tells the agent this is the most important tool and to call
it first. On the curl challenge it failed on all four calls with "Fuzzer source
path not available": every lookup it had needed the build to report a source
path, and none of them fires when a run names its fuzzers explicitly. The agent
retried it four times out of fifty iterations and found no suspicious points.
"""

import asyncio
from pathlib import Path

import pytest

from fuzzingbrain.analyzer.server import AnalysisServer


def _server(task_path, project_name="curl", coverage_path=None):
    """A server object with only the attributes the lookup touches."""
    srv = AnalysisServer.__new__(AnalysisServer)
    srv.task_path = Path(task_path)
    srv.project_name = project_name
    srv.coverage_path = str(coverage_path) if coverage_path else None
    return srv


@pytest.fixture
def workspace(tmp_path):
    """Shaped like the curl challenge: the harness lives outside the repo, and
    only the coverage build leaves a copy of it on disk."""
    ws = tmp_path / "curl_task"
    (ws / "repo" / "lib").mkdir(parents=True)
    (ws / "repo" / "lib" / "ws.c").write_text("/* not a harness */\n")

    proj = ws / "fuzz-tooling" / "projects" / "curl"
    proj.mkdir(parents=True)
    (proj / "curl_fuzzer_ws.options").write_text("[libfuzzer]\n")

    cov = ws / "fuzz-tooling" / "build" / "out" / "curl_coverage"
    src = cov / "src" / "curl_fuzzer"
    src.mkdir(parents=True)
    (src / "curl_fuzzer.cc").write_text("int LLVMFuzzerTestOneInput(){return 0;}\n")
    (src / "curl_fuzzer.h").write_text("void decl(void);\n")
    (src / "fuzz_url.cc").write_text("int LLVMFuzzerTestOneInput(){return 1;}\n")
    return ws, cov


# ------------------------------------------------------------ name candidates


def test_a_variant_name_falls_back_to_its_base():
    """curl builds seventeen named binaries from one curl_fuzzer.cc."""
    srv = _server("/nowhere")
    assert srv._harness_name_candidates("curl_fuzzer_ws") == [
        "curl_fuzzer_ws",
        "curl_fuzzer",
    ]


def test_stripping_stops_before_the_name_stops_being_a_harness():
    """Otherwise curl_fuzzer_ws decays to 'curl' and matches any curl.c."""
    assert "curl" not in _server("/nowhere")._harness_name_candidates("curl_fuzzer_ws")


def test_a_name_with_nothing_to_strip_is_tried_once():
    srv = _server("/nowhere")
    assert srv._harness_name_candidates("libpng_read_fuzzer") == ["libpng_read_fuzzer"]


# ------------------------------------------------------------------- searching


def test_the_coverage_tree_is_searched_when_the_repo_has_no_harness(workspace):
    ws, cov = workspace
    hit = _server(ws, coverage_path=cov)._search_fuzzer_source("curl_fuzzer_ws")
    assert hit is not None and hit.name == "curl_fuzzer.cc"


def test_a_harness_with_its_own_file_is_not_collapsed(workspace):
    ws, cov = workspace
    hit = _server(ws, coverage_path=cov)._search_fuzzer_source("fuzz_url")
    assert hit is not None and hit.name == "fuzz_url.cc"


def test_a_header_is_never_the_answer(workspace):
    ws, cov = workspace
    hit = _server(ws, coverage_path=cov)._search_fuzzer_source("curl_fuzzer")
    assert hit is not None and hit.suffix != ".h"


def test_the_repo_wins_over_the_coverage_tree(workspace):
    """A harness kept in the scanned repo is the one being scanned."""
    ws, cov = workspace
    (ws / "repo" / "contrib").mkdir()
    own = ws / "repo" / "contrib" / "curl_fuzzer.cc"
    own.write_text("int LLVMFuzzerTestOneInput(){return 2;}\n")
    hit = _server(ws, coverage_path=cov)._search_fuzzer_source("curl_fuzzer_ws")
    assert hit == own


def test_nothing_on_disk_returns_none(workspace):
    ws, cov = workspace
    assert _server(ws, coverage_path=cov)._search_fuzzer_source("gzip_fuzzer") is None


def test_a_missing_coverage_build_is_not_an_error(workspace):
    ws, _ = workspace
    assert _server(ws, coverage_path=None)._search_fuzzer_source("curl_fuzzer") is None


# --------------------------------------------------------------- the message


class _Fuzzer:
    def __init__(self, name):
        self.name = name
        self.source_path = None


def _lookup(ws, cov, name):
    srv = _server(ws, coverage_path=cov)
    srv.fuzzers = [_Fuzzer(name)]
    srv.fuzzer_sources = {}
    srv.repos = None
    srv._log = lambda *a, **k: None
    return asyncio.run(srv._get_fuzzer_source(name))


def test_a_found_harness_comes_back_with_its_source(workspace):
    ws, cov = workspace
    result = _lookup(ws, cov, "curl_fuzzer_ws")
    assert "error" not in result
    assert "LLVMFuzzerTestOneInput" in result["source"]


def test_the_failure_tells_the_agent_what_to_do_instead(workspace):
    """The old text named neither a cause nor a next step, so the model's only
    move was to call it again."""
    ws, cov = workspace
    err = _lookup(ws, cov, "gzip_fuzzer")["error"]
    assert "do not" in err.lower() and "retry" in err.lower()
    assert "Glob(" in err and "Read" in err


# ------------------------------------------------- the header comes with it
#
# curl-delta-02, second attempt: the agent found the right function, learned
# the harness's TLV wire format, used the invented protocol scheme and put the
# exact trigger string -- CRLF included -- in seventeen of eighteen candidates.
# None crashed. The TLV type numbers are all #defines in curl_fuzzer.h, which
# get_fuzzer_source did not return, so it inferred the response slots were
# consecutive (2, 3, 4, 5) where they are 2, 17, 18, 19. Every trigger landed
# in the field that means POSTFIELDS.


def test_the_same_stem_header_is_returned_with_the_source(workspace):
    ws, cov = workspace
    result = _lookup(ws, cov, "curl_fuzzer_ws")
    assert isinstance(result["source_path"], list)
    assert any(p.endswith("curl_fuzzer.h") for p in result["source_path"])
    assert "void decl(void);" in result["source"], "header content, not just its name"


def test_the_source_still_comes_first(workspace):
    """The entry point is what the agent reads first; the header supports it."""
    ws, cov = workspace
    src = _lookup(ws, cov, "curl_fuzzer_ws")["source"]
    assert src.index("LLVMFuzzerTestOneInput") < src.index("void decl(void);")


def test_an_unrelated_header_is_not_dragged_in(workspace):
    ws, cov = workspace
    (cov / "src" / "curl_fuzzer" / "unrelated.h").write_text("#define NOPE 1\n")
    assert "NOPE" not in _lookup(ws, cov, "curl_fuzzer_ws")["source"]


def test_a_harness_without_a_header_is_unaffected(workspace):
    ws, cov = workspace
    result = _lookup(ws, cov, "fuzz_url")
    assert "error" not in result
    assert isinstance(result["source_path"], str), "one file, reported as one"


def test_the_fallback_returns_an_absolute_path(workspace):
    """_resolve_source_file only understands an absolute path or one relative
    to the workspace; a cwd-relative path resolves to None and the harness
    reads as missing all over again."""
    ws, cov = workspace
    hit = _server(ws, coverage_path=cov)._search_fuzzer_source("curl_fuzzer_ws")
    assert hit is not None and hit.is_absolute()
