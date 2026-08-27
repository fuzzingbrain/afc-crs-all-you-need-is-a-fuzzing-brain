# SPDX-License-Identifier: Apache-2.0
"""A delta scan runs on the diff alone when there is no function index.

Mapping changed lines to changed functions reads the function index, so a run
without one identifies nothing from a perfectly good diff. That has to degrade,
not skip: the mapping is a filter that lets the agent ignore unreachable
changes, and the delta prompt's first instruction is to read the diff anyway.
"""

from types import SimpleNamespace

import pytest

from fuzzingbrain.worker.strategies.pov_delta import POVDeltaStrategy

DIFF = """diff --git a/pngrutil.c b/pngrutil.c
--- a/pngrutil.c
+++ b/pngrutil.c
@@ -1419,12 +1419,13 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr)
-      char keyword[81];
+      wpng_byte keyword[max_keyword_wbytes];
-      read_length = 81;
+      read_length = sizeof(keyword);
"""


class _Strategy(POVDeltaStrategy):
    """Only the diff plumbing; nothing else in the strategy is exercised."""

    def __init__(self, diff_path):
        self.diff_path = diff_path
        self._all_changes = []
        self.logged = []

    def _log(self, msg, level="INFO"):
        self.logged.append((level, msg))

    log_info = log_warning = log_error = log_debug = _log


@pytest.fixture
def diff_file(tmp_path):
    p = tmp_path / "ref.diff"
    p.write_text(DIFF)
    return p


def test_a_diff_with_content_is_recognised(diff_file):
    assert _Strategy(diff_file)._diff_has_content() is True


def test_an_empty_diff_is_not_content(tmp_path):
    empty = tmp_path / "ref.diff"
    empty.write_text("   \n\n")
    assert _Strategy(empty)._diff_has_content() is False


def test_a_missing_diff_is_not_content(tmp_path):
    assert _Strategy(tmp_path / "absent.diff")._diff_has_content() is False


def test_no_diff_path_at_all_is_not_content():
    assert _Strategy(None)._diff_has_content() is False


def test_the_hunk_header_names_the_function_the_index_would_have_found(diff_file):
    """Why degrading is reasonable: git puts the enclosing function in the hunk
    header, so the agent reading the diff sees what the mapping would report."""
    assert "png_handle_iCCP" in diff_file.read_text()


def test_generator_prompt_survives_an_empty_change_list():
    """The changed-functions section renders empty rather than breaking, and the
    prompt still tells the agent to call get_diff first."""
    from fuzzingbrain.agents.sp_generators import DeltaSPGenerator

    section = DeltaSPGenerator._format_changed_functions_section(SimpleNamespace(), [])
    assert section == ""
