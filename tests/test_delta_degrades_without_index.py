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


# ------------------------------------------------------------------ seeding


def test_seeding_falls_back_to_suspicious_points(diff_file):
    """Seed generation used to require the mapped function list, so a run
    without an index produced no diff-guided seeds even after the find phase
    had produced suspicious points -- which name a function, a vulnerability
    type and a description, and are richer seeding context than that list."""
    import inspect

    from fuzzingbrain.worker.strategies import pov_delta

    src = inspect.getsource(pov_delta.POVDeltaStrategy._generate_delta_seeds)
    assert "not changed_functions and not suspicious_points" in src, (
        "seeding must give up only when there is no lead at all"
    )


def test_seed_agent_tolerates_an_empty_change_list():
    """The prompt section renders only when there are changes, so handing it an
    empty list degrades the prompt rather than breaking the agent."""
    import inspect

    from fuzzingbrain.fuzzer import seed_agent

    src = inspect.getsource(seed_agent)
    assert "if changed_functions:" in src


# --------------------------------------------- the budget follows the work
#
# Degrading to the raw diff made the scan possible; it did not make it
# affordable. On curl-delta-02 the agent made 51 tool calls mapping a 17-file
# diff by hand, hit the cap of 50 iterations still exploring, and recorded no
# suspicious point -- while 97% of the run's dollar budget went unspent. The
# binding constraint was the iteration count, not the money.


def test_an_unmapped_diff_gets_the_larger_budget():
    from fuzzingbrain.worker.strategies.pov_delta import POVDeltaStrategy

    assert (
        POVDeltaStrategy.SP_ITERATIONS_NO_INDEX
        > POVDeltaStrategy.SP_ITERATIONS_WITH_INDEX
    )


def test_the_generator_starts_on_the_mapped_budget():
    """Raising it is a decision made when the diff turns out to be unmapped,
    not the default for every delta scan."""
    import inspect

    from fuzzingbrain.worker.strategies import pov_delta

    src = inspect.getsource(pov_delta.POVDeltaStrategy)
    assert "max_iterations=self.SP_ITERATIONS_WITH_INDEX" in src
    assert "max_iterations = self.SP_ITERATIONS_NO_INDEX" in src


def test_the_raise_is_conditioned_on_having_no_function_list():
    import inspect

    from fuzzingbrain.worker.strategies import pov_delta

    src = inspect.getsource(pov_delta.POVDeltaStrategy)
    i = src.index("max_iterations = self.SP_ITERATIONS_NO_INDEX")
    assert "if not all_changes:" in src[max(0, i - 400) : i]
