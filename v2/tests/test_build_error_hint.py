# SPDX-License-Identifier: Apache-2.0
"""The build-error hint turns the common source-drift failure into a fix."""

from fuzzingbrain.analyzer.builder import _build_error_hint


def test_hint_on_missing_source_file():
    out = ["...", "cat: scripts/pnglibconf.dfa: No such file or directory", "failed"]
    hint = _build_error_hint(out)
    assert "-v <commit>" in hint
    assert "drift" in hint.lower()


def test_no_hint_for_unrelated_failure():
    assert _build_error_hint(["error: undefined reference to `foo`"]) == ""


def test_empty_output_no_hint():
    assert _build_error_hint([]) == ""
