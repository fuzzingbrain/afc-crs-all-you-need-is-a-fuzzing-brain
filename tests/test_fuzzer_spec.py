"""@NO_OOM / fuzztest name parsing and the run argv it produces.

The bug this guards: a logical fuzzer name like ``dav1d_fuzzer_mt@NO_OOM`` was
split on ``@`` and turned into ``--fuzz=NO_OOM`` (a bogus fuzztest test), while
the OOM directive it actually meant was never applied. Memory-heavy decoders
then OOM'd before reaching the sink in every run path. These tests lock the
parse + argv down, and make sure plain libFuzzer and real fuzztest targets are
untouched (no regression for other projects).
"""

from fuzzingbrain.core.fuzzer_spec import (
    parse_fuzzer_spec,
    is_no_oom,
    libfuzzer_oom_flags,
)
from fuzzingbrain.tools.gdb_trace import _argv_tmpl_for

OOM = ["-rss_limit_mb=0", "-malloc_limit_mb=0"]


def test_no_oom_is_parsed_and_stripped_to_base():
    base, no_oom, fuzztest = parse_fuzzer_spec("dav1d_fuzzer_mt@NO_OOM")
    assert base == "dav1d_fuzzer_mt"  # the real on-disk binary name
    assert no_oom is True
    assert fuzztest is None  # NO_OOM is a directive, never a fuzztest test


def test_fuzztest_name_is_not_mistaken_for_no_oom():
    base, no_oom, fuzztest = parse_fuzzer_spec("avif_fuzztest_yuvrgb@YuvRgbFuzzTest.Convert")
    assert base == "avif_fuzztest_yuvrgb"
    assert no_oom is False
    assert fuzztest == "YuvRgbFuzzTest.Convert"


def test_plain_libfuzzer_has_no_directives():
    assert parse_fuzzer_spec("handler_openvpn") == ("handler_openvpn", False, None)
    assert is_no_oom("handler_openvpn") is False
    assert libfuzzer_oom_flags(False) == []


def test_both_directives_can_coexist():
    base, no_oom, fuzztest = parse_fuzzer_spec("x@NO_OOM@Test.A")
    assert (base, no_oom, fuzztest) == ("x", True, "Test.A")


def test_argv_no_oom_adds_the_flags():
    argv = _argv_tmpl_for("dav1d_fuzzer_mt@NO_OOM")("/b/input")
    assert argv == ["/b/elf", *OOM, "/b/input"]


def test_argv_plain_libfuzzer_unchanged():
    # regression: must stay exactly [elf, input] -- no stray flags for other projects
    assert _argv_tmpl_for("handler_openvpn")("/b/input") == ["/b/elf", "/b/input"]


def test_argv_fuzztest_unchanged():
    argv = _argv_tmpl_for("avif_fuzztest_yuvrgb@YuvRgbFuzzTest.Convert")("/b/input")
    assert argv == ["/b/elf", "--fuzz=YuvRgbFuzzTest.Convert", "--", "/b/input"]
