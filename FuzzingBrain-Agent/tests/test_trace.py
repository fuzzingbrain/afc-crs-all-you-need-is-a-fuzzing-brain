# SPDX-License-Identifier: Apache-2.0
"""The trace tool's report, from the tracer's real gdb output.

The fixtures are unedited `gdb -x gdb_tracer.py` output for five inputs on two
graded binaries (libpng-01, cups-01) -- a signature failure, a run that stops
mid-parse on "read error", a "valid" PNG that still errors, an ASan crash, and
a clean run. The report is what the model reads; these pin what it must say.

    python3 -m pytest FuzzingBrain-Agent/tests/test_trace.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent.tools import _summarize_trace, _trace_events, _fmt_arg  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "trace"


def _raw(name: str) -> str:
    return (FIX / f"{name}.raw.txt").read_text()


def test_events_parse():
    evs = _trace_events(_raw("libpng-short"))
    kinds = {e["ev"] for e in evs}
    assert {"setup", "call", "ret", "stop", "ret_lost", "exit", "seq", "counts"} <= kinds
    ex = [e for e in evs if e["ev"] == "exit"][-1]
    assert ex["outcome"] == "exited" and ex["code"] == 0 and ex["hits"] > 50


def test_short_input_why_it_stopped():
    """IHDR parsed, then the second chunk header ran out of bytes: the report
    must name the message, who raised it, and that png_read_info never returned."""
    rep = _summarize_trace(_raw("libpng-short"),
                           ["png_sig_cmp", "png_read_info", "png_handle_IHDR", "png_read_IDAT_data"],
                           verbose=True)
    assert "outcome: no crash; the program gave up (longjmp" in rep
    assert 'error_message="read error"' in rep
    assert "user_read_data  (harness.cc:67)" in rep
    assert "png_read_chunk_header  (pngrutil.c:196)" in rep
    assert "png_sig_cmp: reached (2 calls)" in rep and "returned 0 -> harness.cc:186" in rep
    assert "png_handle_IHDR: reached (1 call)" in rep and "returned handled_ok" in rep
    assert "png_read_info: reached (1 call)" in rep and "never returned" in rep
    assert "png_read_IDAT_data: NOT reached" in rep
    assert "call sequence" in rep and "    png_read_info" in rep
    # one longjmp is one stop, not one per alias breakpoint
    assert "more such stop" not in rep


def test_valid_png_still_errors():
    rep = _summarize_trace(_raw("libpng-valid"),
                           ["png_read_info", "png_handle_IHDR", "png_read_IDAT_data", "png_read_end"],
                           verbose=True)
    assert 'error_message="PNG unsigned integer out of range"' in rep
    assert "png_get_uint_31  (pngrutil.c:46)" in rep and "buf=bytes[" in rep
    assert "png_read_info: reached (1 call)" in rep and "returned (void) -> harness.cc:282" in rep
    assert "png_read_IDAT_data: reached (1 call)" in rep
    assert "png_read_end: reached (1 call)" in rep and "never returned" in rep


def test_signature_failure_is_short():
    rep = _summarize_trace(_raw("libpng-badsig"), [])
    assert "outcome: no crash; ran to the end, process exit code 0" in rep
    assert "deepest call: png_sig_cmp" in rep
    assert "targets:" not in rep            # none asked for
    assert len(rep.splitlines()) < 12


def test_crash_reports_sanitizer_site():
    rep = _summarize_trace(_raw("cups-crash"), ["cupsUTF8ToCharset"], verbose=True)
    assert "outcome: CRASHED — SIGABRT" in rep
    assert "heap-buffer-overflow" in rep
    assert "cupsUTF8ToCharset  (transcode.c:245:12)" in rep
    assert "LLVMFuzzerTestOneInput  (harness.cc:19:3)" in rep
    # only the fault stack, not the "allocated by" stack that follows it
    assert rep.count("LLVMFuzzerTestOneInput  (harness.cc:") == 1
    assert "cupsUTF8ToCharset: reached (1 call)" in rep and "never returned" in rep


def test_clean_run_reports_return_value():
    rep = _summarize_trace(_raw("cups-clean"), ["cupsUTF8ToCharset"], verbose=True)
    assert "outcome: no crash; ran to the end, process exit code 0" in rep
    assert "returned 1 -> harness.cc:20" in rep
    brief = _summarize_trace(_raw("cups-clean"), ["cupsUTF8ToCharset"])
    assert "cupsUTF8ToCharset: reached (1 call); returned 1" in brief


def test_report_is_bounded():
    for name in ("libpng-short", "libpng-valid"):
        rep = _summarize_trace(_raw(name), ["png_read_info"], verbose=True)
        assert len(rep) < 6000 and len(rep.splitlines()) < 100
        brief = _summarize_trace(_raw(name), ["png_read_info"])
        assert len(brief.splitlines()) <= 10


def test_brief_is_the_default_and_answers_the_question():
    """Brief: did it get there, and if not what rejected it -- no sequence, no
    function list, no arguments, one line on why it stopped."""
    rep = _summarize_trace(_raw("libpng-short"), ["png_read_info", "png_read_IDAT_data"])
    assert "call sequence (indent" not in rep and "functions reached" not in rep
    assert "args at first call" not in rep
    assert 'why: "read error" raised from (anonymous namespace)::user_read_data (harness.cc:67)' in rep
    assert "user_read_data (harness.cc:67) ← png_read_chunk_header (pngrutil.c:196) ← png_read_info" in rep
    assert "png_read_info: reached (1 call); 1 call(s) never returned" in rep
    assert "png_read_IDAT_data: NOT reached" in rep
    assert "verbose=true" in rep
    rep2 = _summarize_trace(_raw("libpng-valid"), [])
    assert 'why: "PNG unsigned integer out of range" raised from png_get_uint_31 (pngrutil.c:46)' in rep2
    assert "targets:" not in rep2


def test_legacy_output_still_parses():
    """A bench that has not picked up the tracer returns the one-breakpoint
    script's output; the report must degrade to the old reached/crashed lines."""
    raw = ("Breakpoint 1 at 0x1: file x.c, line 1.\n@@REACHED foo@@\na = 1\n#0 foo (a=1) at x.c:1\n"
           "@@ENDED@@\n")
    rep = _summarize_trace(raw, ["foo"])
    assert rep.startswith("reached foo: YES")
    assert "crashed: no" in rep


def test_arg_formatting():
    assert _fmt_arg('error_message=0x5555 <str> "read error"  bytes=72 65') == 'error_message="read error"'
    assert _fmt_arg('buf=0x7f "\\311\\376", <incomplete sequence \\357>  bytes=c9 fe 92 ef') == "buf=bytes[c9 fe 92 ef]"
    assert _fmt_arg("size=<optimized out>") == "size=?"
    assert _fmt_arg("n=8") == "n=8"
