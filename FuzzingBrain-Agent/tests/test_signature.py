# SPDX-License-Identifier: Apache-2.0
"""Crash signature (ported from fbv2): the sanitizer class + innermost project
frames, harness/runtime frames stripped. Pinned on the real cups-01 ASan
report so "distinct" here means what it means in the bench grader."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent.signature import compute_signature, extract_class  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "trace"

CUPS_ASAN = """==2944161==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602 at pc 0x555
READ of size 1 at 0x602 thread T0
    #0 0x5555556c1c72 in cupsUTF8ToCharset /src/cups/cups/transcode.c:245:12
    #1 0x5555556c0e08 in LLVMFuzzerTestOneInput /src/harness/harness.cc:19:3
    #2 0x5555555e7013 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/x/harness+0x93013)
    #3 0x5555555d101f in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/x/harness+0x7d01f)
"""

LEAK = """==42==ERROR: LeakSanitizer: detected memory leaks
Direct leak of 40 byte(s) in 1 object(s) allocated from:
    #0 0x4a in malloc
    #1 0x5b in hashmgr_add /src/hunspell/src/hunspell/hashmgr.cxx:120:9
"""


def test_class_extraction():
    assert extract_class(CUPS_ASAN) == "heap-buffer-overflow"
    assert extract_class(LEAK) == "memory-leak"
    assert extract_class("nothing here") == ""


def test_cups_signature_drops_harness_and_runtime():
    sig = compute_signature(CUPS_ASAN, harness_names=["harness"])
    assert sig.crash_class == "heap-buffer-overflow"
    # only the project frame survives; harness + fuzzer runtime frames dropped
    assert sig.frames and sig.frames[0][0] == "cupsUTF8ToCharset"
    assert all(f[0] != "LLVMFuzzerTestOneInput" for f in sig.frames)
    assert all("fuzzer::" not in f[0] for f in sig.frames)
    # faulting frame keeps its line
    assert "cupsUTF8ToCharset@transcode.c:245" in sig.key


def test_same_place_same_signature_diff_line_differs():
    a = compute_signature(CUPS_ASAN, harness_names=["harness"])
    b = compute_signature(CUPS_ASAN.replace(":245:12", ":245:99"), harness_names=["harness"])
    # column differs, line same -> same signature (line is what matters, not column)
    assert a.key == b.key
    c = compute_signature(CUPS_ASAN.replace(":245:12", ":600:1"), harness_names=["harness"])
    assert a.key != c.key           # a different line in the same function is a different bug


def test_leak_signature():
    sig = compute_signature(LEAK, harness_names=[])
    assert sig.crash_class == "memory-leak"
    assert sig.frames[0][0] == "hashmgr_add"     # malloc runtime frame dropped, project frame kept


def test_real_fixture_matches():
    raw = (FIX / "cups-crash.raw.txt").read_text()
    sig = compute_signature(raw, harness_names=["harness"])
    assert sig.crash_class == "heap-buffer-overflow"
    assert sig.frames[0][0] == "cupsUTF8ToCharset"
    assert sig.short and len(sig.short) == 16
