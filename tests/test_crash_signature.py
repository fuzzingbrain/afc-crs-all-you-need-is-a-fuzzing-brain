"""A crash's identity, checked against the corpus it has to hold up on.

The bar is two-sided and both sides matter. Distinct bugs must stay distinct --
shadowsocks has five separate overflows inside one function, and a signature
that merges them turns five findings into one. Distinct inputs into one bug must
merge -- mongoose's overflow was reached by three different blobs, and counting
them separately says three where the answer is one.
"""

import json
from pathlib import Path

import pytest

from fuzzingbrain.fuzzer.signature import compute_signature, extract_class

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "internal/challenges.json"


ASAN = """\
==12==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000118
    #0 0x5a1 in json_parse_ex /src/shadowsocks-libev/json.c:310:24
    #1 0x5b2 in json_parse /src/shadowsocks-libev/json.c:958:12
    #2 0x5c3 in LLVMFuzzerTestOneInput /src/json_fuzz.c:12:3
    #3 0x5d4 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)
SUMMARY: AddressSanitizer: heap-buffer-overflow json.c:310 in json_parse_ex
"""

# Same bug, different input: the outer frames differ, the fault does not.
ASAN_OTHER_INPUT = ASAN.replace("#2 0x5c3 in LLVMFuzzerTestOneInput /src/json_fuzz.c:12:3",
                                "#2 0x9f9 in LLVMFuzzerTestOneInput /src/json_fuzz.c:12:3")

# Different bug in the same function: only the faulting line separates them.
ASAN_OTHER_LINE = ASAN.replace("json.c:310:24", "json.c:603:9")

CPP = """\
==7==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x11 in operator new(unsigned long) /usr/lib/asan_new_delete.cpp:95
    #1 0x22 in avifImageYUVToRGB /src/libavif/src/reformat.c:1802:5
    #2 0x33 in avif::testutil::Convert(int) /src/libavif/tests/gtest/x.cc:44
"""


class TestSignatureSeparatesRealBugs:
    """Every bug in the corpus, against every other bug in its challenge."""

    @staticmethod
    def _bundles():
        if not CORPUS.exists():
            pytest.skip("challenge corpus not present")
        for c in json.loads(CORPUS.read_text()):
            vd = c.get("vuln_details") or []
            if len(vd) < 2:
                continue
            crashes = []
            for v in vd:
                f = REPO / c["manifest_dir"] / "bugs" / v["vuln"] / "crash.txt"
                if f.is_file():
                    crashes.append((v["vuln"], f.read_text(errors="replace")))
            if len(crashes) >= 2:
                yield c["challenge"], c["target_harnesses"], crashes

    def test_bugs_in_one_challenge_never_share_a_signature(self):
        collisions = []
        checked = 0
        for challenge, harnesses, crashes in self._bundles():
            seen = {}
            for name, text in crashes:
                key = compute_signature(text, harnesses).key
                checked += 1
                if key in seen:
                    collisions.append(f"{challenge}: {seen[key]} == {name}")
                seen[key] = name
        if checked == 0:
            pytest.skip("no multi-bug bundles on disk")
        assert not collisions, "distinct bugs merged: " + "; ".join(collisions)


class TestSignatureMergesOneBug:
    def test_same_fault_different_input_is_one_signature(self):
        a = compute_signature(ASAN, ["json_fuzz"])
        b = compute_signature(ASAN_OTHER_INPUT, ["json_fuzz"])
        assert a.key == b.key
        assert a.short == b.short

    def test_same_function_different_line_is_two_signatures(self):
        a = compute_signature(ASAN, ["json_fuzz"])
        b = compute_signature(ASAN_OTHER_LINE, ["json_fuzz"])
        assert a.key != b.key

    def test_different_class_is_a_different_bug(self):
        uaf = ASAN.replace("heap-buffer-overflow", "heap-use-after-free")
        assert compute_signature(ASAN, []).key != compute_signature(uaf, []).key


class TestFramesThatAreNotTheProgram:
    def test_harness_frame_is_excluded(self):
        sig = compute_signature(ASAN, ["json_fuzz"])
        assert all("json_fuzz" not in f[1] for f in sig.frames)

    def test_libfuzzer_frame_is_excluded(self):
        sig = compute_signature(ASAN, [])
        assert all("fuzzer::" not in f[0] for f in sig.frames)

    def test_demangled_cpp_operator_is_excluded(self):
        # "operator new(unsigned long)" has a space in it; a parser that stops
        # at the first token records "operator" and lets a runtime frame into
        # the identity of every allocation crash.
        sig = compute_signature(CPP, [])
        assert sig.frames, "expected the project frames to survive"
        assert sig.frames[0][0] == "avifImageYUVToRGB"

    def test_named_harness_is_excluded_by_name(self):
        # AIxCC harnesses are called handler_telnet and TestFuzzCoreServer; no
        # filename pattern covers that, so the name is passed in.
        out = ASAN.replace("json_parse_ex /src/shadowsocks-libev/json.c",
                           "handler_telnet /src/wireshark/handler_telnet.c")
        sig = compute_signature(out, ["handler_telnet"])
        assert all(f[0] != "handler_telnet" for f in sig.frames)


class TestClassExtraction:
    @pytest.mark.parametrize("text,expected", [
        ("ERROR: AddressSanitizer: heap-buffer-overflow on x", "heap-buffer-overflow"),
        ("ERROR: AddressSanitizer: stack-buffer-overflow", "stack-buffer-overflow"),
        ("SUMMARY: AddressSanitizer: LeakSanitizer found leaks", "memory-leak"),
        ("x.c:9:1: runtime error: signed integer overflow: 2 + 2", "undefined-behavior: signed integer overflow: 2 + 2"),
        # DEADLYSIGNAL and "SEGV on unknown address" are one fault under two
        # names; the aliases collapse them so they do not count twice.
        ("==1==ERROR: AddressSanitizer: DEADLYSIGNAL", "segv"),
        ("nothing interesting here", ""),
    ])
    def test_class(self, text, expected):
        assert extract_class(text) == expected

    def test_a_hang_has_no_class_and_no_signature(self):
        hang = "==1== ERROR: libFuzzer: timeout after 25 seconds\n"
        assert extract_class(hang) == ""
        assert not compute_signature(hang, [])
