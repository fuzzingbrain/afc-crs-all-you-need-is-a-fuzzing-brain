# SPDX-License-Identifier: Apache-2.0
"""Tests for the deterministic static substrate (fbagent/analysis.py).

These pin the behaviour that the whole "credibility" argument rests on: the
segmenter must not mistake a call site for a definition, the graph must root at
the harness entry and rank sinks by real reachability, the crash-stack parser
must recover the frames, and the gate extractor must read literal constraints
off the source. All pure computation -- no model, no network, no image.

    python3 -m pytest FuzzingBrain-Agent/tests/test_analysis.py
"""
from __future__ import annotations

from pathlib import Path

from fbagent import analysis


# ------------------------------------------------------------------ segmentation

def test_segmenter_ignores_call_sites():
    """The bug the fix closes: `malloc(...)` inside an `if` is a call, not a def."""
    src = """
int real(int n) {
    char *src;
    if (!(src = malloc(n + 1))) { return -1; }
    memcpy(src, data, n);
    for (int i = 0; i < n; i++) { sink(i); }
    return 0;
}
static void helper(void) { real(3); }
"""
    names = [s[0] for s in analysis._segment_functions(src)]
    assert "real" in names and "helper" in names
    for spurious in ("malloc", "memcpy", "if", "for", "sink"):
        assert spurious not in names, f"{spurious} mis-parsed as a function"


def test_segmenter_masks_strings_and_comments():
    """A `{` in a string or a def-looking line in a comment must not count."""
    src = '''
void f(void) { const char *s = "a { b ( c"; g(s); }
// void ghost(void) { should_not_appear(); }
/* void ghost2(void) { nope(); } */
void real2(void) { f(); }
'''
    names = [s[0] for s in analysis._segment_functions(src)]
    assert names.count("f") == 1
    assert "real2" in names
    assert "ghost" not in names and "ghost2" not in names


def test_segmenter_finds_cpp_qualified_method():
    src = "int Foo::bar(int x) const { return x + baz(x); }\n"
    names = [s[0] for s in analysis._segment_functions(src)]
    assert "bar" in names


# ------------------------------------------------------------------ crash stack (P4)

def test_crash_frames_asan():
    log = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "    #0 0x1 in __asan_memcpy /rt/asan.cpp:22:3\n"
        "    #1 0x2 in LLVMFuzzerTestOneInput harness/harness.cc:16:5\n"
        "    #2 0x3 in main /fuzzer/Main.cpp:20\n"
    )
    fr = analysis.crash_frames(log)
    assert [f.func for f in fr] == ["__asan_memcpy", "LLVMFuzzerTestOneInput", "main"]
    assert fr[1].file == "harness/harness.cc" and fr[1].line == 16


def test_crash_frames_java():
    log = (
        "== Java Exception: java.lang.ArrayIndexOutOfBoundsException\n"
        "\tat com.example.Parser.read(Parser.java:88)\n"
        "\tat com.example.Fuzz.fuzzerTestOneInput(Fuzz.java:12)\n"
    )
    fr = analysis.crash_frames(log)
    assert fr and fr[0].func == "com.example.Parser.read"
    assert fr[0].file == "Parser.java" and fr[0].line == 88


# ------------------------------------------------------------------ gates (P7)

def test_gate_regexes_read_literals():
    body = 'if (memcmp(p, "GIF89a", 6)) return; if (size < 16) return; if (buf[0] == 0xff) go();'
    assert analysis._G_MEMCMP.search(body).group(1) == "GIF89a"
    assert analysis._G_LEN.search(body)
    assert analysis._G_BYTEEQ.search(body)


# ------------------------------------------------------------------ end-to-end on a tiny tree

def test_analyze_tiny_tree(tmp_path: Path):
    (tmp_path / "harness").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "harness" / "harness.cc").write_text(
        'extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n'
        "    parse(data, size);\n"
        "    return 0;\n"
        "}\n"
    )
    (tmp_path / "src" / "p.c").write_text(
        "void parse(const unsigned char *d, unsigned long n) {\n"
        '    if (memcmp(d, "MZ", 2)) return;\n'
        "    char buf[8];\n"
        "    memcpy(buf, d, n);\n"          # the sink
        "}\n"
        "void unreachable(void) { boom(); }\n"
    )
    out = analysis.analyze(tmp_path)
    assert out["entry"] == "LLVMFuzzerTestOneInput"
    funcs = {s["func"] for s in out["reachable_sinks"]}
    assert "parse" in funcs                       # the sink's function is reachable
    assert "unreachable" not in funcs             # and the dead one is not
    g = analysis.gates_to(tmp_path, "parse")
    assert "MZ" in g                              # the magic gate is recovered


def test_crash_frames_submit_stripped_format():
    """The bug reached hit in the wild: ./submit prints frames as `#N func file:line`
    (the `0x.. in` stripped). reached must parse that, not only raw ASan frames."""
    log = ("crash: the harness faulted under the sanitizer (segv).\n"
           "stack (where it crashed):\n"
           "  #0 hwdb_add_property  /src/systemd/src/libsystemd/sd-hwdb/sd-hwdb.c:121\n"
           "  #1 trie_search_f  /src/systemd/src/libsystemd/sd-hwdb/sd-hwdb.c:273\n"
           "  #2 LLVMFuzzerTestOneInput  /src/systemd/src/libsystemd/sd-hwdb/fuzz-hwdb.c:47")
    fr = analysis.crash_frames(log)
    assert [f.func for f in fr] == ["hwdb_add_property", "trie_search_f", "LLVMFuzzerTestOneInput"]
    assert fr[0].line == 121
