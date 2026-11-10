"""The function index: llvm-cov export, and the symbol fallback for a prebuilt."""

from __future__ import annotations

import json
import subprocess

import pytest

from fbv3.fuzz import coverage, symbols

EXPORT = {
    "data": [{
        "functions": [
            {"name": "deflate", "count": 17, "filenames": ["/src/zlib/deflate.c"],
             "regions": [[100, 1, 180, 2, 17, 0, 0, 0]]},
            {"name": "infback.c:never_run", "count": 0, "filenames": ["/src/zlib/infback.c"],
             "regions": [[10, 1, 40, 2, 0, 0, 0, 0]]},
            {"name": "libfuzzer_internal", "count": 5, "filenames": ["/src/libfuzzer/FuzzerLoop.cpp"],
             "regions": [[1, 1, 5, 2, 5, 0, 0, 0]]},
            {"name": "std_thing", "count": 3, "filenames": ["/usr/include/c++/v1/vector"],
             "regions": [[1, 1, 5, 2, 3, 0, 0, 0]]},
            {"name": "templated", "count": 2, "filenames": ["/src/p/t.cc"],
             "regions": [[5, 1, 9, 2, 2, 0, 0, 0]]},
            {"name": "templated", "count": 9, "filenames": ["/src/p/t.cc"],
             "regions": [[5, 1, 30, 2, 9, 0, 0, 0]]},
        ]
    }]
}


def test_a_static_functions_name_is_the_one_in_the_source():
    """llvm-cov qualifies internal linkage by file: trees.c:pqdownheap."""
    rows = {r.name: r for r in coverage.parse_export(EXPORT)}
    assert "never_run" in rows and "infback.c:never_run" not in rows
    assert coverage._plain_name("deflate", "/src/zlib/deflate.c") == "deflate"
    assert coverage._plain_name("other.c:f", "/src/zlib/deflate.c") == "other.c:f"


def test_parse_export_keeps_project_functions_only():
    rows = {r.name: r for r in coverage.parse_export(EXPORT)}
    assert set(rows) == {"deflate", "never_run", "templated"}
    assert rows["deflate"].execution_count == 17
    assert (rows["deflate"].start_line, rows["deflate"].end_line) == (100, 180)
    assert rows["never_run"].execution_count == 0  # linked but not executed: the B set


def test_instantiations_of_one_function_merge_to_the_widest_and_hottest():
    rows = {r.name: r for r in coverage.parse_export(EXPORT)}
    assert rows["templated"].execution_count == 9
    assert rows["templated"].end_line == 30


def test_parse_export_survives_empty_input():
    assert coverage.parse_export({}) == []
    assert coverage.parse_export({"data": [{"functions": []}]}) == []


def test_the_export_script_is_bounded_and_isolated():
    script = coverage.export_script("/ws/out/coverage/fuzz", "/ws/fuzz/global/corpus", "/ws/coverage/prof-a")
    assert "timeout 30" in script  # one slow input cannot hang the export
    assert "/ws/coverage/prof-a" in script and "rm -rf /ws/coverage/prof-a" in script
    assert "PATH=/ws/out/llvm" in script  # the tools that match the build
    assert "empty_input" in script  # always at least one profile


def test_index_round_trip(tmp_path):
    rows = coverage.parse_export(EXPORT)
    path = tmp_path / "index.json"
    coverage.write_index(rows, path)
    assert {r.name for r in coverage.load_index(path)} == {r.name for r in rows}
    assert coverage.load_index(tmp_path / "missing.json") == []
    assert json.loads(path.read_text())[0]["name"]


def test_snapshot_counts_only_what_ran(tmp_path):
    summary = coverage.snapshot(coverage.parse_export(EXPORT), tmp_path / "snap.json")
    assert summary["functions_total"] == 3 and summary["functions_covered"] == 2
    assert summary["covered_names"] == ["deflate", "templated"]


class FakeWS:
    """A workspace whose exec returns scripted bytes."""

    def __init__(self, tmp_path, stdout=b"", code=0):
        self.root = tmp_path
        self.stdout, self.code = stdout, code

    def exec(self, argv, *, timeout=600, **kw):
        return subprocess.CompletedProcess(argv, self.code, self.stdout, b"boom")

    def to_host(self, path):
        if path.startswith("/src/"):
            return self.root / "src" / path[5:]
        if path.startswith("/ws/"):
            return self.root / path[4:]
        raise ValueError(path)


def test_a_failed_export_is_reported_not_raised(tmp_path):
    rows, err = coverage.collect_functions(FakeWS(tmp_path, code=1), coverage_binary="/ws/b",
                                           corpus_dir="/ws/c")
    assert rows == [] and "coverage export failed" in err and "boom" in err


def test_non_json_output_is_reported(tmp_path):
    rows, err = coverage.collect_functions(FakeWS(tmp_path, stdout=b"not json"), coverage_binary="/ws/b",
                                          corpus_dir="/ws/c")
    assert rows == [] and "did not produce JSON" in err


def test_collect_functions_parses_a_good_export(tmp_path):
    ws = FakeWS(tmp_path, stdout=json.dumps(EXPORT).encode())
    rows, err = coverage.collect_functions(ws, coverage_binary="/ws/b", corpus_dir="/ws/c")
    assert not err and len(rows) == 3


# -- the symbol fallback -----------------------------------------------------------------------

SYMS = "0x401000\tdeflate\n0x402000\tinflate\n0x403000\tLLVMFuzzerTestOneInput\n"
LOCS = """\
deflate
/src/zlib/deflate.c:100:0

inflate
/src/zlib/inflate.c:50:0

LLVMFuzzerTestOneInput
/src/harness.c:10:0

"""


def test_symbols_give_an_index_when_there_is_no_coverage_build(tmp_path):
    (tmp_path / "src" / "zlib").mkdir(parents=True)
    (tmp_path / "src" / "zlib" / "deflate.c").write_text("\n" * 99 + "int deflate(void) {\n  x();\n}\n")
    ws = FakeWS(tmp_path, stdout=(SYMS + "==FBV3-SPLIT==\n" + LOCS).encode())
    rows, err = symbols.linked_functions(ws, binary="/ws/out/address/fuzz")
    assert not err
    by = {r.name: r for r in rows}
    assert by["deflate"].file == "/src/zlib/deflate.c" and by["deflate"].start_line == 100
    assert by["deflate"].end_line == 102  # the closing brace
    assert all(r.execution_count == 0 for r in rows)  # linked is not executed


def test_symbols_skip_non_project_files(tmp_path):
    locs = "memcpy\n/usr/include/string.h:1:0\n\nok\n/src/a.c:5:0\n\n"
    ws = FakeWS(tmp_path, stdout=("0x1\tmemcpy\n0x2\tok\n==FBV3-SPLIT==\n" + locs).encode())
    rows, _ = symbols.linked_functions(ws, binary="/ws/b")
    assert [r.name for r in rows] == ["ok"]


def test_symbols_report_a_stripped_binary(tmp_path):
    ws = FakeWS(tmp_path, stdout=b"==FBV3-SPLIT==\n")
    rows, err = symbols.linked_functions(ws, binary="/ws/b")
    assert rows == [] and "debug info" in err


def test_symbols_report_a_failed_command(tmp_path):
    ws = FakeWS(tmp_path, stdout=b"", code=1)
    rows, err = symbols.linked_functions(ws, binary="/ws/b")
    assert rows == [] and "symbol listing failed" in err


def test_a_prebuilt_target_is_made_executable(tmp_path):
    """A benchmark case or an archive can hand us a target with no exec bit."""
    from fbv3.sandbox.workspace import copy_runtime_bundle

    src = tmp_path / "prebuilt"
    src.mkdir()
    (src / "fuzz").write_bytes(b"\x7fELF")
    (src / "fuzz").chmod(0o644)
    target = copy_runtime_bundle(src, tmp_path / "out" / "address", "fuzz")
    assert target.stat().st_mode & 0o111


def test_a_missing_prebuilt_target_is_reported(tmp_path):
    from fbv3.sandbox.workspace import copy_runtime_bundle

    (tmp_path / "prebuilt").mkdir()
    with pytest.raises(FileNotFoundError):
        copy_runtime_bundle(tmp_path / "prebuilt", tmp_path / "out", "fuzz")


def test_symbols_skip_compiler_generated_entries(tmp_path):
    """_GLOBAL__sub_I_* and friends are not functions anyone wrote."""
    locs = ("_GLOBAL__sub_I_Assimp.cpp\n/src/assimp/code/Assimp.cpp:0:0\n\n"
            "__cxx_global_var_init.3\n/src/a.cc:5:0\n\n"
            "ReadFileFromMemory\n/src/assimp/code/Importer.cpp:300:0\n\n")
    ws = FakeWS(tmp_path, stdout=("0x1\ta\n0x2\tb\n0x3\tc\n==FBV3-SPLIT==\n" + locs).encode())
    rows, _ = symbols.linked_functions(ws, binary="/ws/b")
    assert [r.name for r in rows] == ["ReadFileFromMemory"]


def test_symbols_skip_a_relative_debug_path(tmp_path):
    """A relative path comes from a stdlib build, not the project tree."""
    ws = FakeWS(tmp_path, stdout=b"0x1\tx\n==FBV3-SPLIT==\nstd_thing\niostream.cpp:0:0\n\n")
    rows, err = symbols.linked_functions(ws, binary="/ws/b")
    assert rows == [] and "debug info" in err


def test_a_macro_expansion_does_not_stretch_a_function_over_its_file():
    """zlib's deflate() came out as lines 58-1290 instead of 981-1290."""
    export = {"data": [{"functions": [{
        "name": "deflate", "count": 1150, "filenames": ["/src/zlib/deflate.c"],
        "regions": [
            [981, 1, 1290, 2, 1150, 0, 0, 0],   # the body
            [1000, 5, 1005, 9, 900, 0, 0, 0],   # a branch inside it
            [58, 20, 58, 40, 1150, 0, 0, 1],    # a macro expanded at line 58
            [60, 1, 60, 9, 0, 0, 0, 3],         # a gap region
            [70, 1, 90, 2, 5, 40, 0, 0],        # code attributed to another file
        ]}]}]}
    row = coverage.parse_export(export)[0]
    assert (row.start_line, row.end_line) == (981, 1290)


def test_a_function_with_only_expansion_regions_still_gets_a_span():
    export = {"data": [{"functions": [{
        "name": "wrapper", "count": 3, "filenames": ["/src/a.c"],
        "regions": [[10, 1, 20, 2, 3, 0, 0, 1]]}]}]}
    row = coverage.parse_export(export)[0]
    assert (row.start_line, row.end_line) == (10, 20)


def test_short_region_rows_are_tolerated():
    export = {"data": [{"functions": [{
        "name": "f", "count": 1, "filenames": ["/src/a.c"], "regions": [[5, 1, 9, 2, 1]]}]}]}
    assert coverage.parse_export(export)[0].end_line == 9


def test_losing_the_container_log_does_not_fail_the_shutdown(tmp_path, monkeypatch):
    """A run whose directory was moved aside still shuts down cleanly."""
    from fbv3.sandbox import docker as dockermod
    from fbv3.sandbox.workspace import Workspace

    ws = Workspace(root=tmp_path / "gone", run_id="r1")
    ws.container = "fbv3-ws-test"
    removed = []
    monkeypatch.setattr(dockermod, "run", lambda argv, **kw: removed.append(argv[:3]) or
                        subprocess.CompletedProcess(argv, 0, b"log", b""))
    ws.stop()  # the logs dir does not exist
    assert ws.container == ""
    assert ["docker", "rm", "-f"] in removed  # it still removed the container


def test_mangled_cpp_names_are_turned_back_into_source_names(tmp_path):
    """llvm-cov only demangles when its -Xdemangler run succeeds; json11's index
    came out with 141 of 142 names mangled, which no agent reading the source
    would recognise."""
    from fbv3.fuzz.coverage import FunctionRow, demangle

    table = {"_ZNK6json1110JsonDouble9int_valueEv": "json11::JsonDouble::int_value() const",
             "_ZN6json114Json5parseERKNSt3__112basic_stringIcEE": "json11::Json::parse(std::string const&)"}

    class WS:
        def __init__(self):
            self.stdin = None

        def exec(self, argv, *, timeout=120, stdin=None, **kw):
            self.stdin = stdin
            names = stdin.decode().strip().split("\n")
            return subprocess.CompletedProcess(
                argv, 0, ("\n".join(table.get(n, n) for n in names) + "\n").encode(), b"")

    ws = WS()
    rows = [FunctionRow(m, "/src/json11.cpp", 1, 9, 3) for m in table] + \
           [FunctionRow("LLVMFuzzerTestOneInput", "/src/h.cc", 1, 9, 1)]
    out = {r.name for r in demangle(ws, rows)}
    assert out == set(table.values()) | {"LLVMFuzzerTestOneInput"}
    assert b"_ZNK6json11" in ws.stdin  # only the mangled ones were sent


def test_demangling_is_skipped_when_nothing_is_mangled(tmp_path):
    from fbv3.fuzz.coverage import FunctionRow, demangle

    class WS:
        def exec(self, *a, **kw):
            raise AssertionError("should not be called")

    rows = [FunctionRow("deflate", "/src/a.c", 1, 9, 2)]
    assert [r.name for r in demangle(WS(), rows)] == ["deflate"]


def test_a_demangler_that_loses_lines_keeps_the_mangled_names(tmp_path):
    from fbv3.fuzz.coverage import FunctionRow, demangle

    class WS:
        def exec(self, argv, *, timeout=120, stdin=None, **kw):
            return subprocess.CompletedProcess(argv, 0, b"only-one-line\n", b"")

    rows = [FunctionRow("_ZNK1a", "/src/a.cc", 1, 9, 1), FunctionRow("_ZNK1b", "/src/a.cc", 2, 9, 1)]
    assert sorted(r.name for r in demangle(WS(), rows)) == ["_ZNK1a", "_ZNK1b"]


def test_the_export_script_reports_why_demangling_fell_back():
    from fbv3.fuzz import coverage as cov

    s = cov.export_script("/cov/fuzz", "/corpus", "/ws/coverage/p")
    assert "demangling export failed" in s and "export.err" in s
    assert "2>/dev/null" not in s  # the reason is no longer swallowed
