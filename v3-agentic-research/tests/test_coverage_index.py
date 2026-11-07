"""The function index: llvm-cov export, and the symbol fallback for a prebuilt."""

from __future__ import annotations

import json
import subprocess

from fbv3.fuzz import coverage, symbols

EXPORT = {
    "data": [{
        "functions": [
            {"name": "deflate", "count": 17, "filenames": ["/src/zlib/deflate.c"],
             "regions": [[100, 1, 180, 2, 17, 0, 0, 0]]},
            {"name": "never_run", "count": 0, "filenames": ["/src/zlib/infback.c"],
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
