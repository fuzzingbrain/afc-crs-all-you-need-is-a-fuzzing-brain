# SPDX-License-Identifier: Apache-2.0
"""Tests for the frontier integration: language-from-entry, recursion sinks in
the worklist, and the diversify tool. Kept separate so the wiring is pinned."""
from __future__ import annotations

from pathlib import Path

from fbagent import analysis


def _c_tree(tmp: Path):
    (tmp / "harness").mkdir()
    (tmp / "src").mkdir()
    (tmp / "harness" / "h.cc").write_text(
        'extern "C" int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n){\n'
        "  return walk(d, n);\n}\n")
    (tmp / "src" / "p.c").write_text(
        "int walk(const unsigned char *d, unsigned long n){ return walk(d, n-1); }\n"
        "void other(void){ helper(); }\n")
    return tmp


def test_language_from_entry_c(tmp_path: Path):
    _c_tree(tmp_path)
    # even if we add many .java files, a C harness entry keeps it 'c'
    jd = tmp_path / "j"; jd.mkdir()
    for i in range(5):
        (jd / f"K{i}.java").write_text("class K{ int x; }\n")
    _, lang = analysis.discover(tmp_path)
    assert lang == "c", "C harness entry must win over java file count"


def test_language_from_entry_java(tmp_path: Path):
    (tmp_path / "H.java").write_text(
        "public class H { public static void fuzzerTestOneInput(byte[] d){ parse(d); } }\n")
    (tmp_path / "P.java").write_text("class P { static void parse(byte[] d){} }\n")
    _, lang = analysis.discover(tmp_path)
    assert lang == "java"


def test_recursion_sink_in_worklist(tmp_path: Path):
    _c_tree(tmp_path)                       # walk() is directly self-recursive
    out = analysis.analyze(tmp_path)
    so = [s for s in out["reachable_sinks"] if s["klass"] == "stack-overflow"]
    assert any(s["func"] == "walk" for s in so), "self-recursion not surfaced as a sink"


def test_diversify_tool_dispatch(tmp_path: Path, monkeypatch):
    _c_tree(tmp_path)
    from fbagent import tools
    monkeypatch.setattr(tools, "WORKSPACE", tmp_path)
    out, err = tools.run_tool("diversify", {"cracked": "walk"})
    assert not err, out
    assert "furthest" in out.lower() or "reachable sinks" in out.lower()
