# SPDX-License-Identifier: Apache-2.0
"""Jazzer (JVM) support: the pipeline is the same as ASan except there is no gdb
trace (JVM). Pins that Java targets drop the trace tool, jazzer guidance is
selected, a Java submit crash gets a signature, and Java crash classes dedup."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fbagent import hypothesis_tools, roles  # noqa: E402
from fbagent.hypothesis import HypothesisPool, crash_class  # noqa: E402
from fbagent.sanitizer_guidance import guidance_for  # noqa: E402
from fbagent.signature import signature_from_submit  # noqa: E402


def test_jazzer_guidance_selected():
    g = guidance_for("jazzer")
    assert "Jazzer (JVM)" in g and "command injection" in g
    assert "AddressSanitizer" not in g


def test_is_java():
    assert roles._is_java("jazzer") and not roles._is_java("address")


def test_java_target_drops_trace_tool():
    b = HypothesisPool(Path("/tmp/nonexistent-board-x.jsonl"))
    c_tools = {s["name"] for s in hypothesis_tools.build("reproduce", b, vh_id="L1",
                                                   with_trace=True)[0]}
    j_tools = {s["name"] for s in hypothesis_tools.build("reproduce", b, vh_id="L1",
                                                   with_trace=False)[0]}
    assert "trace" in c_tools
    assert "trace" not in j_tools
    assert {"read", "bash", "gates"} <= j_tools     # the rest stay


JAVA_CRASH = ("crash: the harness faulted under the sanitizer (IllegalStateException).\n"
              "stack (where it crashed):\n"
              "  #0 com.example.Parser.decode  Parser.java:88\n"
              "  #1 com.example.FuzzTarget.fuzzerTestOneInput  FuzzTarget.java:20\n")


def test_java_submit_signature_parses():
    sig = signature_from_submit(JAVA_CRASH, harness_names=["FuzzTarget"])
    assert sig.crash_class == "IllegalStateException"
    assert sig.frames and sig.frames[0][0] == "com.example.Parser.decode"
    assert "Parser.java:88" in sig.key


def test_java_crash_classes_dedup(tmp_path):
    b = HypothesisPool(tmp_path / "hypotheses.jsonl")
    a = b.create(function="decode", description="ClassCastException on a bad tag",
                 origin="discovery/llm", sanitizer="jazzer")
    dup = b.create(function="decode", description="another classcastexception path",
                   origin="discovery/llm", sanitizer="jazzer")
    assert a.id == dup.id and len(b.all()) == 1       # same (function, class) merged
    assert crash_class("hit a NullPointerException") == "nullpointerexception"
