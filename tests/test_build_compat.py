# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the OSS-Fuzz build-compatibility harness's pure logic.

The actual builds need Docker + an OSS-Fuzz checkout (run scripts/build_compat.py
directly). These tests cover the parts that must be correct regardless: failure
classification, report math, and resume bookkeeping.
"""

import importlib.util
import json
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "build_compat",
    Path(__file__).resolve().parent.parent / "scripts" / "build_compat.py",
)
build_compat = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(build_compat)


def test_classify_known_failures():
    assert build_compat.classify_failure("cat: x: No such file or directory") == (
        "missing_source_file"
    )
    assert build_compat.classify_failure("ERROR: Building fuzzers failed.") == (
        "build_fuzzers_failed"
    )
    assert build_compat.classify_failure("foo.c:1: error: bad") == "compiler_error"
    assert build_compat.classify_failure("partial...\n__HARNESS_TIMEOUT__") == "timeout"
    assert build_compat.classify_failure("something weird") == "unknown"


def test_classify_priority_missing_file_before_generic_error():
    # A missing file should win over a generic 'error:' later in the log.
    log = "No such file or directory\n...\nerror: build stopped"
    assert build_compat.classify_failure(log) == "missing_source_file"


def test_report_math_and_resume(tmp_path):
    out = tmp_path / "report.json"
    results = [
        {"project": "a", "success": True, "stage": "done", "reason": "ok"},
        {"project": "b", "success": False, "stage": "build_fuzzers", "reason": "x"},
    ]
    build_compat.write_report(out, results)

    data = json.loads(out.read_text())
    assert data["summary"] == {
        "total": 2,
        "succeeded": 1,
        "failed": 1,
        "success_rate": 0.5,
    }
    # Markdown summary is written alongside.
    assert out.with_suffix(".md").exists()
    # Resume reads back the recorded projects.
    done = build_compat.load_done(out)
    assert set(done) == {"a", "b"}
    assert done["a"]["success"] is True
