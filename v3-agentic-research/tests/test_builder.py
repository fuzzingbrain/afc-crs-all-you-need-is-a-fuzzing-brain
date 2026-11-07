"""The overlay builder's pure parts: the marker, log excerpts, target detection."""

from __future__ import annotations

import struct

from fbv3.build import builder


def test_the_marker_keeps_the_agents_line_numbers():
    out = builder.inject_marker("int LLVMFuzzerTestOneInput(void) { return 0; }\n", "FBV3MARK-abc")
    lines = out.splitlines()
    assert "FBV3MARK-abc" in lines[0]
    assert lines[1] == "#line 1"  # a compiler error still names the agent's own line
    assert lines[2].startswith("int LLVMFuzzerTestOneInput")
    assert builder.strip_marker(out).startswith("int LLVMFuzzerTestOneInput")


def test_the_excerpt_keeps_diagnostics_not_flags():
    log = "\n".join([
        "+ clang -Wno-error=deprecated -o /out/fuzz fuzz.c",
        "fuzz.c:12:5: error: use of undeclared identifier 'nope'",
        "  nope(1);",
        "fuzz.c:20:9: warning: unused variable 'x'",
        "/usr/bin/ld: error: undefined reference to `deflate2'",
    ])
    text = builder.excerpt(log)
    assert "error: use of undeclared identifier" in text
    assert "undefined reference" in text
    # The diagnostics section holds only diagnostics; the raw tail follows it.
    diagnostics = text.split("\n...\n")[0]
    assert "-Wno-error=deprecated" not in diagnostics
    assert "unused variable" not in diagnostics


def test_the_excerpt_is_bounded():
    assert len(builder.excerpt("x: error: boom\n" * 10000, budget=800)) <= 1200


def test_infrastructure_failures_are_classified():
    assert builder.classify_infra("Cannot connect to the Docker daemon", 1) == "docker_daemon"
    assert builder.classify_infra("No space left on device", 1) == "disk_full"
    assert builder.classify_infra("Could not resolve host: github.com", 1) == "network"
    assert builder.classify_infra("fuzz.c:1:1: error: boom", 1) == ""


def elf(tmp_path, name: str, body: bytes, kind: int = 2):
    """A minimal ELF file: e_type 2 is an executable, 1 a relocatable object."""
    path = tmp_path / name
    header = bytearray(b"\x7fELF\x02\x01\x01" + b"\x00" * 9)
    header += struct.pack("<HH", kind, 0x3E)
    path.write_bytes(bytes(header) + body)
    path.chmod(0o755)
    return path


def test_fuzz_targets_finds_executables_with_the_entry_point(tmp_path):
    elf(tmp_path, "fuzz_a", b"....LLVMFuzzerTestOneInput....")
    elf(tmp_path, "fuzz_b", b"....LLVMFuzzerTestOneInput....")
    elf(tmp_path, "helper", b"....main....")
    elf(tmp_path, "obj.o", b"....LLVMFuzzerTestOneInput....", kind=1)
    (tmp_path / "fuzz_a.dict").write_text("\"x\"\n")
    (tmp_path / "script.sh").write_text("#!/bin/sh\nLLVMFuzzerTestOneInput\n")
    assert builder.fuzz_targets(tmp_path) == ["fuzz_a", "fuzz_b"]


def test_a_build_result_reports_its_failure_to_the_agent():
    res = builder.BuildResult(False, "address", "/out", error="compile exited 1",
                              log_excerpt="fuzz.c:3:1: error: boom")
    text = res.feedback()
    assert "compile exited 1" in text and "error: boom" in text
    assert builder.BuildResult(True, "address", "/out", binary="fuzz").feedback() == "build ok (address): fuzz"


def test_an_overlay_must_be_a_src_path(tmp_path):
    res = builder.build_harness(builder_image="img", overlay="harness.c", source="", build_dir=tmp_path)
    assert not res.ok and "must be a path under /src/" in res.error
