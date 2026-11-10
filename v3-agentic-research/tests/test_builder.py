"""The overlay builder's pure parts: the marker, log excerpts, target detection."""

from __future__ import annotations

import struct
import subprocess

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


def test_one_built_target_is_taken_without_fuss():
    from fbv3.build.builder import choose_binary

    assert choose_binary(["profile_fuzzer"], "/src/oss-fuzz/profile_fuzzer.cc") == ("profile_fuzzer", "")


def test_the_overlay_name_identifies_its_target():
    from fbv3.build.builder import choose_binary

    got, why = choose_binary(["other", "profile_fuzzer"], "/src/oss-fuzz/profile_fuzzer.cc")
    assert got == "profile_fuzzer" and why == ""
    assert choose_binary(["a", "b"], "/src/x.cc", "b") == ("b", "")


def test_an_overlay_built_into_many_targets_is_reported_not_guessed():
    """ImageMagick compiles one encoder_fuzzer.cc into 150 encoder_<format>_fuzzer
    binaries, so the marker is in all of them; taking the first by name hands back
    encoder_aai_fuzzer while the agent believes it fuzzes the generic decoder."""
    from fbv3.build.builder import choose_binary

    marked = [f"encoder_{f}_fuzzer" for f in ("aai", "png", "tif", "dcm")]
    got, why = choose_binary(marked, "/src/imagemagick/oss-fuzz/encoder_fuzzer.cc")
    assert got == ""
    assert "compiled into 4 fuzz targets" in why
    assert "encoder_aai_fuzzer" in why and "name the one you mean" in why
    # naming it resolves the ambiguity
    assert choose_binary(marked, "/src/imagemagick/oss-fuzz/encoder_fuzzer.cc",
                         "encoder_png_fuzzer") == ("encoder_png_fuzzer", "")


def test_the_ambiguity_fails_the_build_and_lists_the_candidates(tmp_path, monkeypatch):
    from fbv3.build import builder

    marked = ["encoder_aai_fuzzer", "encoder_png_fuzzer"]
    monkeypatch.setattr(builder, "fuzz_targets", lambda out: marked)
    monkeypatch.setattr(builder, "_contains", lambda path, needle: True)
    monkeypatch.setattr(builder.docker, "run", lambda argv, **kw: subprocess.CompletedProcess(
        argv, 0, b"", b""))
    res = builder.build_harness(builder_image="img", overlay="/src/encoder_fuzzer.cc",
                                source="int LLVMFuzzerTestOneInput(void){return 0;}",
                                build_dir=tmp_path / "b")
    assert not res.ok and "compiled into 2 fuzz targets" in res.error
    assert res.binaries == sorted(marked)
