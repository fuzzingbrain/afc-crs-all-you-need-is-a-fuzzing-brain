"""The overlay builder's pure parts: the marker, log excerpts, target detection."""

from __future__ import annotations

import struct
import subprocess
from pathlib import Path

from fbv3.build import builder
from fbv3.sandbox import docker


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


def test_the_targets_this_run_will_never_fuzz_are_pruned(tmp_path):
    """ImageMagick's build.sh builds 154 fuzz targets at 110 MB each. A run that
    fuzzes four binaries kept 96 GB; nothing reads the other 150."""
    for name in ("profile_fuzzer", "encoder_aai_fuzzer", "encoder_png_fuzzer"):
        elf(tmp_path, name, b"..LLVMFuzzerTestOneInput.." + b"\x00" * 500)
    (tmp_path / "profile_fuzzer.dict").write_text('"x"\n')
    (tmp_path / "encoder_png_fuzzer_seed_corpus.zip").write_bytes(b"PK\x03\x04")
    elf(tmp_path, "llvm-symbolizer", b"....main....")

    freed = builder.prune_out(tmp_path, "profile_fuzzer")

    assert freed > 500  # the two other targets' bytes
    assert (tmp_path / "profile_fuzzer").is_file()
    assert not (tmp_path / "encoder_aai_fuzzer").exists()
    assert not (tmp_path / "encoder_png_fuzzer").exists()
    # everything that is not a fuzz target weighs 7 MB in total: it stays
    assert (tmp_path / "profile_fuzzer.dict").is_file()
    assert (tmp_path / "encoder_png_fuzzer_seed_corpus.zip").is_file()
    assert (tmp_path / "llvm-symbolizer").is_file()


def test_pruning_what_is_already_gone_is_not_an_error(tmp_path, monkeypatch):
    elf(tmp_path, "keep", b"..LLVMFuzzerTestOneInput..")
    monkeypatch.setattr(builder, "fuzz_targets", lambda out: ["keep", "vanished"])
    assert builder.prune_out(tmp_path, "keep") == 0
    assert (tmp_path / "keep").is_file()


def test_a_successful_build_prunes_and_can_be_told_not_to(tmp_path, monkeypatch):
    def fake_build(out):
        for name in ("harness", "other"):
            elf(out, name, b"..LLVMFuzzerTestOneInput..")

    def run(argv, **kw):
        out = Path([argv[i + 1].split(":")[0] for i, a in enumerate(argv)
                    if a == "-v" and argv[i + 1].endswith(":/out")][0])
        fake_build(out)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(builder.docker, "run", run)
    monkeypatch.setattr(builder, "_contains", lambda path, needle: path.name == "harness")

    res = builder.build_harness(builder_image="img", overlay="/src/harness.c", source="int x;",
                                build_dir=tmp_path / "a")
    assert res.ok and res.binary == "harness"
    assert not (Path(res.out_dir) / "other").exists()

    res = builder.build_harness(builder_image="img", overlay="/src/harness.c", source="int x;",
                                build_dir=tmp_path / "b", prune=False)
    assert res.ok and (Path(res.out_dir) / "other").is_file()


# -- the cgroup caps ---------------------------------------------------------------------------


def test_the_cpu_cap_never_asks_for_more_cores_than_the_machine_has(monkeypatch):
    # docker refuses the container outright -- "Range of CPUs is from 0.01 to
    # 2.00, as there are only 2 CPUs available" -- so a default chosen on a
    # 32-core host would stop every build on a laptop, not slow it down.
    monkeypatch.setattr(docker.os, "cpu_count", lambda: 2)
    assert "--cpus=2" in docker.resource_args(8192, 4.0)
    monkeypatch.setattr(docker.os, "cpu_count", lambda: 32)
    assert "--cpus=4" in docker.resource_args(8192, 4.0)


def test_a_machine_that_reports_no_cores_still_gets_a_container(monkeypatch):
    # An unknown core count is treated as one, not as a reason to fail.
    monkeypatch.setattr(docker.os, "cpu_count", lambda: None)
    assert "--cpus=1" in docker.resource_args(8192, 4.0)


def test_the_environment_override_is_clamped_too(monkeypatch):
    monkeypatch.setattr(docker.os, "cpu_count", lambda: 4)
    monkeypatch.setenv("FBV3_DOCKER_CPUS", "64")
    assert "--cpus=4" in docker.resource_args(8192, 2.0)


def test_memory_is_not_clamped_because_a_cap_above_ram_is_never_reached(monkeypatch):
    monkeypatch.setattr(docker.os, "cpu_count", lambda: 1)
    args = docker.resource_args(8192, 1.0)
    assert "--memory=8192m" in args and "--memory-swap=8192m" in args
