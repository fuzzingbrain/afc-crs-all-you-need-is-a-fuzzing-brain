"""The crash monitor: what counts as a bug, and what one bug is.

A libFuzzer timeout prints a stack trace of its own, so frames alone cannot
make a crash; a run that counts them reports slow inputs as bugs. The first
live CyberGym run did exactly that.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fbv3.fuzz.fuzzer import CrashMonitor, is_afl_target
from fbv3.store import Store

ASAN = """\
==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60300000eff8
    #0 0x4f1a2b in Assimp::AC3DImporter::LoadObjectSection() /src/assimp/code/ACLoader.cpp:196:9
    #1 0x4f2000 in Assimp::AC3DImporter::InternReadFile() /src/assimp/code/ACLoader.cpp:836:13
    #2 0x4f3000 in LLVMFuzzerTestOneInput /src/assimp/fuzz/assimp_fuzzer.cc:62:34
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/assimp/code/ACLoader.cpp:196:9
"""

TIMEOUT = """\
ALARM: working on the last Unit for 31 seconds
    #0 0x55cf in TokenMatch<char const> /src/assimp/code/ParsingUtils.h:240:17
    #1 0x55cf in Assimp::AC3DImporter::LoadObjectSection() /src/assimp/code/ACLoader.cpp:196:1
    #2 0x55cf in LLVMFuzzerTestOneInput /src/assimp/fuzz/assimp_fuzzer.cc:62:34
SUMMARY: libFuzzer: timeout
"""

OOM = """\
==9==ERROR: libFuzzer: out-of-memory (malloc(3221225472))
    #0 0x55cf in operator new(unsigned long) /src/llvm-project/compiler-rt/asan_new_delete.cpp:95
    #1 0x55cf in Assimp::MD5Importer::LoadFile() /src/assimp/code/MD5Loader.cpp:300:5
SUMMARY: libFuzzer: out-of-memory
"""

UBSAN = """\
/src/dav1d/src/decode.c:2849:35: runtime error: signed integer overflow: 1 * 2147483647 cannot be represented
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/dav1d/src/decode.c:2849:35
"""


def monitor(tmp_path, **kw) -> tuple[CrashMonitor, Store]:
    store = Store(tmp_path / "run")
    store.start_run("t", {})
    m = CrashMonitor(lg="assimp_fuzzer", store=store, image="img", build_out=tmp_path / "out",
                     binary="assimp_fuzzer", harness_names=["assimp_fuzzer"],
                     save_dir=tmp_path / "crashes", **kw)
    m.save_dir.mkdir(parents=True, exist_ok=True)
    return m, store


def artifact(tmp_path, name="crash-abc") -> Path:
    p = tmp_path / name
    p.write_bytes(b"AC3Db\x00")
    return p


def test_a_sanitizer_report_is_a_crash(tmp_path):
    m, store = monitor(tmp_path)
    rec = m.handle("global", artifact(tmp_path), output=ASAN)
    assert rec and rec["new"] and rec["crash_class"] == "heap-buffer-overflow"
    assert "LoadObjectSection" in rec["describe"]
    assert m.new_crashes == 1 and store.crashes("assimp_fuzzer")
    assert Path(rec["artifact"]).is_file()  # the input is kept next to the report
    assert (m.save_dir / f"{rec['signature']}.txt").read_text().endswith("\n")


def test_a_timeout_is_not_a_crash(tmp_path):
    """It prints frames, so only the missing sanitizer class tells them apart."""
    m, store = monitor(tmp_path)
    assert m.handle("global", artifact(tmp_path), output=TIMEOUT) is None
    assert store.crashes("assimp_fuzzer") == []
    assert m.new_crashes == 0 and m.skipped == {"timeout": 1}
    events = (tmp_path / "run" / "events.jsonl").read_text()
    assert "artifact_skipped" in events and "timeout" in events


def test_an_out_of_memory_is_not_a_crash(tmp_path):
    m, store = monitor(tmp_path)
    assert m.handle("poc", artifact(tmp_path), output=OOM) is None
    assert m.skipped == {"out-of-memory": 1} and store.crashes() == []


def test_output_with_no_report_at_all_is_not_a_crash(tmp_path):
    m, store = monitor(tmp_path)
    assert m.handle("global", artifact(tmp_path), output="Executed in 12 ms\n") is None
    assert m.skipped == {"no sanitizer report": 1}


def test_an_undefined_behaviour_report_is_a_crash(tmp_path):
    """dav1d's CWE-190 is a UBSan integer overflow, not an ASan fault."""
    m, store = monitor(tmp_path)
    rec = m.handle("global", artifact(tmp_path), output=UBSAN)
    assert rec and rec["crash_class"].startswith("undefined-behavior")


def test_the_same_bug_found_twice_is_one_crash(tmp_path):
    m, store = monitor(tmp_path)
    first = m.handle("global", artifact(tmp_path, "a"), output=ASAN)
    second = m.handle("poc", artifact(tmp_path, "b"), output=ASAN)
    assert first["new"] and not second["new"]
    assert first["crash_id"] == second["crash_id"]
    assert len(store.crashes("assimp_fuzzer")) == 1
    assert m.new_crashes == 1


def test_two_bugs_in_one_function_stay_apart(tmp_path):
    m, store = monitor(tmp_path)
    other = ASAN.replace("ACLoader.cpp:196:9", "ACLoader.cpp:402:11")
    m.handle("global", artifact(tmp_path, "a"), output=ASAN)
    m.handle("global", artifact(tmp_path, "b"), output=other)
    assert len(store.crashes("assimp_fuzzer")) == 2


def test_only_a_new_crash_calls_back(tmp_path):
    seen = []
    m, _ = monitor(tmp_path, on_new=seen.append)
    m.handle("global", artifact(tmp_path, "a"), output=ASAN)
    m.handle("global", artifact(tmp_path, "b"), output=ASAN)
    assert len(seen) == 1


def test_a_crash_from_a_poc_agent_is_linked_to_its_hypothesis(tmp_path):
    m, store = monitor(tmp_path)
    rec = m.handle("poc_agent", artifact(tmp_path), vh_id="vh42", output=ASAN)
    assert store.crashes()[0]["vh_id"] == "vh42" and rec["new"]


def test_the_scan_only_picks_up_artifacts(tmp_path):
    m, store = monitor(tmp_path)
    crashes = tmp_path / "fuzz" / "crashes"
    crashes.mkdir(parents=True)
    (crashes / "crash-1").write_bytes(b"x")
    (crashes / "leak-2").write_bytes(b"x")
    (crashes / "fuzz-0.log").write_bytes(b"x")
    (crashes / "notes.txt").write_bytes(b"x")
    handled = []
    m.handle = lambda source, art, **kw: handled.append(art.name)
    m.watch("global", crashes)
    m.scan()
    m.scan()  # a second pass must not re-handle what it saw
    assert sorted(handled) == ["crash-1", "leak-2"]


@pytest.mark.parametrize("data,expected", [
    (b"\x7fELF__afl_persistent_loop", True),
    (b"\x7fELF__AFL_SHM_ID", True),
    (b"\x7fELF LLVMFuzzerTestOneInput", False),
])
def test_an_afl_build_is_recognised(tmp_path, data, expected):
    (tmp_path / "afl-fuzz").write_bytes(b"\x7fELF")
    (tmp_path / "fuzz").write_bytes(data)
    assert is_afl_target(tmp_path, "fuzz") is expected


def test_an_afl_marked_binary_without_the_driver_is_not_driven_as_afl(tmp_path):
    """Without /out/afl-fuzz there is nothing to drive it with."""
    (tmp_path / "fuzz").write_bytes(b"\x7fELF__AFL_SHM_ID")
    assert is_afl_target(tmp_path, "fuzz") is False
    assert is_afl_target(tmp_path, "missing") is False
