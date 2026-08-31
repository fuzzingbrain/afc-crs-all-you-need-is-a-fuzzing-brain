# SPDX-License-Identifier: Apache-2.0
"""libFuzzer artifact detection.

libFuzzer writes more than plain `crash-*` under -artifact_prefix: OOMs,
hangs/timeouts, and leaks are separate reproducers and each is a reportable
finding. get_crashes() must pick up all of them, not just crashes.
"""

from fuzzingbrain.fuzzer.instance import FuzzerInstance
from fuzzingbrain.fuzzer.models import CRASH_ARTIFACT_PREFIXES, FuzzerType


def _instance(tmp_path):
    return FuzzerInstance(
        instance_id="global",
        fuzzer_path=tmp_path / "fuzzer_bin",
        docker_image="img",
        corpus_dir=tmp_path / "corpus",
        crashes_dir=tmp_path / "crashes",
        fuzzer_type=FuzzerType.GLOBAL,
    )


def test_prefixes_cover_libfuzzer_artifact_kinds():
    # "timeout-" is not among them on purpose: a hang is about how long the
    # harness took, against a threshold we chose, and one on the empty input
    # once ended a scan two minutes in as a "POV".
    assert set(CRASH_ARTIFACT_PREFIXES) == {"crash-", "oom-", "leak-"}


def test_get_crashes_detects_all_artifact_kinds(tmp_path):
    inst = _instance(tmp_path)
    artifacts = {"crash-aaa", "oom-bbb", "leak-ddd"}
    for name in artifacts:
        (inst.crashes_dir / name).write_bytes(b"x")
    # A hang, and a non-artifact file (e.g. a stray README): neither is a crash.
    (inst.crashes_dir / "timeout-ccc").write_bytes(b"x")
    (inst.crashes_dir / "README").write_bytes(b"x")

    assert {p.name for p in inst.get_crashes()} == artifacts
