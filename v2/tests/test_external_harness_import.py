# SPDX-License-Identifier: Apache-2.0
"""The external-harness importer materializes a valid OSS-Fuzz workspace.

These tests exercise the pure file-materialization logic only (no git clone,
no Docker): a fake oss-fuzz infra dir and clone_repo=False keep them fast and
hermetic.
"""

import json
import stat

import pytest

from fuzzingbrain.importers.external_harness import HarnessSpec, build_workspace


def _fake_oss_fuzz(tmp_path):
    infra = tmp_path / "oss-fuzz" / "infra"
    infra.mkdir(parents=True)
    (infra / "helper.py").write_text("# stub helper\n")
    return tmp_path / "oss-fuzz"


def _spec(tmp_path, **over):
    harness = tmp_path / "vacm_fuzzer.c"
    harness.write_text("int LLVMFuzzerTestOneInput(const char*d,long n){return 0;}\n")
    base = dict(
        project="net-snmp",
        language="c",
        main_repo="https://github.com/net-snmp/net-snmp",
        commit="fc28b88a64b7739d76c73058c3811d5387851c32",
        harness_files=[str(harness)],
        apt_deps=["autoconf", "libtool"],
        build_script=(
            'cd $SRC/net-snmp\n./configure --enable-static\nmake -C snmplib\n'
            "$CC $CFLAGS -I include $SRC/harness/vacm_fuzzer.c "
            "snmplib/.libs/libnetsnmp.a $LIB_FUZZING_ENGINE -o $OUT/vacm_fuzzer\n"
        ),
    )
    base.update(over)
    return HarnessSpec.from_dict(base)


def test_materializes_oss_fuzz_layout(tmp_path):
    spec = _spec(tmp_path)
    ws = build_workspace(
        spec, tmp_path / "ws", _fake_oss_fuzz(tmp_path), clone_repo=False
    )
    proj = ws / "fuzz-tooling" / "projects" / "net-snmp"
    assert (ws / "fuzz-tooling" / "infra" / "helper.py").is_file()
    assert (proj / "project.yaml").is_file()
    assert (proj / "Dockerfile").is_file()
    assert (proj / "build.sh").is_file()
    assert (proj / "harness" / "vacm_fuzzer.c").is_file()


def test_build_sh_is_executable_and_has_shebang(tmp_path):
    spec = _spec(tmp_path)
    ws = build_workspace(
        spec, tmp_path / "ws", _fake_oss_fuzz(tmp_path), clone_repo=False
    )
    build_sh = ws / "fuzz-tooling" / "projects" / "net-snmp" / "build.sh"
    assert build_sh.read_text().startswith("#!/bin/bash")
    assert "$OUT/vacm_fuzzer" in build_sh.read_text()
    assert stat.S_IMODE(build_sh.stat().st_mode) & stat.S_IXUSR


def test_dockerfile_uses_base_builder_and_copies_harness(tmp_path):
    spec = _spec(tmp_path)
    ws = build_workspace(
        spec, tmp_path / "ws", _fake_oss_fuzz(tmp_path), clone_repo=False
    )
    dockerfile = (
        ws / "fuzz-tooling" / "projects" / "net-snmp" / "Dockerfile"
    ).read_text()
    assert dockerfile.startswith("FROM gcr.io/oss-fuzz-base/base-builder")
    assert "autoconf" in dockerfile  # apt dep threaded through
    assert "COPY harness $SRC/harness" in dockerfile
    assert "checkout fc28b88a" in dockerfile  # vuln commit pinned


def test_project_yaml_lists_language_and_sanitizer(tmp_path):
    spec = _spec(tmp_path, sanitizers=["address", "undefined"])
    ws = build_workspace(
        spec, tmp_path / "ws", _fake_oss_fuzz(tmp_path), clone_repo=False
    )
    yml = (ws / "fuzz-tooling" / "projects" / "net-snmp" / "project.yaml").read_text()
    assert "language: c" in yml
    assert "- address" in yml and "- undefined" in yml
    assert "libfuzzer" in yml


def test_rejects_unknown_fields(tmp_path):
    with pytest.raises(ValueError, match="Unknown spec"):
        HarnessSpec.from_dict(
            {
                "project": "p",
                "language": "c",
                "main_repo": "u",
                "build_script": "x",
                "bogus": 1,
            }
        )


def test_rejects_missing_required(tmp_path):
    with pytest.raises(ValueError, match="missing required"):
        HarnessSpec.from_dict({"project": "p", "language": "c"})


def test_rejects_slash_in_project(tmp_path):
    with pytest.raises(ValueError, match="must not contain"):
        HarnessSpec.from_dict(
            {"project": "a/b", "language": "c", "main_repo": "u", "build_script": "x"}
        )


def test_no_overwrite_without_flag(tmp_path):
    spec = _spec(tmp_path)
    oss = _fake_oss_fuzz(tmp_path)
    build_workspace(spec, tmp_path / "ws", oss, clone_repo=False)
    with pytest.raises(FileExistsError):
        build_workspace(spec, tmp_path / "ws", oss, clone_repo=False)
    # overwrite=True succeeds
    build_workspace(spec, tmp_path / "ws", oss, clone_repo=False, overwrite=True)


def test_from_json_roundtrip(tmp_path):
    spec = _spec(tmp_path)
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(
        json.dumps(
            {
                "project": spec.project,
                "language": spec.language,
                "main_repo": spec.main_repo,
                "build_script": spec.build_script,
            }
        )
    )
    loaded = HarnessSpec.from_json(spec_path)
    assert loaded.project == "net-snmp"
    assert loaded.sanitizers == ["address"]  # default applied
