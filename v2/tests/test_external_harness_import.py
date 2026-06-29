# SPDX-License-Identifier: Apache-2.0
"""The external-harness importer materializes a valid OSS-Fuzz workspace.

These tests exercise the pure file-materialization logic only (no git clone,
no Docker): a fake oss-fuzz infra dir and clone_repo=False keep them fast and
hermetic.
"""

import json
import stat
import subprocess

import pytest

from fuzzingbrain.importers.external_harness import HarnessSpec, build_workspace, _git_clone


def _git(*args, cwd):
    env = {
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    subprocess.run(["git", *args], cwd=str(cwd), check=True,
                   capture_output=True, env={**env}, text=True)


def _make_repo(path, files):
    path.mkdir(parents=True)
    _git("init", "-q", "-b", "main", cwd=path)
    for name, content in files.items():
        (path / name).write_text(content)
    _git("add", "-A", cwd=path)
    _git("commit", "-qm", "init", cwd=path)


def test_git_clone_fetches_submodules(tmp_path):
    # upx vendors ucl/zlib as submodules; without recursive init the build dies
    # with "No SOURCES given to target". The clone must materialize them.
    sub = tmp_path / "sub"
    _make_repo(sub, {"vendored.txt": "from-submodule"})
    main = tmp_path / "main"
    _make_repo(main, {"top.txt": "x"})
    _git("-c", "protocol.file.allow=always", "submodule", "add",
         str(sub), "vendor/sub", cwd=main)
    _git("commit", "-qm", "add sub", cwd=main)

    dest = tmp_path / "clone"
    # protocol.file.allow lets submodule update use a file:// URL in this test.
    import os
    os.environ["GIT_ALLOW_PROTOCOL"] = "file"
    _git_clone(str(main), "", dest)
    assert (dest / "vendor" / "sub" / "vendored.txt").read_text() == "from-submodule"


def test_git_clone_tolerates_unresolvable_commit(tmp_path):
    # skia/GraalVM pin revisions not in the default fetch; the bench Dockerfile
    # itself falls back to the default branch. _git_clone must not raise.
    repo = tmp_path / "repo"
    _make_repo(repo, {"f.txt": "v1"})
    dest = tmp_path / "clone"
    _git_clone(str(repo), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", dest)  # bogus SHA
    assert (dest / "f.txt").read_text() == "v1"  # cloned, left on default branch


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


def test_dockerfile_renders_setup_deps_and_extra_clones_before_target(tmp_path):
    # rust/jvm/multi-repo targets need: pip deps, carried-over toolchain setup,
    # and dependency clones — all in place before the target is cloned/built.
    spec = _spec(
        tmp_path,
        pip_deps=["meson", "ninja"],
        setup_steps=["ENV JAVA_HOME=/opt/jdk21", "RUN curl -sSf https://x | sh"],
        extra_clones=[{"url": "https://github.com/strukturag/libde265",
                       "dir": "/src/libde265", "ref": "v1.0.15"}],
    )
    ws = build_workspace(
        spec, tmp_path / "ws", _fake_oss_fuzz(tmp_path), clone_repo=False
    )
    df = (ws / "fuzz-tooling" / "projects" / "net-snmp" / "Dockerfile").read_text()
    assert "pip3 install" in df and "meson ninja" in df
    assert "ENV JAVA_HOME=/opt/jdk21" in df
    assert "RUN curl -sSf https://x | sh" in df
    # dependency repo cloned at its pinned ref
    assert "git clone https://github.com/strukturag/libde265 /src/libde265" in df
    assert "checkout v1.0.15" in df
    # ordering: toolchain setup + deps must precede cloning the target itself
    assert df.index("JAVA_HOME") < df.index("$SRC/net-snmp")
    assert df.index("libde265") < df.index("$SRC/net-snmp")


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


def test_description_written_when_present(tmp_path):
    spec = _spec(tmp_path, description="NULL deref in vacm_parse_config_group")
    ws = build_workspace(
        spec, tmp_path / "ws", _fake_oss_fuzz(tmp_path), clone_repo=False
    )
    desc = ws / "DESCRIPTION.txt"
    assert desc.is_file()
    assert "vacm_parse_config_group" in desc.read_text()


def test_no_description_no_file(tmp_path):
    spec = _spec(tmp_path)  # description defaults to ""
    ws = build_workspace(
        spec, tmp_path / "ws", _fake_oss_fuzz(tmp_path), clone_repo=False
    )
    assert not (ws / "DESCRIPTION.txt").exists()


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
