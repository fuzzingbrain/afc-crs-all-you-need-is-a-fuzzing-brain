# SPDX-License-Identifier: Apache-2.0
"""bench.spec_from_bench_bug derives a buildable HarnessSpec from a bug dir.

Hermetic: a synthetic bench bug directory stands in for the real corpus.
"""

import pytest

from fuzzingbrain.importers.bench import (
    spec_from_bench_bug,
    _parse_apt_deps,
    _build_script,
)


def _make_bug(tmp_path, *, language="c", sources=("vacm_fuzzer.c",), apt=None,
              description="NULL deref in vacm_parse_config_group at vacm.c:414"):
    bug = tmp_path / "netsnmp-vacm-parse-npd"
    (bug / "harness").mkdir(parents=True)
    if description is not None:
        (bug / "description.txt").write_text(description + "\n")
    (bug / "bench.yaml").write_text(
        "bug_id: netsnmp-vacm-parse-npd\n"
        "project: net-snmp\n"
        "target:\n"
        "  repo: https://github.com/net-snmp/net-snmp\n"
        "  vuln_commit: fc28b88a64b7739d76c73058c3811d5387851c32\n"
        f"  language: {language}\n"
    )
    for s in sources:
        (bug / "harness" / s).write_text("int LLVMFuzzerTestOneInput(){return 0;}\n")
    (bug / "harness" / "build.sh").write_text("#!/bin/bash\n")
    (bug / "harness" / "PROVENANCE.md").write_text("docs\n")
    apt = apt or ["git", "clang", "libclang-rt-14-dev", "autoconf", "perl"]
    (bug / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends \\\n"
        + "    " + " ".join(apt) + " \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
    )
    return bug


def test_basic_fields(tmp_path):
    spec = spec_from_bench_bug(_make_bug(tmp_path))
    assert spec.project == "net-snmp"
    assert spec.language == "c"
    assert spec.commit.startswith("fc28b88a")
    assert spec.main_repo.endswith("net-snmp")


def test_harness_files_include_build_sh_and_source_but_not_md(tmp_path):
    spec = spec_from_bench_bug(_make_bug(tmp_path))
    names = sorted(p.rsplit("/", 1)[-1] for p in spec.harness_files)
    assert names == ["build.sh", "vacm_fuzzer.c"]
    assert all(not n.endswith(".md") for n in names)


def test_apt_filters_toolchain_packages(tmp_path):
    spec = spec_from_bench_bug(_make_bug(tmp_path))
    # clang / libclang-rt-14-dev collide with base-builder and are dropped.
    assert "clang" not in spec.apt_deps
    assert not any(p.startswith("libclang-rt") for p in spec.apt_deps)
    # real build deps survive.
    assert "autoconf" in spec.apt_deps and "perl" in spec.apt_deps


def test_libclang_dev_is_kept(tmp_path):
    # libclang-dev is a bindgen library, not the clang compiler — keep it.
    spec = spec_from_bench_bug(_make_bug(tmp_path, apt=["git", "libclang-dev", "meson"]))
    assert "libclang-dev" in spec.apt_deps


def test_cpp_language_mapped(tmp_path):
    spec = spec_from_bench_bug(_make_bug(tmp_path, language="cpp", sources=("h.cc",)))
    assert spec.language == "c++"


def test_build_script_uses_bench_build_and_copies_to_out(tmp_path):
    spec = spec_from_bench_bug(_make_bug(tmp_path))
    bs = spec.build_script
    assert "$SRC/harness/build.sh" in bs
    assert "build-libs" in bs
    assert 'harness "$c"' in bs
    assert "$OUT/vacm_fuzzer" in bs
    assert "coverage" in bs  # SANITIZER=coverage branch present


def test_build_script_selects_by_sanitizer():
    bs = _build_script("foo_fuzzer")
    assert 'SANITIZER:-address' in bs
    assert "release-asan debug-asan debug" in bs


def test_build_script_sets_git_safe_directory():
    # Without this, build.sh git commands (submodule/autoreconf) fail on the
    # bind-mounted repo with "dubious ownership".
    assert "safe.directory" in _build_script("foo_fuzzer")


def test_description_included_by_default(tmp_path):
    spec = spec_from_bench_bug(_make_bug(tmp_path))
    assert "vacm_parse_config_group" in spec.description


def test_description_excluded_when_disabled(tmp_path):
    spec = spec_from_bench_bug(_make_bug(tmp_path), with_description=False)
    assert spec.description == ""


def test_missing_description_file_is_empty(tmp_path):
    spec = spec_from_bench_bug(_make_bug(tmp_path, description=None))
    assert spec.description == ""


def test_no_source_raises(tmp_path):
    bug = _make_bug(tmp_path, sources=())  # only build.sh, no .c
    with pytest.raises(ValueError, match="no harness source"):
        spec_from_bench_bug(bug)


def test_parse_apt_deps_missing_dockerfile(tmp_path):
    assert _parse_apt_deps(tmp_path / "nope") == []
