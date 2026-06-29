# SPDX-License-Identifier: Apache-2.0
"""bench.spec_from_bench_bug derives a buildable HarnessSpec from a bug dir.

Hermetic: a synthetic bench bug directory stands in for the real corpus.
"""

import os
import subprocess

import pytest

from fuzzingbrain.importers.bench import (
    spec_from_bench_bug,
    _parse_apt_deps,
    _parse_clones,
    _build_script,
    _detect_libs_cmd,
)


def _run_build_script(tmp_path, script, fake_build_sh, sanitizer="address",
                      path_prepend=None):
    """Execute a generated build_script against a fake bench build.sh.

    The fake stands in for ``$SRC/harness/build.sh`` and decides which configs it
    can build; we then assert on what the generated driver actually does. HOME is
    sandboxed so the script's ``git config --global`` cannot touch the real one.
    ``path_prepend`` puts a dir at the front of PATH (e.g. a stub ``ld.lld``).
    """
    src = tmp_path / "src"
    (src / "harness").mkdir(parents=True)
    bs = src / "harness" / "build.sh"
    bs.write_text(fake_build_sh)
    out = tmp_path / "out"
    out.mkdir()
    path = os.environ["PATH"]
    if path_prepend:
        path = f"{path_prepend}:{path}"
    env = {**os.environ, "SRC": str(src), "OUT": str(out),
           "SANITIZER": sanitizer, "HOME": str(tmp_path), "PATH": path}
    r = subprocess.run(["bash", "-c", script], env=env,
                       capture_output=True, text=True)
    return r, out


# A fake build.sh exposing the common contract: build-libs is a no-op, and
# `harness <cfg>` emits $OUT/<cfg>/harness. Rejects the bare-config form.
_FAKE_STD = (
    "#!/bin/bash\n"
    'case "$1" in\n'
    '  build-libs) exit 0;;\n'
    '  harness) mkdir -p "$OUT/$2"; echo bin > "$OUT/$2/harness"; exit 0;;\n'
    '  *) exit 2;;\n'
    'esac\n'
)


def test_build_script_drives_bench_recipe_and_copies_fuzzer(tmp_path):
    # End-to-end: runs build-libs + harness, copies the built binary to the
    # OSS-Fuzz fuzzer name. release-asan is preferred and should be the one taken.
    r, out = _run_build_script(tmp_path, _build_script("vacm_fuzzer"), _FAKE_STD)
    assert r.returncode == 0, r.stderr
    assert (out / "vacm_fuzzer").is_file()              # copied to $OUT/<name>
    assert (out / "release-asan" / "harness").is_file()  # highest-priority cfg used


def test_build_script_falls_back_to_bare_config_form(tmp_path):
    # mongoose-style build.sh has no `harness` subcommand and no build-libs; it
    # takes the config directly. The driver must fall back to the bare form.
    fake = (
        "#!/bin/bash\n"
        'case "$1" in\n'
        '  release-asan|debug-asan|debug) mkdir -p "$OUT/$1"; echo bin > "$OUT/$1/harness";;\n'
        '  *) exit 2;;\n'  # rejects build-libs and `harness <cfg>`
        'esac\n'
    )
    r, out = _run_build_script(tmp_path, _build_script("f", libs_cmd=""), fake)
    assert r.returncode == 0, r.stderr
    assert (out / "f").is_file()


def test_build_script_fails_loudly_when_nothing_builds(tmp_path):
    # No config produces a harness -> non-zero exit and a diagnostic on stderr
    # (not a silent success, which would strand the run with no fuzzer).
    fake = "#!/bin/bash\necho boom >&2\nexit 1\n"
    r, out = _run_build_script(tmp_path, _build_script("f"), fake)
    assert r.returncode != 0
    assert "no harness config built" in r.stderr
    assert not (out / "f").exists()


def test_build_script_uses_the_renamed_libs_step(tmp_path):
    # openldap renames build-libs -> openldap-libs. Prove the driver actually
    # invokes the renamed step: the harness only builds once libs have run.
    fake = (
        "#!/bin/bash\n"
        'case "$1" in\n'
        '  openldap-libs) touch "$OUT/.libs"; exit 0;;\n'
        '  build-libs) exit 2;;\n'  # this project does NOT have build-libs
        '  harness) [ -f "$OUT/.libs" ] || exit 3; mkdir -p "$OUT/$2"; echo bin > "$OUT/$2/harness";;\n'
        '  *) exit 2;;\n'
        'esac\n'
    )
    r, out = _run_build_script(tmp_path, _build_script("f", "openldap-libs"), fake)
    assert r.returncode == 0, r.stderr
    assert (out / "f").is_file()


def test_build_script_strips_libcxx_stdlib_for_bench_builds(tmp_path):
    # base-builder forces -stdlib=libc++; bench harnesses are GNU libstdc++. The
    # driver must hand build.sh a CXXFLAGS without -stdlib=libc++ so sub-builds
    # (libde265) don't compile against the wrong stdlib. Capture what build.sh sees.
    fake = (
        "#!/bin/bash\n"
        'echo "$CXXFLAGS" > "$OUT/seen_cxxflags"\n'
        'case "$1" in\n'
        '  build-libs) exit 0;;\n'
        '  harness) mkdir -p "$OUT/$2"; echo bin > "$OUT/$2/harness"; exit 0;;\n'
        '  *) exit 2;;\n'
        'esac\n'
    )
    src = tmp_path / "src"
    (src / "harness").mkdir(parents=True)
    (src / "harness" / "build.sh").write_text(fake)
    out = tmp_path / "out"
    out.mkdir()
    env = {**os.environ, "SRC": str(src), "OUT": str(out), "SANITIZER": "address",
           "HOME": str(tmp_path),
           "CXXFLAGS": "-O1 -stdlib=libc++ -DFOO", "CFLAGS": "-O1"}
    r = subprocess.run(["bash", "-c", _build_script("f")], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    seen = (out / "seen_cxxflags").read_text()
    assert "-stdlib=libc++" not in seen  # stripped
    assert "-DFOO" in seen and "-O1" in seen  # other flags preserved


def test_build_script_repoints_ld_to_lld_when_available(tmp_path):
    # LTO/IPO projects (FreeRDP, open62541) ship bitcode static libs that GNU ld
    # (base-builder's default /usr/bin/ld) cannot link. The driver must repoint ld
    # at lld when present — observe the repoint via the FB_LD_PATH test seam.
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    lld = stub_bin / "ld.lld"
    lld.write_text("#!/bin/bash\nexit 0\n")
    lld.chmod(0o755)
    ld_target = tmp_path / "ld"  # stands in for /usr/bin/ld
    script = f'export FB_LD_PATH="{ld_target}"\n' + _build_script("f")
    r, out = _run_build_script(
        tmp_path, script, _FAKE_STD, path_prepend=str(stub_bin)
    )
    assert r.returncode == 0, r.stderr
    assert ld_target.is_symlink()
    assert os.path.realpath(ld_target) == str(lld)  # ld now resolves to lld
    assert (out / "f").is_file()  # and the build still completes


def test_build_script_ld_repoint_is_non_fatal_without_lld(tmp_path):
    # When lld is absent the repoint must be a guarded no-op, never aborting the
    # build under `set -eu`. Point FB_LD_PATH at an unwritable location to prove a
    # failed/absent repoint cannot break an otherwise fine build.
    script = 'export FB_LD_PATH="/proc/nonexistent/ld"\n' + _build_script("f")
    r, out = _run_build_script(tmp_path, script, _FAKE_STD)
    assert r.returncode == 0, r.stderr
    assert (out / "f").is_file()


def test_build_script_picks_coverage_config_under_coverage_sanitizer(tmp_path):
    # SANITIZER=coverage must select the coverage config, not an asan one.
    r, out = _run_build_script(
        tmp_path, _build_script("f"), _FAKE_STD, sanitizer="coverage"
    )
    assert r.returncode == 0, r.stderr
    assert (out / "coverage" / "harness").is_file()
    assert not (out / "release-asan").exists()


import shutil

_CC = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")


@pytest.mark.skipif(not _CC, reason="needs a C compiler")
def test_compat_shim_is_inert_on_a_modern_base_and_supplies_gnu_source(tmp_path):
    # The focal-compat shim is force-included into EVERY bench compile, so on a
    # base that already has these symbols (the host, glibc 2.35) it must be inert:
    # compile clean under -Werror. This is a real behavioral guard, not a mirror —
    #   * a missing `__GLIBC_PREREQ(2,33)` guard would redefine glibc's own
    #     `struct mallinfo2`/`mallinfo2()` and the compile would ERROR;
    #   * dropping the shim's `#define _GNU_SOURCE` would leave RTLD_DEFAULT (used
    #     here WITHOUT the TU defining _GNU_SOURCE) undeclared and ERROR.
    # Both are exactly the breakages hit while bringing systemd up on focal.
    from fuzzingbrain.importers.bench import _FOCAL_COMPAT_SHIM
    shim = tmp_path / "fb_compat.h"
    shim.write_text(_FOCAL_COMPAT_SHIM)
    tu = tmp_path / "probe.c"
    tu.write_text(  # intentionally does NOT define _GNU_SOURCE; the shim must
        "#include <dlfcn.h>\n"
        "#include <malloc.h>\n"
        "#include <sys/syscall.h>\n"
        "#include <signal.h>\n"
        "void *use(void) {\n"
        "  struct mallinfo2 m = mallinfo2();\n"
        "  (void)m; (void)SEGV_MTEAERR; (void)__NR_openat2; (void)__NR_close_range;\n"
        "  return RTLD_DEFAULT;\n"
        "}\n"
    )
    r = subprocess.run(
        [_CC, "-c", "-Werror", "-include", str(shim), str(tu),
         "-o", str(tmp_path / "probe.o")],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_build_script_writes_compat_shim_and_force_includes_that_path(tmp_path):
    # The driver must both WRITE the compat header and aim -include at the SAME
    # path; a header written elsewhere (or not at all) makes every compile fail to
    # open it. The fake build.sh records C/CXXFLAGS and confirms the -include'd
    # file is actually present on disk when the bench recipe runs.
    rec = tmp_path / "rec.txt"
    fake = (
        "#!/bin/bash\n"
        'case "$1" in\n'
        f'  build-libs) {{ echo "C=$CFLAGS"; echo "X=$CXXFLAGS"; }} > "{rec}"; '
        'p=$(printf "%s" "$CFLAGS" | grep -oE "/[^ ]*fb_compat.h" | head -1); '
        f'[ -f "$p" ] && echo "SHIM_PRESENT" >> "{rec}"; exit 0;;\n'
        '  harness) mkdir -p "$OUT/$2"; echo bin > "$OUT/$2/harness"; exit 0;;\n'
        '  *) exit 2;;\n'
        'esac\n'
    )
    r, out = _run_build_script(tmp_path, _build_script("f"), fake)
    assert r.returncode == 0, r.stderr
    body = rec.read_text()
    assert "-include" in body and "fb_compat.h" in body   # forced into CFLAGS
    assert "X=" in body and "fb_compat.h" in body.split("X=", 1)[1]  # and CXXFLAGS
    assert "SHIM_PRESENT" in body                          # written at that path


def test_build_script_softens_systemd_static_pie_check_and_spares_others(tmp_path):
    # systemd's src/boot/meson.build aborts configure when the linker can't do
    # -static-pie, which base-builder's focal toolchain can't under ASAN. The
    # driver rewrites that one hard error to a message so the (un-fuzzed) EFI boot
    # stub no longer blocks the build. It must match systemd's exact string and
    # leave every other meson.build alone.
    src = tmp_path / "src"
    boot = src / "systemd" / "src" / "boot"
    boot.mkdir(parents=True)
    boot_meson = boot / "meson.build"
    boot_meson.write_text(
        "subdir_done()\n"
        "        error('Linker does not support -static-pie.')\n")
    # same exact string but NOT under src/boot -> must be left alone (path-scoped)
    decoy = src / "elsewhere" / "meson.build"
    decoy.parent.mkdir(parents=True)
    decoy.write_text("        error('Linker does not support -static-pie.')\n")
    r, out = _run_build_script(tmp_path, _build_script("f"), _FAKE_STD)
    assert r.returncode == 0, r.stderr
    patched = boot_meson.read_text()
    assert "error('Linker does not support -static-pie.')" not in patched
    assert "(fb)" in patched                       # softened to message(...)
    assert "error('Linker does not support -static-pie.')" in decoy.read_text()


_FWUPD_DOCKERFILE = (
    "FROM debian:bookworm-slim\n"
    "RUN apt-get update && apt-get install -y meson cargo\n"
    "ENV JAVA_HOME=/opt/jdk\n"  # pre-clone toolchain setup -> carried
    "ENV LIB_FUZZING_ENGINE=/usr/lib/clang/14/lib/linux/libclang_rt.fuzzer.a\n"
    "RUN curl -sSf https://x | sh\n"  # pre-clone -> carried
    "RUN git clone https://github.com/fwupd/fwupd /src/fwupd \\\n"
    " && git -C /src/fwupd checkout 2.0.18\n"
    "RUN sed -i 's|a|b|' /src/fwupd/contrib/ci/oss-fuzz.py\n"  # post-clone build patch
    "WORKDIR /src/fwupd\n"
    "RUN python3 contrib/ci/oss-fuzz.py\n"
    "RUN mkdir -p /out/release-asan && cp /src/.ossfuzz/out/cab_fuzzer /out/release-asan/harness\n"
)


def test_setup_steps_stop_at_project_clone():
    from fuzzingbrain.importers.bench import _parse_setup_steps
    steps = _parse_setup_steps(_FWUPD_DOCKERFILE, {})
    assert "ENV JAVA_HOME=/opt/jdk" in steps          # pre-clone toolchain kept
    assert any("curl" in s for s in steps)            # pre-clone RUN kept
    assert not any("oss-fuzz.py" in s for s in steps)  # post-clone build NOT leaked
    assert not any("sed" in s for s in steps)          # post-clone patch NOT leaked


def test_setup_steps_drop_debian_fuzzing_engine_env():
    # The bench points LIB_FUZZING_ENGINE at a debian clang path absent on
    # base-builder; base-builder's own engine must win.
    from fuzzingbrain.importers.bench import _parse_setup_steps
    steps = _parse_setup_steps(_FWUPD_DOCKERFILE, {})
    assert not any("LIB_FUZZING_ENGINE" in s for s in steps)


def test_dockerfile_harness_output_and_recipe():
    from fuzzingbrain.importers.bench import (
        _dockerfile_harness_output, _dockerfile_build_recipe,
    )
    assert _dockerfile_harness_output(_FWUPD_DOCKERFILE) == "cab_fuzzer"
    recipe = _dockerfile_build_recipe(_FWUPD_DOCKERFILE, {})
    assert any("oss-fuzz.py" in r for r in recipe)   # the build command
    assert any("sed -i" in r for r in recipe)        # source patch before it
    assert not any("/out" in r for r in recipe)      # /out bundling excluded


def test_dockerfile_harness_output_empty_for_buildsh_projects():
    # A normal bug whose Dockerfile just runs harness/build.sh is NOT a
    # Dockerfile-build target (recipe empty -> importer reuses build.sh).
    from fuzzingbrain.importers.bench import (
        _dockerfile_harness_output, _dockerfile_build_recipe,
    )
    df = (
        "FROM debian\nRUN apt-get install -y autoconf\n"
        "RUN git clone https://x/net-snmp /src/net-snmp\n"
        "RUN /src/harness/build.sh build-libs\n"
        "RUN mkdir -p /out && cp /out/release-asan/harness /out/harness\n"
    )
    assert _dockerfile_build_recipe(df, {}) == []  # only build.sh + /out -> nothing


def test_dockerfile_build_script_exposes_only_target_fuzzer(tmp_path):
    # The Dockerfile build (oss-fuzz.py) emits many fuzzers; build.sh must surface
    # only this bug's target in $OUT. Drive it with a fake recipe + stubbed python.
    from fuzzingbrain.importers.bench import _dockerfile_build_script
    stub = tmp_path / "bin"
    stub.mkdir()
    for name in ("python", "pip3"):
        (stub / name).write_text("#!/bin/bash\nexit 0\n")  # no-op pip install
        (stub / name).chmod(0o755)
    src = tmp_path / "src"
    (src / "fwupd").mkdir(parents=True)
    out = tmp_path / "out"
    out.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    # recipe writes two fuzzers into the (redirected) $OUT scratch dir
    recipe = ['touch "$OUT/cab_fuzzer"', 'touch "$OUT/wacom_fuzzer"']
    script = _dockerfile_build_script("fwupd", recipe, "cab_fuzzer")
    env = {**os.environ, "SRC": str(src), "OUT": str(out), "WORK": str(work),
           "HOME": str(tmp_path), "PATH": f"{stub}:{os.environ['PATH']}"}
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (out / "cab_fuzzer").is_file()       # target exposed
    assert not (out / "wacom_fuzzer").exists()  # other fuzzers stay in scratch


def test_parse_clones_line_continuation_and_branch(tmp_path):
    # A clone split across lines with `-b <tag>` must be parsed as one command.
    df = tmp_path / "Dockerfile"
    df.write_text(
        "ARG TAG=1.9.4\n"
        "RUN git clone --depth 1 -b ${TAG} \\\n"
        "        https://github.com/x/jsoncpp /src/jsoncpp\n"
    )
    main_dir, flatten, main_ref, _ = _parse_clones(df, "https://github.com/x/jsoncpp")
    assert main_dir == "jsoncpp" and not flatten
    assert main_ref == "1.9.4"  # resolved from ARG via -b


def test_parse_clones_flatten_to_src(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text(
        "RUN git clone https://github.com/x/mongoose /src \\\n"
        " && git -C /src checkout abc123\n"
    )
    main_dir, flatten, main_ref, _ = _parse_clones(df, "https://github.com/x/mongoose")
    assert flatten and main_dir == ""
    assert main_ref == "abc123"


def test_parse_setup_steps_carries_toolchain_not_apt_or_clone():
    from fuzzingbrain.importers.bench import _parse_setup_steps
    df = (
        "FROM debian\n"
        "ARG V=1.2.3\n"
        "RUN apt-get install -y git\n"
        "RUN curl -fsSL https://x/jdk-${V}.tgz -o /tmp/j.tgz && tar -C /opt -xzf /tmp/j.tgz\n"
        "ENV JAVA_HOME=/opt/jdk\n"
        "ENV CC=gcc\n"  # must be dropped (base-builder owns CC)
        "RUN git clone https://x/repo /src/repo\n"
        "COPY harness/ /src/harness/\n"
        "RUN /src/harness/build.sh build-libs\n"
        "RUN ls -la /out\n"
    )
    steps = _parse_setup_steps(df, {"V": "1.2.3"})
    assert any("curl" in s and "jdk-1.2.3.tgz" in s for s in steps)  # ARG resolved
    assert "ENV JAVA_HOME=/opt/jdk" in steps
    assert not any("CC=gcc" in s for s in steps)        # protected env dropped
    assert not any("apt-get" in s for s in steps)       # handled separately
    assert not any("git clone" in s for s in steps)     # handled separately
    assert not any("build.sh" in s for s in steps)      # we run our own build
    assert not any("/out" in s for s in steps)


def _run_jdk_select(tmp_path, java_home, available=("17",)):
    # Drive just the JDK-selection prelude of the JVM build script in isolation.
    from fuzzingbrain.importers.bench import _JVM_JDK_SELECT
    jvmdir = tmp_path / "jvm"
    for v in available:
        d = jvmdir / f"java-{v}-openjdk-amd64" / "bin"
        d.mkdir(parents=True)
        (d / "javac").write_text("#!/bin/bash\n:\n")
        (d / "javac").chmod(0o755)
    script = (
        f'export FB_JVM_DIR="{jvmdir}"\n'
        f'export JAVA_HOME="{java_home}"\n'
        + _JVM_JDK_SELECT
        + 'echo "$JAVA_HOME"\n'
    )
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                       env={**os.environ})
    return r.stdout.strip()


def test_jvm_picks_jdk17_over_focal_default_jdk11(tmp_path):
    # base-builder-jvm's default JAVA_HOME is openjdk-11 (too old for GraalVM 24.x
    # JDK-17 bytecode); the build must switch to the system JDK 17.
    out = _run_jdk_select(tmp_path, "/usr/lib/jvm/default-java", available=("17",))
    assert out.endswith("java-17-openjdk-amd64")


def test_jvm_prefers_17_when_both_17_and_21_present(tmp_path):
    # The bench targets bookworm's default-jdk (17); prefer it for parity.
    out = _run_jdk_select(tmp_path, "/usr/lib/jvm/default-java", available=("17", "21"))
    assert out.endswith("java-17-openjdk-amd64")


def test_jvm_keeps_bench_installed_jdk(tmp_path):
    # A bench-installed JDK (avro's /opt/jdk21) must be respected, not overridden.
    out = _run_jdk_select(tmp_path, "/opt/jdk21", available=("17",))
    assert out == "/opt/jdk21"


def test_jvm_wrapper_assembles_classpath_and_targets_entry_class(tmp_path):
    # The generated $OUT/<name> wrapper is what Jazzer actually runs. Execute it
    # against a fake jazzer_driver and verify it builds the classpath from the
    # bench's $OUT/lib (classes + project/dep jars) and targets the entry class.
    from fuzzingbrain.importers.bench import _jvm_build_script
    script = _jvm_build_script("com.x.IntlFuzzer", "IntlFuzzer", "build-libs")
    wrapper = script.split("<<'EOF'\n", 1)[1].split("\nEOF\n", 1)[0]

    d = tmp_path / "out"
    (d / "lib" / "classes").mkdir(parents=True)
    (d / "lib" / "proj.jar").write_text("")
    (d / "lib" / "deps").mkdir()
    (d / "lib" / "deps" / "dep.jar").write_text("")
    (d / "jazzer_driver").write_text(
        '#!/bin/bash\nprintf "%s\\n" "$@" > "$(dirname "$0")/argv"\n'
    )
    (d / "jazzer_driver").chmod(0o755)
    target = d / "IntlFuzzer"
    target.write_text(wrapper)
    target.chmod(0o755)

    r = subprocess.run([str(target), "corpus/"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    argv = (d / "argv").read_text()
    assert "--target_class=com.x.IntlFuzzer" in argv  # FQN entry class wired
    assert "corpus/" in argv                          # libFuzzer args forwarded
    cp_line = next(l for l in argv.splitlines() if l.startswith("--cp="))
    assert "lib/classes" in cp_line                   # bench-compiled classes
    assert "proj.jar" in cp_line and "dep.jar" in cp_line  # project + transitive deps


def test_jvm_build_reuses_bench_harness_step(tmp_path):
    # The JVM build must run the bench harness step (which assembles $OUT/lib) and
    # fail if it does not populate it, rather than recompiling the harness itself.
    from fuzzingbrain.importers.bench import _jvm_build_script
    script = _jvm_build_script("C", "C", "build-libs")
    fake = "#!/bin/bash\nexit 0\n"  # build-libs/harness succeed but make no $OUT/lib
    r, _ = _run_build_script(tmp_path, script, fake)
    assert r.returncode != 0
    assert "did not populate" in r.stderr


def test_needs_rust_signals():
    from fuzzingbrain.importers.bench import _needs_rust, _select_base_image
    assert _needs_rust(["cargo", "git"], "", "")           # apt
    assert _needs_rust([], "ENV RUSTUP_HOME=/x\nRUN rustup", "")  # dockerfile
    assert _needs_rust([], "", "cargo build --release")    # build.sh
    assert not _needs_rust(["git", "cmake"], "FROM x", "clang -o h h.c")
    assert _select_base_image("c++", True).endswith("-rust")
    assert _select_base_image("jvm", False).endswith("-jvm")
    assert _select_base_image("c", False).endswith("base-builder")


def test_detect_libs_cmd_default():
    assert _detect_libs_cmd("usage: build.sh build-libs | harness <config>") == "build-libs"


def test_detect_libs_cmd_renamed():
    assert _detect_libs_cmd("usage: build.sh openldap-libs | harness <config>") == "openldap-libs"


def test_detect_libs_cmd_none():
    # mongoose-style: build.sh <config>, no libs step.
    assert _detect_libs_cmd('cmd="${1:?usage: build.sh <config>}"') == ""


def _make_bug(tmp_path, *, language="c", sources=("vacm_fuzzer.c",), apt=None,
              project="net-snmp", entrypoint=None,
              description="NULL deref in vacm_parse_config_group at vacm.c:414"):
    bug = tmp_path / "netsnmp-vacm-parse-npd"
    (bug / "harness").mkdir(parents=True)
    if description is not None:
        (bug / "description.txt").write_text(description + "\n")
    harness_section = f"harness:\n  entrypoint: {entrypoint}\n" if entrypoint else ""
    (bug / "bench.yaml").write_text(
        "bug_id: netsnmp-vacm-parse-npd\n"
        f"project: {project}\n"
        "target:\n"
        "  repo: https://github.com/net-snmp/net-snmp\n"
        "  vuln_commit: fc28b88a64b7739d76c73058c3811d5387851c32\n"
        f"  language: {language}\n"
        + harness_section
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


def test_jvm_fuzzer_uses_simple_class_for_out_file_and_fqn_for_target(tmp_path):
    # The $OUT fuzzer file must be the simple class name (no dots — a dotted file
    # name breaks discovery), while Jazzer's --target_class needs the FQN.
    spec = spec_from_bench_bug(_make_bug(
        tmp_path, language="jvm", sources=("IntlFuzzer.java",),
        entrypoint="com.oracle.IntlFuzzer.fuzzerTestOneInput",
    ))
    assert 'cat > "$OUT/IntlFuzzer"' in spec.build_script        # simple name
    assert "--target_class=com.oracle.IntlFuzzer" in spec.build_script  # FQN


def test_harness_source_pick_is_deterministic(tmp_path):
    # Multiple sources -> the fuzzer name is the lexicographically first stem, so
    # the chosen entry point does not depend on filesystem iteration order.
    spec = spec_from_bench_bug(
        _make_bug(tmp_path, sources=("z_fuzzer.c", "a_fuzzer.c"))
    )
    assert 'cp "$OUT/$c/harness" "$OUT/a_fuzzer"' in spec.build_script


def test_clone_matches_main_repo_case_and_dotgit_insensitively(tmp_path):
    # The Dockerfile clone is matched to bench.yaml's repo to find the mount dir;
    # the match must ignore case and a .git suffix, or the target mounts at the
    # wrong /src path and the build.sh can't find its source.
    bug = _make_bug(tmp_path)  # bench.yaml repo: .../net-snmp/net-snmp
    (bug / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "RUN git clone https://github.com/Net-SNMP/NET-SNMP.git /src/snmpsrc\n"
    )
    spec = spec_from_bench_bug(bug)
    assert spec.project == "snmpsrc"  # matched despite case + .git mismatch


def test_commit_uses_dockerfile_checkout_ref(tmp_path):
    # When target.repo is a dependency pinned by tag, bench.yaml's vuln_commit
    # names a different repo; the Dockerfile's own checkout ref is authoritative
    # (openscreen builds jsoncpp@1.9.4, not the openscreen SHA).
    bug = _make_bug(tmp_path)  # vuln_commit fc28b88a...
    (bug / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "RUN git clone https://github.com/net-snmp/net-snmp /src/x \\\n"
        " && git -C /src/x checkout v9.9.9-pinned\n"
    )
    spec = spec_from_bench_bug(bug)
    assert spec.commit == "v9.9.9-pinned"  # ref wins over bench.yaml vuln_commit


def test_apt_deps_skip_paths_and_dedup(tmp_path):
    # Path fragments (from a wrapped RUN) are not packages, and duplicates must
    # collapse, or apt-get install gets junk / repeats.
    spec = spec_from_bench_bug(
        _make_bug(tmp_path, apt=["git", "/var/lib/apt", "make", "make", "perl"])
    )
    assert "/var/lib/apt" not in spec.apt_deps
    assert spec.apt_deps.count("make") == 1


def test_flatten_symlink_exposes_repo_at_src(tmp_path):
    # mongoose/dtc clone the repo straight into /src and #include files by bare
    # name; with the mount at /src/<project> the build script must symlink the
    # repo contents up into /src. Drive it end to end.
    bug = _make_bug(tmp_path, project="mongoose")
    (bug / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "RUN git clone https://github.com/net-snmp/net-snmp /src \\\n"
        " && git -C /src checkout fc28b88a\n"
    )
    script = spec_from_bench_bug(bug).build_script
    # fake build.sh succeeds only if the flattened source is visible at $SRC/<file>
    fake = (
        "#!/bin/bash\n"
        '[ "$1" = build-libs ] && exit 0\n'
        '[ "$1" = harness ] && { [ -f "$SRC/amalgam.c" ] || exit 9; '
        'mkdir -p "$OUT/$2"; echo bin > "$OUT/$2/harness"; exit 0; }\n'
        "exit 2\n"
    )
    src = tmp_path / "run" / "src"
    (src / "mongoose").mkdir(parents=True)
    (src / "mongoose" / "amalgam.c").write_text("// the library\n")
    (src / "harness").mkdir()
    (src / "harness" / "build.sh").write_text(fake)
    out = tmp_path / "run" / "out"
    out.mkdir(parents=True)
    env = {**os.environ, "SRC": str(src), "OUT": str(out),
           "SANITIZER": "address", "HOME": str(tmp_path)}
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (src / "amalgam.c").exists()  # symlinked up from $SRC/mongoose


def test_cased_project_name_is_lowercased(tmp_path):
    # OSS-Fuzz rejects a cased project (docker tag must be lower-case). A bench
    # project like "Ghidra"/"FreeRDP" with no matching clone must still come out
    # lower-cased, or the docker build dies with "repository name must be lower".
    spec = spec_from_bench_bug(_make_bug(tmp_path, project="Ghidra"))
    assert spec.project == "ghidra"


def test_cased_clone_dir_is_lowercased_with_symlink(tmp_path):
    # OSS-Fuzz lower-cases the project (docker tag + /src mount); a cased bench
    # dir (Ghidra, ImageMagick) must become lower-case and the build script must
    # symlink the cased path the build.sh hard-codes back to the mounted lower one.
    bug = _make_bug(tmp_path)
    (bug / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "RUN git clone https://github.com/net-snmp/net-snmp /src/Net-SNMP \\\n"
        " && git -C /src/Net-SNMP checkout fc28b88a\n"
    )
    spec = spec_from_bench_bug(bug)
    assert spec.project == "net-snmp"                       # lower-cased
    assert 'ln -sfn "$SRC/net-snmp" "$SRC/Net-SNMP"' in spec.build_script  # cased symlink


def test_spec_build_script_wires_the_bug_fuzzer_name(tmp_path):
    # The end-to-end spec must drive the bench build.sh and target the harness
    # source's stem as the fuzzer name (vacm_fuzzer.c -> vacm_fuzzer).
    r, out = _run_build_script(
        tmp_path / "run", spec_from_bench_bug(_make_bug(tmp_path)).build_script, _FAKE_STD
    )
    assert r.returncode == 0, r.stderr
    assert (out / "vacm_fuzzer").is_file()


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
