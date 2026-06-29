# SPDX-License-Identifier: Apache-2.0
"""Derive a HarnessSpec from a FuzzingBrain-Bench bug directory.

A bench bug is a self-contained target: ``bench.yaml`` (project, repo, vulnerable
commit, language), a ``harness/`` directory (one libFuzzer source plus a
``build.sh`` exposing the uniform ``build-libs`` / ``harness <config>`` contract),
and a ``Dockerfile`` listing apt build deps. This module reads those and produces
a :class:`~fuzzingbrain.importers.external_harness.HarnessSpec` so V2 can build
and fuzz the bug through the normal pipeline.

The generated OSS-Fuzz ``build_script`` reuses the bench's own ``build.sh``
verbatim — it already emits a libFuzzer+sanitizer binary at
``/out/<config>/harness`` — and copies the result to ``$OUT``. The config is
chosen from ``$SANITIZER`` (coverage vs an asan variant), so the same recipe
serves every bench project regardless of its build system (autoconf, cmake,
meson, gn).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .external_harness import HarnessSpec

# Sources are these extensions; everything else in harness/ (build.sh, *.md) is
# support and copied verbatim but not treated as the fuzzer entry point.
_SRC_EXTS = (".c", ".cc", ".cpp", ".cxx", ".c++")

# apt packages that collide with base-builder's own toolchain. base-builder
# ships its (newer) clang + compiler-rt; reinstalling Debian's shadows them and
# breaks the build. Keep everything else (autoconf, meson, ninja, libclang-dev
# for bindgen, ...).
_TOOLCHAIN_PKG = re.compile(r"^(clang(-\d+)?|llvm(-\d+)?|libclang-rt-[\w.-]+)$")

_LANG_MAP = {"c": "c", "c++": "c++", "cpp": "c++", "cxx": "c++", "jvm": "jvm"}

# Rust toolchain packages: their presence means the build invokes cargo/rustc
# (e.g. harfbuzz's fontations crate, fwupd) — base-builder lacks Rust, so switch
# to base-builder-rust which ships clang *and* the Rust toolchain.
_RUST_PKG = re.compile(r"^(cargo|rustc|rustup)$")

_BASE = "gcr.io/oss-fuzz-base/base-builder"


def _select_base_image(language: str, needs_rust: bool) -> str:
    """Pick the OSS-Fuzz builder image that carries the needed toolchain."""
    if language == "jvm":
        return f"{_BASE}-jvm"  # Jazzer + JDK
    if needs_rust:
        return f"{_BASE}-rust"  # clang + cargo/rustc
    return _BASE


def _needs_rust(apt_deps: list[str], dockerfile_text: str, build_sh_text: str) -> bool:
    """Detect a Rust toolchain dependency from any available signal.

    Bench bugs declare Rust three ways: an apt cargo/rustc package, a rustup
    bootstrap in the Dockerfile (harfbuzz), or a cargo invocation in build.sh.
    """
    if any(_RUST_PKG.match(p) for p in apt_deps):
        return True
    if re.search(r"rustup|RUSTUP_HOME|CARGO_HOME", dockerfile_text):
        return True
    return bool(re.search(r"\bcargo\b", build_sh_text))


def _parse_apt_deps(dockerfile: Path) -> list[str]:
    """Best-effort extraction of apt packages from the bench Dockerfile."""
    if not dockerfile.is_file():
        return []
    text = dockerfile.read_text()
    m = re.search(r"apt-get install[^\n]*?-y[^\n]*?(.+?)(?:&&|\n\n|\Z)", text, re.S)
    if not m:
        return []
    blob = m.group(1)
    pkgs = []
    for tok in blob.replace("\\", " ").split():
        if tok.startswith("-") or "=" in tok or tok in ("rm", "rf", "apt-get"):
            continue
        if tok.startswith("--") or "/" in tok:
            continue
        if _TOOLCHAIN_PKG.match(tok):
            continue
        pkgs.append(tok)
    # de-dup, preserve order
    seen, out = set(), []
    for p in pkgs:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _parse_dockerfile_args(text: str) -> dict:
    """Collect `ARG NAME=default` defaults for ${NAME} substitution."""
    args = {}
    for m in re.finditer(r"^\s*ARG\s+([A-Za-z_]\w*)=(\S+)", text, re.M):
        args[m.group(1)] = m.group(2)
    return args


def _subst(value: str, args: dict) -> str:
    """Resolve ${NAME} / $NAME against ARG defaults."""
    def repl(m):
        return args.get(m.group(1) or m.group(2), m.group(0))
    return re.sub(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", repl, value)


def _normalize_repo(url: str) -> str:
    return url.rstrip("/").removesuffix(".git").lower()


def _parse_clones(
    dockerfile: Path, main_repo: str
) -> tuple[str, bool, str, list[dict]]:
    """Parse `git clone <url> /src[/<dir>]` (+ checkout) lines from the Dockerfile.

    Returns (main_dir, main_flatten, main_ref, extra_clones). main_dir is the /src
    directory the build.sh expects the target source at (matched to main_repo);
    main_flatten is True when the main repo is cloned to /src itself (so its
    contents sit directly under /src, e.g. mongoose/dtc); main_ref is the ref the
    Dockerfile checks the target out at; extra_clones are the dependency repos the
    build needs at their own fixed /src paths.
    """
    if not dockerfile.is_file():
        return "", False, "", []
    text = dockerfile.read_text()
    # Join shell line-continuations so a clone split across lines (e.g. openscreen's
    # `git clone -b $TAG \<newline> <url> /src/jsoncpp`) is seen as one command.
    text = re.sub(r"\\\s*\n", " ", text)
    args = _parse_dockerfile_args(text)

    clones = []
    # `git clone [flags...] <url> /src[/<dir>]` — flags (e.g. --depth 1,
    # --filter=blob:none, -b <tag>) sit between; the URL is the last token before
    # the dir. The subdir is optional: some bugs clone straight into /src ("flatten").
    for m in re.finditer(r"git clone\s+(.+?)\s+((?:/src|\$SRC)(?:/\S+)?)(?:\s|$)", text):
        flags = m.group(1)
        url = _subst(flags.split()[-1], args)
        d = _subst(m.group(2), args).replace("${SRC}", "/src").replace("$SRC", "/src")
        # ref: prefer an explicit `git -C <dir> checkout <ref>`, else `-b <tag>`.
        cm = re.search(rf"git -C\s+{re.escape(m.group(2))}\s+checkout\s+(\S+)", text)
        if cm:
            ref = _subst(cm.group(1), args)
        else:
            bm = re.search(r"(?:^|\s)(?:-b|--branch)[= ]+(\S+)", flags)
            ref = _subst(bm.group(1), args) if bm else ""
        clones.append({"url": url, "dir": d.rstrip("/"), "ref": ref})

    main_dir, flatten, main_ref, extra = "", False, "", []
    norm_main = _normalize_repo(main_repo)
    matched = False
    for c in clones:
        if not matched and _normalize_repo(c["url"]) == norm_main:
            matched = True
            main_ref = c["ref"]
            if c["dir"] == "/src":
                flatten = True
            else:
                main_dir = c["dir"].rsplit("/", 1)[-1]
        else:
            extra.append(c)
    return main_dir, flatten, main_ref, extra


# ENV keys base-builder owns — overriding them breaks its clang toolchain.
_PROTECTED_ENV = re.compile(r"^(CC|CXX|CFLAGS|CXXFLAGS|SANITIZER|OUT|SRC|WORK)\b")


def _parse_setup_steps(dockerfile_text: str, args: dict) -> list[str]:
    """Carry over toolchain-setup ENV/RUN directives from the bench Dockerfile.

    Bench bugs install non-apt toolchains (a pinned JDK+maven for avro, a rustup
    nightly + bindgen for harfbuzz) via Dockerfile RUN/ENV steps. We replicate
    those verbatim, skipping what the importer already handles (apt, the clones,
    the harness COPY/build) and ENV that would clobber base-builder's compiler.
    """
    text = re.sub(r"\\\s*\n", " ", dockerfile_text)  # join line-continuations
    steps: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"(\w+)\s+(.*)", line)
        if not m:
            continue
        instr, rest = m.group(1).upper(), _subst(m.group(2), args)
        if instr == "ENV":
            if _PROTECTED_ENV.match(rest.lstrip()):
                continue
            steps.append(f"ENV {rest}")
        elif instr == "RUN":
            low = rest.lower()
            if any(
                s in low
                for s in ("apt-get", "git clone", "harness/build.sh", "/out")
            ):
                continue
            if "chmod" in low and "harness" in low:
                continue
            steps.append(f"RUN {rest}")
    return steps


def _detect_libs_cmd(build_sh_text: str) -> str:
    """Find the library-build subcommand name, which varies across bench bugs.

    Most use ``build-libs``; some rename it (openldap: ``openldap-libs``). A few
    have no separate libs step (mongoose: just ``build.sh <config>``) -> "".
    """
    m = re.search(r"usage:\s*build\.sh\s+([A-Za-z][\w-]*)\s*\|", build_sh_text)
    if m and m.group(1) != "harness":
        return m.group(1)
    m = re.search(r'=\s*"([A-Za-z][\w-]*-libs)"', build_sh_text)
    return m.group(1) if m else ""


def _build_script(fuzzer_name: str, libs_cmd: str = "build-libs") -> str:
    """OSS-Fuzz build.sh body that drives the bench harness build.

    Reuses ``$SRC/harness/build.sh`` (the bench's own recipe) and selects a
    config that matches ``$SANITIZER``. Robust to interface variation across
    bench projects: tries the detected libs step then ``build-libs``, and invokes
    each config as both ``harness <cfg>`` and bare ``<cfg>``.
    """
    libs_list = " ".join(dict.fromkeys(filter(None, [libs_cmd, "build-libs"])))
    return (
        'set -eu\n'
        # The repo is bind-mounted with host ownership; without this, git in the
        # build container refuses to operate ("dubious ownership"), breaking any
        # build.sh that runs submodule update / autoreconf (e.g. jq, oniguruma).
        "git config --global --add safe.directory '*' || true\n"
        # base-builder (Ubuntu 20.04) ships gettext 0.19; projects whose
        # configure.ac requires 0.20+ (hunspell) abort in autopoint during
        # autoreconf. Fuzzing needs no translations, so skip autopoint — the m4
        # macros these projects ship are enough for configure.
        'export AUTOPOINT="${AUTOPOINT:-true}"\n'
        'BS="$SRC/harness/build.sh"\n'
        'L_LOG=/tmp/fb_libs.log\n'
        # Optional library-build step; name varies, some projects have none.
        f'for L in {libs_list}; do bash "$BS" "$L" >"$L_LOG" 2>&1 && break || true; done\n'
        'if [ "${SANITIZER:-address}" = "coverage" ]; then\n'
        '  CFGS="coverage"\n'
        'else\n'
        '  CFGS="release-asan debug-asan debug"\n'
        'fi\n'
        'built=""\n'
        'for c in $CFGS; do\n'
        # Try "harness <cfg>" (most) then bare "<cfg>" (mongoose-style). Capture
        # output per config so a real failure is visible (no silent /dev/null).
        '  bash "$BS" harness "$c" >"/tmp/fb_$c.log" 2>&1 '
        '|| bash "$BS" "$c" >"/tmp/fb_$c.log" 2>&1 || true\n'
        '  if [ -f "$OUT/$c/harness" ]; then\n'
        f'    cp "$OUT/$c/harness" "$OUT/{fuzzer_name}"\n'
        '    built="$c"; break\n'
        '  fi\n'
        'done\n'
        'if [ -z "$built" ]; then\n'
        '  echo "no harness config built; build.sh output follows:" >&2\n'
        '  tail -n 40 "$L_LOG" /tmp/fb_*.log 2>/dev/null >&2 || true\n'
        '  exit 1\n'
        'fi\n'
    )


def _jvm_build_script(target_class: str, out_name: str, libs_cmd: str) -> str:
    """Build a Jazzer fuzz target from a bench JVM bug.

    The bench's own ``harness`` step emits a plain-``java`` reproducer (for the
    grader), not a fuzz target — but it also assembles ``/out/lib`` (the compiled
    harness ``classes`` plus the project and dependency jars) with the *correct*
    classpath. We reuse that assembly verbatim (re-deriving the classpath
    ourselves is brittle — avro/pdfbox need transitive deps), and just drop a
    standard libFuzzer-compatible Jazzer wrapper at ``$OUT/<class>`` over it.
    Jazzer is a libFuzzer driver, so V2's existing fuzz loop runs it unchanged.
    """
    libs_list = " ".join(dict.fromkeys(filter(None, [libs_cmd, "build-libs"])))
    return (
        'set -eu\n'
        "git config --global --add safe.directory '*' || true\n"
        'BS="$SRC/harness/build.sh"\n'
        # Build the project, then run the bench harness step which populates
        # $OUT/lib (LIB=/out/lib in the bench recipe) with classes + jars.
        f'for L in {libs_list}; do bash "$BS" "$L" && break || true; done\n'
        'built=""\n'
        'for c in release-asan debug-asan debug; do\n'
        '  if { bash "$BS" harness "$c" || bash "$BS" "$c"; } '
        '&& [ -d "$OUT/lib/classes" ]; then built="$c"; break; fi\n'
        'done\n'
        '[ -n "$built" ] || { echo "bench harness did not populate \\$OUT/lib" >&2; exit 1; }\n'
        # Jazzer runtime + a libFuzzer-compatible wrapper over the bench classpath.
        'cp /usr/local/bin/jazzer_driver /usr/local/bin/jazzer_agent_deploy.jar "$OUT/"\n'
        f'cat > "$OUT/{out_name}" <<\'EOF\'\n'
        '#!/bin/bash\n'
        'this_dir=$(dirname "$0")\n'
        'cp="$this_dir/lib/classes"\n'
        'for j in "$this_dir"/lib/*.jar "$this_dir"/lib/deps/*.jar; do '
        '[ -f "$j" ] && cp="$cp:$j"; done\n'
        'exec "$this_dir/jazzer_driver" '
        '--agent_path="$this_dir/jazzer_agent_deploy.jar" \\\n'
        '  --cp="$cp" '
        f'--target_class={target_class} --jvm_args="-Xmx2048m" "$@"\n'
        'EOF\n'
        f'chmod +x "$OUT/{out_name}"\n'
    )


def _harness_source(harness_dir: Path) -> Path:
    srcs = sorted(
        p for p in harness_dir.iterdir() if p.suffix.lower() in _SRC_EXTS
    )
    if not srcs:
        raise ValueError(f"no harness source ({_SRC_EXTS}) in {harness_dir}")
    return srcs[0]


def spec_from_bench_bug(
    bug_dir: str | Path, with_description: bool = True
) -> HarnessSpec:
    """Build a :class:`HarnessSpec` from a bench bug directory.

    Args:
        bug_dir: Path to a bench bug (contains bench.yaml, harness/, Dockerfile).
        with_description: Include the bug's description.txt as a direction hint.
            The bench's task is to reproduce *from a description*, so this is the
            faithful (and far more effective) mode; set False to measure purely
            autonomous discovery.

    Returns:
        A HarnessSpec whose build_script drives the bench's own harness build.
    """
    bug_dir = Path(bug_dir)
    meta = yaml.safe_load((bug_dir / "bench.yaml").read_text())
    target = meta.get("target", {})

    project = meta["project"]
    raw_lang = str(target.get("language", "c")).lower()
    language = _LANG_MAP.get(raw_lang, raw_lang)
    main_repo = target["repo"]
    commit = str(target.get("vuln_commit", "") or "")

    # The bench build.sh hard-codes /src/<dir> paths from the bench Dockerfile.
    # Mount the target there (project = that dir) and replicate dependency clones,
    # otherwise build.sh fails ("/src/aom: No such file", missing libde265, ...).
    dockerfile = bug_dir / "Dockerfile"
    main_dir, main_flatten, main_ref, extra_clones = _parse_clones(dockerfile, main_repo)
    # The Dockerfile's own checkout of the target is authoritative: when the bench
    # target.repo is a dependency pinned by tag (openscreen builds jsoncpp@1.9.4),
    # bench.yaml's vuln_commit names a *different* repo, so prefer the clone ref.
    if main_ref:
        commit = main_ref
    case_fix = ""
    if main_dir:
        # The build.sh hard-codes the cased /src/<dir>; use the lower-cased name
        # as the project and symlink the cased path so the build.sh finds it.
        if main_dir != main_dir.lower():
            case_fix = (
                f'[ -e "$SRC/{main_dir}" ] || '
                f'ln -sfn "$SRC/{main_dir.lower()}" "$SRC/{main_dir}"\n'
            )
        project = main_dir.lower()
    # OSS-Fuzz requires a lower-case project (it is the docker image tag and the
    # /src mount dir); cased bench projects (Ghidra, FreeRDP) break the build.
    project = project.lower()
    if main_flatten:
        # The build.sh expects the repo flattened at /src (it hard-codes SRC=/src
        # and #includes files by bare name). helper.py mounts it at /src/<project>,
        # so symlink the repo's contents up into /src before building.
        case_fix += (
            f'for f in "$SRC/{project}"/* "$SRC/{project}"/.[!.]*; do\n'
            f'  [ -e "$f" ] && ln -sfn "$f" "$SRC/$(basename "$f")" || true\n'
            'done\n'
        )

    harness_dir = bug_dir / "harness"
    build_sh = harness_dir / "build.sh"
    build_sh_text = build_sh.read_text() if build_sh.is_file() else ""
    libs_cmd = _detect_libs_cmd(build_sh_text) if build_sh_text else "build-libs"

    target_class = ""
    if language == "jvm":
        # The Jazzer entry class names the fuzz target (bench.yaml entrypoint is
        # "<Class>.fuzzerTestOneInput"); fall back to the sole .java stem.
        entry = str(meta.get("harness", {}).get("entrypoint", ""))
        target_class = entry.rsplit(".", 1)[0] if "." in entry else entry
        if not target_class:
            javas = sorted(harness_dir.glob("*.java"))
            target_class = javas[0].stem if javas else "Fuzzer"
        fuzzer_name = target_class.rsplit(".", 1)[-1]  # simple name -> $OUT file
    else:
        fuzzer_name = _harness_source(harness_dir).stem

    apt_deps = _parse_apt_deps(dockerfile)
    dockerfile_text = dockerfile.read_text() if dockerfile.is_file() else ""
    setup_steps = _parse_setup_steps(dockerfile_text, _parse_dockerfile_args(dockerfile_text))
    base_image = _select_base_image(
        language, _needs_rust(apt_deps, dockerfile_text, build_sh_text)
    )
    if base_image.endswith("-rust"):
        # cargo/rustc ship in base-builder-rust; Debian's would shadow them.
        apt_deps = [p for p in apt_deps if not _RUST_PKG.match(p)]
    # base-builder's meson is too old for some projects (need >= 0.55) — pull a
    # current meson/ninja from pip when the project builds with meson. Include
    # jinja2 under the same (pip) python: systemd's meson.build imports it, and
    # the apt python3-jinja2 is invisible to the pip-installed meson's python.
    pip_deps = ["meson", "ninja", "jinja2"] if "meson" in apt_deps else []

    # Copy the whole harness dir except docs; build.sh + sources must be present.
    harness_files = [
        str(p)
        for p in sorted(harness_dir.iterdir())
        if p.is_file() and p.suffix.lower() != ".md"
    ]

    description = ""
    desc_file = bug_dir / "description.txt"
    if with_description and desc_file.is_file():
        description = desc_file.read_text(errors="replace").strip()

    return HarnessSpec(
        project=project,
        language=language,
        main_repo=main_repo,
        commit=commit,
        harness_files=harness_files,
        apt_deps=apt_deps,
        build_script=(
            _jvm_build_script(target_class, fuzzer_name, libs_cmd)
            if language == "jvm"
            else case_fix + _build_script(fuzzer_name, libs_cmd)
        ),
        description=description,
        extra_clones=extra_clones,
        pip_deps=pip_deps,
        base_image=base_image,
        setup_steps=setup_steps,
    )
