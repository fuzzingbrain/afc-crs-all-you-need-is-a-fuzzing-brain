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


def _parse_clones(dockerfile: Path, main_repo: str) -> tuple[str, list[dict]]:
    """Parse `git clone <url> /src/<dir>` (+ checkout) lines from the Dockerfile.

    Returns (main_dir, extra_clones). main_dir is the /src directory the build.sh
    expects the target source at (matched to main_repo); extra_clones are the
    dependency repos the build needs at their own fixed /src paths.
    """
    if not dockerfile.is_file():
        return "", []
    text = dockerfile.read_text()
    args = _parse_dockerfile_args(text)

    clones = []
    # `git clone [flags...] <url> /src/<dir>` — flags (e.g. --depth 1,
    # --filter=blob:none) sit between; the URL is the last token before the dir.
    for m in re.finditer(r"git clone\s+(.+?)\s+((?:/src|\$SRC)/\S+)", text):
        url = _subst(m.group(1).split()[-1], args)
        d = _subst(m.group(2), args).replace("$SRC", "/src").replace("${SRC}", "/src")
        # checkout ref for this dir, if any
        cm = re.search(rf"git -C\s+{re.escape(m.group(2))}\s+checkout\s+(\S+)", text)
        ref = _subst(cm.group(1), args) if cm else ""
        clones.append({"url": url, "dir": d, "ref": ref})

    main_dir, extra = "", []
    norm_main = _normalize_repo(main_repo)
    for c in clones:
        if not main_dir and _normalize_repo(c["url"]) == norm_main:
            main_dir = c["dir"].rsplit("/", 1)[-1]
        else:
            extra.append(c)
    return main_dir, extra


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
        'BS="$SRC/harness/build.sh"\n'
        # Optional library-build step; name varies, some projects have none.
        f'for L in {libs_list}; do bash "$BS" "$L" 2>/dev/null && break || true; done\n'
        'if [ "${SANITIZER:-address}" = "coverage" ]; then\n'
        '  CFGS="coverage"\n'
        'else\n'
        '  CFGS="release-asan debug-asan debug"\n'
        'fi\n'
        'built=""\n'
        'for c in $CFGS; do\n'
        # Try "harness <cfg>" (most) then bare "<cfg>" (mongoose-style).
        '  if { bash "$BS" harness "$c" || bash "$BS" "$c"; } 2>/dev/null '
        '&& [ -f "/out/$c/harness" ]; then\n'
        f'    cp "/out/$c/harness" "$OUT/{fuzzer_name}"\n'
        '    built="$c"; break\n'
        '  fi\n'
        'done\n'
        'if [ -z "$built" ]; then echo "no harness config built" >&2; exit 1; fi\n'
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
    main_dir, extra_clones = _parse_clones(dockerfile, main_repo)
    case_fix = ""
    if main_dir:
        # OSS-Fuzz lower-cases the project name, so helper.py mounts the target
        # at /src/<lower> while the build.sh hard-codes the original (possibly
        # cased) /src/<dir>. Use the lower-cased name as the project and symlink
        # the cased path to it so the build.sh finds its source.
        if main_dir != main_dir.lower():
            case_fix = (
                f'[ -e "$SRC/{main_dir}" ] || '
                f'ln -sfn "$SRC/{main_dir.lower()}" "$SRC/{main_dir}"\n'
            )
        project = main_dir.lower()

    apt_deps = _parse_apt_deps(dockerfile)
    # base-builder's meson is too old for some projects (need >= 0.55) — pull a
    # current meson/ninja from pip when the project builds with meson.
    pip_deps = ["meson", "ninja"] if "meson" in apt_deps else []

    harness_dir = bug_dir / "harness"
    source = _harness_source(harness_dir)
    fuzzer_name = source.stem
    build_sh = harness_dir / "build.sh"
    libs_cmd = _detect_libs_cmd(build_sh.read_text()) if build_sh.is_file() else "build-libs"

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
        build_script=case_fix + _build_script(fuzzer_name, libs_cmd),
        description=description,
        extra_clones=extra_clones,
        pip_deps=pip_deps,
    )
