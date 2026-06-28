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
    for m in re.finditer(
        r"git clone\s+((?:--\S+\s+)*)(\S+)\s+((?:/src|\$SRC)/\S+)", text
    ):
        url = _subst(m.group(2), args)
        d = _subst(m.group(3), args).replace("$SRC", "/src").replace("${SRC}", "/src")
        # checkout ref for this dir, if any
        cm = re.search(rf"git -C\s+{re.escape(m.group(3))}\s+checkout\s+(\S+)", text)
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


def _build_script(fuzzer_name: str) -> str:
    """OSS-Fuzz build.sh body that drives the bench harness build.

    Reuses ``$SRC/harness/build.sh`` (the bench's own recipe) and selects a
    config that matches ``$SANITIZER``. Tries asan configs in priority order so
    projects that only define a subset still build.
    """
    return (
        'set -eu\n'
        # The repo is bind-mounted with host ownership; without this, git in the
        # build container refuses to operate ("dubious ownership"), breaking any
        # build.sh that runs submodule update / autoreconf (e.g. jq, oniguruma).
        "git config --global --add safe.directory '*' || true\n"
        'BS="$SRC/harness/build.sh"\n'
        'bash "$BS" build-libs\n'
        'if [ "${SANITIZER:-address}" = "coverage" ]; then\n'
        '  CFGS="coverage"\n'
        'else\n'
        '  CFGS="release-asan debug-asan debug"\n'
        'fi\n'
        'built=""\n'
        'for c in $CFGS; do\n'
        '  if bash "$BS" harness "$c" && [ -f "/out/$c/harness" ]; then\n'
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
    if main_dir:
        project = main_dir

    apt_deps = _parse_apt_deps(dockerfile)
    # base-builder's meson is too old for some projects (need >= 0.55) — pull a
    # current meson/ninja from pip when the project builds with meson.
    pip_deps = ["meson", "ninja"] if "meson" in apt_deps else []

    harness_dir = bug_dir / "harness"
    source = _harness_source(harness_dir)
    fuzzer_name = source.stem

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
        build_script=_build_script(fuzzer_name),
        description=description,
        extra_clones=extra_clones,
        pip_deps=pip_deps,
    )
