# SPDX-License-Identifier: Apache-2.0
"""Materialize a FuzzingBrain workspace from a bring-your-own-harness spec.

V2's pipeline builds fuzzers through the OSS-Fuzz contract: a workspace with
``repo/`` (the target source) and ``fuzz-tooling/`` (``infra/helper.py`` plus a
``projects/<name>/`` directory holding ``project.yaml``, ``Dockerfile`` and
``build.sh``). The builder then runs, unchanged::

    helper.py build_fuzzers --sanitizer <san> --engine libfuzzer \
        --mount_path /src/<name> <name> <repo_path>

helper.py bind-mounts the local ``repo/`` over the project source and runs the
project's ``build.sh`` inside ``base-builder`` with the OSS-Fuzz environment
(``$CC``/``$CXX``/``$CFLAGS``/``$OUT``/``$SRC``/``$LIB_FUZZING_ENGINE``; the
sanitizer is injected per build).

Many real targets are not OSS-Fuzz projects: a benchmark or an internal tool
ships its *own* libFuzzer harness and a known-good build recipe. This importer
turns such a target into a standard OSS-Fuzz project so V2 can run against it
with no pipeline changes. The build recipe lives in the spec (``build_script``),
expressed against the OSS-Fuzz environment, so this module stays target-neutral.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class HarnessSpec:
    """A bring-your-own-harness target.

    Attributes:
        project: OSS-Fuzz-style project name (no slashes); names the workspace
            project and the produced fuzzer's mount path.
        language: ``c`` / ``c++`` / ``rust`` / ``jvm`` / ... (project.yaml).
        main_repo: Git URL of the target source.
        commit: Commit/tag/branch to check out (e.g. the vulnerable revision).
            Empty means the cloned default branch.
        harness_files: Local paths to harness sources copied into the project so
            the Dockerfile can ``COPY`` them into ``$SRC/harness``.
        build_script: Body of ``build.sh``, written against the OSS-Fuzz
            environment. It must emit one or more fuzzers into ``$OUT``.
        sanitizers: Sanitizers to build (``project.yaml`` + builder list).
        apt_deps: Extra ``base-builder`` apt packages the build needs.
        base_image: Builder image (override for non-default toolchains).
    """

    project: str
    language: str
    main_repo: str
    build_script: str
    commit: str = ""
    harness_files: List[str] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=lambda: ["address"])
    apt_deps: List[str] = field(default_factory=list)
    base_image: str = "gcr.io/oss-fuzz-base/base-builder"
    # Dependency repos the build needs at fixed /src paths (each {url, dir, ref}).
    # The build.sh often hard-codes these (e.g. libheif needs /src/libde265).
    extra_clones: List[dict] = field(default_factory=list)
    # pip packages to install (e.g. a newer meson/ninja than base-builder ships).
    pip_deps: List[str] = field(default_factory=list)
    # Toolchain setup directives carried over from the source Dockerfile, each a
    # full Dockerfile instruction ("ENV JAVA_HOME=...", "RUN curl ... | tar ..."),
    # emitted after apt/pip and before the clones. Replicates non-apt toolchain
    # installs (a pinned JDK+maven, a rustup nightly bootstrap, ...).
    setup_steps: List[str] = field(default_factory=list)
    # Optional known-vulnerability report. Written to <ws>/DESCRIPTION.txt and
    # fed to direction planning to focus the search (see pov_fullscan).
    description: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "HarnessSpec":
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"Unknown spec fields: {sorted(unknown)}")
        for required in ("project", "language", "main_repo", "build_script"):
            if not data.get(required):
                raise ValueError(f"Spec missing required field: {required}")
        if "/" in data["project"]:
            raise ValueError(f"project must not contain '/': {data['project']!r}")
        return cls(**data)

    @classmethod
    def from_json(cls, path: str | Path) -> "HarnessSpec":
        return cls.from_dict(json.loads(Path(path).read_text()))


def _render_project_yaml(spec: HarnessSpec) -> str:
    sans = "\n".join(f"  - {s}" for s in spec.sanitizers)
    return (
        f"homepage: {spec.main_repo}\n"
        f"language: {spec.language}\n"
        f"main_repo: {spec.main_repo}\n"
        "fuzzing_engines:\n  - libfuzzer\n"
        f"sanitizers:\n{sans}\n"
    )


def _render_dockerfile(spec: HarnessSpec) -> str:
    lines = [f"FROM {spec.base_image}"]
    if spec.apt_deps:
        deps = " ".join(spec.apt_deps)
        lines.append(
            "RUN apt-get update && apt-get install -y --no-install-recommends "
            f"{deps} && rm -rf /var/lib/apt/lists/*"
        )
    if spec.pip_deps:
        pips = " ".join(spec.pip_deps)
        lines.append(f"RUN pip3 install --no-cache-dir --upgrade {pips}")
    # Toolchain setup carried over from the source Dockerfile (pinned JDK/maven,
    # rustup nightly, ...) — emitted before the clones so the build sees it.
    for step in spec.setup_steps:
        lines.append(step)
    # Dependency repos the build.sh expects at fixed /src paths.
    for c in spec.extra_clones:
        url, d = c["url"], c["dir"]
        ref = c.get("ref", "")
        line = f"RUN git clone {url} {d}"
        if ref:
            line += f" && git -C {d} checkout {ref}"
        lines.append(line)
    # Baseline clone so the image is self-contained; helper.py --mount_path
    # bind-mounts the local repo/ over this at build time.
    clone = f"RUN git clone --depth 1 {spec.main_repo} $SRC/{spec.project}"
    if spec.commit:
        clone = (
            f"RUN git clone {spec.main_repo} $SRC/{spec.project} && "
            f"git -C $SRC/{spec.project} checkout {spec.commit} || true"
        )
    lines.append(clone)
    if spec.harness_files:
        lines.append("COPY harness $SRC/harness")
    lines.append("COPY build.sh $SRC/")
    lines.append(f"WORKDIR $SRC/{spec.project}")
    return "\n".join(lines) + "\n"


def _render_build_sh(spec: HarnessSpec) -> str:
    return "#!/bin/bash -eu\n" + spec.build_script.rstrip("\n") + "\n"


def _git_clone(main_repo: str, commit: str, dest: Path) -> None:
    subprocess.run(["git", "clone", main_repo, str(dest)], check=True)
    if commit:
        subprocess.run(["git", "-C", str(dest), "checkout", commit], check=True)
    # Fetch submodules at the checked-out commit's pinned revisions. Many targets
    # vendor libraries this way (upx's ucl/zlib, opcua's deps); without them the
    # build fails with "No SOURCES given to target". Harmless when there are none.
    subprocess.run(
        ["git", "-C", str(dest), "submodule", "update", "--init", "--recursive"],
        check=False,
    )


def build_workspace(
    spec: HarnessSpec,
    dest: str | Path,
    oss_fuzz_dir: str | Path,
    clone_repo: bool = True,
    overwrite: bool = False,
) -> Path:
    """Materialize a V2 workspace for ``spec`` under ``dest``.

    Produces::

        dest/repo/                              # target source @ commit
        dest/fuzz-tooling/infra/                # copied from oss_fuzz_dir
        dest/fuzz-tooling/projects/<project>/   # project.yaml, Dockerfile, build.sh, harness/

    Args:
        spec: The target description.
        dest: Workspace directory to create.
        oss_fuzz_dir: A local OSS-Fuzz checkout to source ``infra/`` from.
        clone_repo: Clone the target into ``repo/`` (set False if already present).
        overwrite: Replace ``dest`` if it exists.

    Returns:
        The workspace path (pass to ``FuzzingBrain.sh <path>`` / ``--workspace``).
    """
    dest = Path(dest)
    oss_fuzz_dir = Path(oss_fuzz_dir)
    infra_src = oss_fuzz_dir / "infra"
    if not (infra_src / "helper.py").is_file():
        raise FileNotFoundError(f"helper.py not found under {infra_src}")

    if dest.exists():
        if not overwrite:
            raise FileExistsError(f"Workspace already exists: {dest}")
        shutil.rmtree(dest)

    proj_dir = dest / "fuzz-tooling" / "projects" / spec.project
    proj_dir.mkdir(parents=True)

    # 1) target source
    if clone_repo:
        _git_clone(spec.main_repo, spec.commit, dest / "repo")

    # 2) OSS-Fuzz infra (helper.py + base image build context)
    shutil.copytree(infra_src, dest / "fuzz-tooling" / "infra")

    # 3) synthesized OSS-Fuzz project
    (proj_dir / "project.yaml").write_text(_render_project_yaml(spec))
    (proj_dir / "Dockerfile").write_text(_render_dockerfile(spec))
    build_sh = proj_dir / "build.sh"
    build_sh.write_text(_render_build_sh(spec))
    build_sh.chmod(0o755)
    # Optional bug report for direction planning (see pov_fullscan._get_vuln_hint)
    if spec.description.strip():
        (dest / "DESCRIPTION.txt").write_text(spec.description.strip() + "\n")
    if spec.harness_files:
        hdir = proj_dir / "harness"
        hdir.mkdir()
        for f in spec.harness_files:
            src = Path(f)
            if not src.is_file():
                raise FileNotFoundError(f"harness file not found: {src}")
            shutil.copy2(src, hdir / src.name)

    return dest


def _main(argv: Optional[List[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="python -m fuzzingbrain.importers.external_harness",
        description="Materialize a V2 workspace from a harness spec JSON.",
    )
    p.add_argument("spec", help="Path to the harness spec JSON")
    p.add_argument("dest", help="Workspace directory to create")
    p.add_argument(
        "--oss-fuzz",
        default="/data4/ze/oss-fuzz",
        help="Local OSS-Fuzz checkout (for infra/helper.py)",
    )
    p.add_argument("--overwrite", action="store_true", help="Replace dest if present")
    p.add_argument(
        "--no-clone", action="store_true", help="Do not clone repo/ (already present)"
    )
    args = p.parse_args(argv)

    spec = HarnessSpec.from_json(args.spec)
    ws = build_workspace(
        spec,
        args.dest,
        args.oss_fuzz,
        clone_repo=not args.no_clone,
        overwrite=args.overwrite,
    )
    print(f"workspace ready: {ws}")
    print(f"run: ./FuzzingBrain.sh {ws} --task-type pov --pov-count 1")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
