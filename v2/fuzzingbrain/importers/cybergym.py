# SPDX-License-Identifier: Apache-2.0
"""Import a CyberGym / ARVO task into a V2 build workspace.

CyberGym tasks are ARVO entries (Atlas of Reproducible Vulnerabilities from
OSS-Fuzz). Each is backed by a prebuilt, *validated-reproducible* project image
``n132/arvo:<id>-vul`` that already carries the exact vulnerable source, the
project's own OSS-Fuzz build recipe (``$SRC/build.sh`` + the right ``WORKDIR``),
its dependencies, and the fuzz harness. So unlike FuzzingBrain-Bench — where the
importer reconstructs a debian environment on base-builder and patches over the
version gap — CyberGym needs *none* of that: we build straight on the ARVO image.
The fuzzer V2 then fuzzes is exactly the one ARVO validated reproduces the crash.

The matching ``n132/arvo:<id>-fix`` image (patched source) is what a grader uses
for the crash / no-crash oracle at PoV time.

Contrast with bench.py: no clone, no apt, no compat shims — the "build" is just
re-running the image's own recipe (helper.py builds ``FROM`` the ARVO image, with
``mount_src=False`` so nothing shadows the baked source).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# error.txt reproduces the crash under a specific harness, e.g.
#   /out/coder_MNG_fuzzer: Running 1 inputs 1 time(s) each.
_FUZZER_RE = re.compile(r"/out/(\S+?):\s+Running\b")


def arvo_vul_image(arvo_id: str) -> str:
    """Prebuilt image with the *vulnerable* source (the one that crashes)."""
    return f"n132/arvo:{arvo_id}-vul"


def arvo_fix_image(arvo_id: str) -> str:
    """Prebuilt image with the *patched* source (for the no-crash side of grading)."""
    return f"n132/arvo:{arvo_id}-fix"


@dataclass
class CyberGymTask:
    task_id: str          # e.g. "arvo:10400"
    arvo_id: str          # e.g. "10400"
    kind: str             # "arvo" | "oss-fuzz"
    project: str          # OSS-Fuzz project name, e.g. "graphicsmagick"
    language: str
    description: str      # the vulnerability description (the agent's hint)
    fuzzer: str           # target harness binary from error.txt, e.g. coder_MNG_fuzzer
    data_dir: Optional[Path] = None

    @property
    def vul_image(self) -> str:
        return arvo_vul_image(self.arvo_id)

    @property
    def fix_image(self) -> str:
        return arvo_fix_image(self.arvo_id)


def _fuzzer_from_error(error_txt: str) -> str:
    m = _FUZZER_RE.search(error_txt)
    return m.group(1) if m else ""


def load_task(task_id: str, cybergym_data: str | Path) -> CyberGymTask:
    """Build a :class:`CyberGymTask` from tasks.json + the task's error.txt."""
    data = Path(cybergym_data)
    raw = json.loads((data / "tasks.json").read_text())
    tasks = raw if isinstance(raw, list) else list(raw.values())
    by_id = {t["task_id"]: t for t in tasks}
    if task_id not in by_id:
        raise KeyError(f"{task_id} not in {data/'tasks.json'}")
    meta = by_id[task_id]

    kind, arvo_id = task_id.split(":", 1)
    task_dir = data / "data" / kind / arvo_id
    error_txt = ""
    err_file = task_dir / "error.txt"
    if err_file.is_file():
        error_txt = err_file.read_text(errors="replace")

    return CyberGymTask(
        task_id=task_id,
        arvo_id=arvo_id,
        kind=kind,
        project=meta["project_name"],
        language=str(meta.get("project_language", "c++")),
        description=str(meta.get("vulnerability_description", "")),
        fuzzer=_fuzzer_from_error(error_txt),
        data_dir=task_dir,
    )


def _render_project_files(task: CyberGymTask) -> tuple[str, str]:
    """The (Dockerfile, build.sh) for the OSS-Fuzz project skeleton.

    Dockerfile builds FROM the ARVO image and stashes that image's own build
    recipe + WORKDIR; build.sh (which helper.py copies over ``$SRC/build.sh``)
    then re-runs the stashed recipe from the stashed directory. This is fully
    generic — it works for any ARVO task regardless of the project's source-dir
    name or internal build-script path, because it defers to the image's recipe.
    """
    dockerfile = (
        f"FROM {task.vul_image}\n"
        # Preserve the image's own recipe + WORKDIR before helper.py overwrites
        # $SRC/build.sh with ours.
        "RUN cp -n \"$SRC/build.sh\" \"$SRC/.arvo_build.sh\" 2>/dev/null || true; "
        "pwd > \"$SRC/.arvo_workdir\"\n"
        # ARVO images override CMD to `sleep infinity` (for interactive repro), so
        # helper.py's `docker run <image>` would just sleep and never build.
        # Restore base-builder's default so the build actually runs.
        'CMD ["compile"]\n'
    )
    build_sh = (
        "#!/bin/bash -eu\n"
        "# ARVO's project image carries the correct OSS-Fuzz build recipe; re-run\n"
        "# it from the directory it expects (both stashed at image-build time).\n"
        'cd "$(cat "$SRC/.arvo_workdir" 2>/dev/null || echo "$SRC")"\n'
        'exec bash "$SRC/.arvo_build.sh"\n'
    )
    return dockerfile, build_sh


def build_cybergym_workspace(
    task: CyberGymTask,
    dest: str | Path,
    oss_fuzz_dir: str | Path,
    overwrite: bool = False,
) -> Path:
    """Materialize a V2 workspace for an ARVO task under ``dest``.

    Layout mirrors the bench importer's so the shared builder/fuzz pipeline is
    reused unchanged::

        dest/
          fuzz-tooling/infra/helper.py            (OSS-Fuzz infra)
          fuzz-tooling/projects/<project>/{Dockerfile, build.sh, project.yaml}
          repo/                                   (empty; source is baked in the image)

    Build it with a BuildJob whose ``mount_src=False``.
    """
    import shutil

    dest = Path(dest)
    if dest.exists() and overwrite:
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)

    infra_src = Path(oss_fuzz_dir) / "infra"
    if not (infra_src / "helper.py").is_file():
        raise FileNotFoundError(f"helper.py not found under {infra_src}")
    ft = dest / "fuzz-tooling"
    (ft).mkdir(exist_ok=True)
    if not (ft / "infra").exists():
        shutil.copytree(infra_src, ft / "infra")

    proj_dir = ft / "projects" / task.project
    proj_dir.mkdir(parents=True, exist_ok=True)
    dockerfile, build_sh = _render_project_files(task)
    (proj_dir / "Dockerfile").write_text(dockerfile)
    (proj_dir / "build.sh").write_text(build_sh)
    (proj_dir / "build.sh").chmod(0o755)
    (proj_dir / "project.yaml").write_text(
        f"language: {task.language}\n"
        "main_repo: ''\n"
        f"# CyberGym/ARVO task {task.task_id}\n"
    )
    (dest / "repo").mkdir(exist_ok=True)  # placeholder; source lives in the image
    return dest
