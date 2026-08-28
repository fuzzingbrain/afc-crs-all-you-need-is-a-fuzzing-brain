# SPDX-License-Identifier: Apache-2.0
"""Build the workspace the agent works in.

The challenge lives inside its image, split in two by design: ``/challenge``
holds the public material -- ``bench.yaml``, ``description.txt``, the harness
source and the project source -- while ``/opt/fbbench/oracle`` holds the answer
and the instrumented binary, root-owned and 0700.

Copying ``/challenge`` out is therefore safe by construction rather than by our
care: there is no answer in it to leak. That is what lets the agent use ordinary
file tools on real source instead of reaching into the container for every read.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

CHALLENGE_DIR = "/challenge"
ORACLE_DIR = "/opt/fbbench/oracle"


class StagingError(RuntimeError):
    pass


def image_for(alias: str, prefix: str = "docker.io/osanzas/fbbench-challenge-") -> str:
    return f"{prefix}{alias}"


def _docker(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout
    )


def ensure_image(image: str, pull: bool = True) -> None:
    """Make sure the image is present, pulling only when it is not."""
    if _docker("image", "inspect", image, timeout=60).returncode == 0:
        return
    if not pull:
        raise StagingError(f"image not present locally and pull disabled: {image}")
    result = _docker("pull", image, timeout=1800)
    if result.returncode != 0:
        raise StagingError(f"docker pull {image} failed: {result.stderr.strip()[:300]}")


def stage(image: str, workspace: Path) -> dict:
    """Copy the public challenge into `workspace` and describe what landed.

    Returns the parsed bench.yaml fields the runner needs, so the caller does not
    have to start a second container to learn the language or the sanitizer.
    """
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    created = _docker("create", image, timeout=120)
    if created.returncode != 0:
        raise StagingError(f"docker create failed: {created.stderr.strip()[:300]}")
    container = created.stdout.strip()
    try:
        copied = _docker("cp", f"{container}:{CHALLENGE_DIR}/.", str(workspace))
        if copied.returncode != 0:
            raise StagingError(f"docker cp failed: {copied.stderr.strip()[:300]}")
    finally:
        _docker("rm", "-f", container, timeout=120)

    assert_no_answer(workspace)
    return read_spec(workspace)


def assert_no_answer(workspace: Path) -> None:
    """Refuse to hand the agent a workspace that holds the answer.

    The split above makes this true already; the check is here so that a change
    to the image layout fails the run loudly instead of quietly producing a
    score that means nothing. A run that cheats and a run that works look the
    same in the summary.
    """
    strays = []
    for pattern in ("**/oracle.yaml", "**/expected.yaml", "**/binaries/vuln/**"):
        strays += [str(p.relative_to(workspace)) for p in workspace.glob(pattern)]
    if strays:
        raise StagingError(
            "the staged workspace contains answer-side files: "
            f"{strays[:5]} -- refusing to run, since any finding would be worthless"
        )


def read_spec(workspace: Path) -> dict:
    """The public bench.yaml, parsed without a YAML dependency.

    Five flat fields and one nested mapping; a hand-rolled read keeps this
    package installable with nothing but the standard library.
    """
    spec: dict = {"bug_id": "", "project": "", "language": "", "sanitizer": "", "engine": ""}
    path = workspace / "bench.yaml"
    if not path.is_file():
        return spec
    section = None
    for raw in path.read_text().splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indented = raw.startswith((" ", "\t"))
        line = raw.strip()
        if not indented and line.endswith(":"):
            section = line[:-1]
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip("- ").strip(), value.strip().strip("'\"")
        if not indented:
            section = None
            if key in spec:
                spec[key] = value
        elif section == "harness" and key in ("sanitizer", "engine"):
            spec[key] = value
    return spec


def describe(workspace: Path) -> str:
    """A one-line summary of what the agent was given, for the run log."""
    files = sum(1 for p in workspace.rglob("*") if p.is_file())
    harness = sorted(p.name for p in (workspace / "harness").glob("*")) if (
        workspace / "harness"
    ).is_dir() else []
    return f"{files} files staged, harness: {', '.join(harness) or 'none found'}"
