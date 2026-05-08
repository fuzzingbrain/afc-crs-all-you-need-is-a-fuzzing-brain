# SPDX-License-Identifier: Apache-2.0
"""Patch validation helpers.

Two entry points:

* :func:`validate_patch_by_functionality_test` runs a project-supplied
  ``test.sh`` inside the OSS-Fuzz / AIXCC build image to confirm the
  patch preserves functionality.
* :func:`validate_patch_against_all_povs` re-runs every known POV blob
  against the patched binary, reporting whether every crash is now
  blocked. Selects a diverse, bounded subset when too many POVs are
  available.
"""
from __future__ import annotations

import logging
import os
import subprocess
from typing import Any, Dict, List, Tuple

from common.fuzzing.image import resolve_project_image
from common.fuzzing.output import filter_instrumented_lines
from common.fuzzing.runner import run_fuzzer_with_input

logger = logging.getLogger(__name__)

_FUNCTIONALITY_TEST_TIMEOUT_SECONDS = 180
_MAX_POVS_TO_TEST = 5


def validate_patch_by_functionality_test(
    test_sh_path: str,
    project_src_dir: str,
    project_name: str,
) -> Tuple[bool, str]:
    """Run ``project_src_dir/test.sh`` inside the project container.

    Args:
        test_sh_path: Host path to a ``test.sh`` script. When missing,
            the check is considered a pass (nothing to verify).
        project_src_dir: Patched project source directory mounted as
            ``/src/{project_name}``.
        project_name: OSS-Fuzz project name (used for docker image
            lookup and the container mount point).

    Returns:
        ``(passed, combined_output)``.
    """
    logger.info("Functionality test: test.sh=%s src=%s", test_sh_path, project_src_dir)

    if not os.path.exists(test_sh_path):
        logger.info("test.sh not found; skipping functionality test")
        return True, "test.sh not present - skipped"

    docker_image = resolve_project_image(project_name)
    if not docker_image:
        logger.error("Cannot locate docker image for %s", project_name)
        return False, f"Failed to find docker image for {project_name}"

    docker_cmd = [
        "docker", "run", "--rm",
        "--platform", "linux/amd64",
        "-e", "ARCHITECTURE=x86_64",
        "-v", f"{project_src_dir}:/src/{project_name}",
        "-v", f"{test_sh_path}:/src/{project_name}/test.sh",
        docker_image,
        f"/src/{project_name}/test.sh",
    ]
    logger.debug("Functionality test cmd: %s", " ".join(docker_cmd))

    try:
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=_FUNCTIONALITY_TEST_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        logger.warning("Functionality test timed out after %ss", exc.timeout)
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return False, f"{stdout}\n{stderr}"
    except (subprocess.SubprocessError, OSError) as exc:
        logger.error("Error running functionality test: %s", exc)
        return False, str(exc)

    combined_output = f"{result.stdout}\n{result.stderr}"
    if result.returncode == 0:
        logger.info("Functionality test passed")
        return True, combined_output

    logger.warning("Functionality test failed (exit %s)", result.returncode)
    return False, combined_output


def _select_diverse_povs(all_povs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return up to :data:`_MAX_POVS_TO_TEST` POVs spanning distinct blobs."""
    if len(all_povs) <= _MAX_POVS_TO_TEST:
        return all_povs

    logger.info(
        "Found %d POVs; selecting %d for validation",
        len(all_povs),
        _MAX_POVS_TO_TEST,
    )

    by_blob: Dict[str, List[Dict[str, Any]]] = {}
    for pov in all_povs:
        blob_file = pov.get("blob_file")
        if not blob_file:
            continue
        by_blob.setdefault(blob_file, []).append(pov)

    unique_blobs = list(by_blob)
    if len(unique_blobs) > _MAX_POVS_TO_TEST:
        unique_blobs = unique_blobs[:_MAX_POVS_TO_TEST]

    selected = [by_blob[blob][0] for blob in unique_blobs]

    if len(selected) < _MAX_POVS_TO_TEST and len(all_povs) > len(selected):
        remaining = [p for p in all_povs if p not in selected]
        selected.extend(remaining[: _MAX_POVS_TO_TEST - len(selected)])

    return selected


def validate_patch_against_all_povs(
    fuzzer_path: str,
    project_dir: str,
    project_name: str,
    focus: str,
    sanitizer: str,
    all_povs: List[Dict[str, Any]],
    pov_success_dir: str,
    language: str = "c",
    patch_id: str = "",
) -> bool:
    """Return True iff every POV in ``all_povs`` is blocked by the patched binary.

    Args:
        fuzzer_path: Patched fuzzer binary to exercise.
        project_dir: Project workspace root on host.
        project_name: OSS-Fuzz project name.
        focus: Focus directory (mounted as ``/src/{project_name}``).
        sanitizer: Sanitiser in use.
        all_povs: POV metadata dicts (as produced by
            :func:`common.pov.store.load_all_pov_metadata`).
        pov_success_dir: Directory that stores the blob files whose
            paths the POV metadata references.
        language: ``"c"`` / ``"java"`` — kept for signature parity.
        patch_id: Identifier used for logging.

    Returns:
        ``True`` when no selected POV crashes the patched binary.
    """
    del language, patch_id  # reserved for parity with legacy signature
    if not all_povs:
        logger.debug("No POVs available for validation")
        return False

    selected = _select_diverse_povs(all_povs)
    logger.info("Validating patch against %d POVs", len(selected))

    all_blocked = True
    for i, pov in enumerate(selected, start=1):
        blob_file = pov.get("blob_file")
        if not blob_file:
            logger.debug("POV %d has no blob_file, skipping", i)
            continue

        blob_path = os.path.join(pov_success_dir, blob_file)
        if not os.path.exists(blob_path):
            logger.warning("POV %d blob missing at %s, skipping", i, blob_path)
            continue

        crash_detected, fuzzer_output = run_fuzzer_with_input(
            fuzzer_path=fuzzer_path,
            project_dir=project_dir,
            focus=focus,
            sanitizer=sanitizer,
            project_name=project_name,
            blob_path=blob_path,
        )
        fuzzer_output = filter_instrumented_lines(fuzzer_output)
        if crash_detected:
            logger.warning("POV %d still crashes the patched binary", i)
            logger.debug("Fuzzer output: %s", fuzzer_output)
            all_blocked = False
            break
        logger.debug("POV %d blocked", i)

    if all_blocked:
        logger.info("Patch successfully blocks all tested POVs")
    else:
        logger.info("Patch does not block all tested POVs")
    return all_blocked
