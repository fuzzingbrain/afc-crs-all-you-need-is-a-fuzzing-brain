# SPDX-License-Identifier: Apache-2.0
"""Apply LLM-generated patches to a project source tree.

Two entry points:

* :func:`replace_function` — given ``file_path`` + ``func_name`` +
  replacement body, locate the function via
  :func:`common.code.fundef.extract_function_using_fundef`, pick the
  best variant via
  :func:`common.code.similarity.calculate_function_similarity` when
  multiple matches exist, and rewrite the file in place.
* :func:`apply_patch` — iterate a ``{function_name: new_code}`` dict,
  call :func:`replace_function` for each, and then rebuild the
  project's docker image so the patched binary is ready for
  verification.

``apply_patch`` takes ``function_metadata`` and (optionally)
``relevant_source_files`` as parameters instead of the legacy global
``GLOBAL_FUNCTION_METADATA`` / ``GLOBAL_RELEVANT_SOURCE_FILES``. It
also uses :func:`common.fuzzing.image.resolve_project_image` so the
same AIXCC / OSS-Fuzz fallback is applied as everywhere else in
``common/``.
"""
from __future__ import annotations

import logging
import os
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from common.code.fundef import extract_function_using_fundef
from common.code.similarity import calculate_function_similarity
from common.fuzzing.image import resolve_project_image
from common.patch.workspace import ensure_patch_workspace_git

logger = logging.getLogger(__name__)

_C_EXTENSION = ".c"
_JAVA_EXTENSION = ".java"
_FUZZING_LANGUAGE_C = "c++"
_FUZZING_LANGUAGE_JAVA = "jvm"


def _parse_variant_index(func_name: str) -> Tuple[str, bool, int]:
    """Split ``func_name_N`` into ``(base, is_variant, index)``."""
    if "_" not in func_name:
        return func_name, False, 0
    parts = func_name.split("_")
    if not parts[-1].isdigit():
        return func_name, False, 0
    return "_".join(parts[:-1]), True, int(parts[-1])


def _pick_best_variant(
    metadata_list: List[Dict[str, Any]],
    new_func_code: str,
    is_variant: bool,
    variant_index: int,
) -> Dict[str, Any]:
    """Pick the right entry from a multi-match ``fundef`` result."""
    if is_variant and 0 < variant_index <= len(metadata_list):
        logger.debug("Using explicit variant %d", variant_index)
        return metadata_list[variant_index - 1]

    best_index = 0
    best_score = -1.0
    for i, metadata in enumerate(metadata_list):
        original_code = metadata["content"]
        sim = calculate_function_similarity(new_func_code, original_code)
        logger.debug(
            "Variant %d weighted=%.4f sig=%.4f params=%.4f content=%.4f",
            i + 1,
            sim["weighted_similarity"],
            sim["signature_similarity"],
            sim["param_count_similarity"],
            sim["content_similarity"],
        )
        if sim["weighted_similarity"] > best_score:
            best_score = sim["weighted_similarity"]
            best_index = i
    logger.debug("Best variant is %d (score %.4f)", best_index + 1, best_score)
    return metadata_list[best_index]


def replace_function(
    project_src_dir: str,  # noqa: ARG001 — kept for signature parity
    file_path: str,
    func_name: str,
    new_func_code: str,
) -> bool:
    """Rewrite the definition of ``func_name`` in ``file_path``.

    Args:
        project_src_dir: Project root (reserved for future use; kept
            in the signature so callers with a legacy shape work
            without change).
        file_path: Path to the source file to edit in place.
        func_name: Function name; suffixed variants (``foo_2``) are
            handled.
        new_func_code: Replacement body (trailing newline added if
            missing).

    Returns:
        True on successful rewrite.
    """
    base_func_name, is_variant, variant_index = _parse_variant_index(func_name)

    metadata_list = extract_function_using_fundef(file_path, base_func_name)
    if not metadata_list:
        logger.warning("Function '%s' not found in %s", base_func_name, file_path)
        return False

    if not isinstance(metadata_list, list):
        metadata_list = [metadata_list]

    if len(metadata_list) == 1:
        function_info = metadata_list[0]
        logger.debug("Only one match for '%s'", base_func_name)
    else:
        function_info = _pick_best_variant(metadata_list, new_func_code, is_variant, variant_index)

    try:
        with open(file_path, "r") as fh:
            lines = fh.readlines()
    except OSError as exc:
        logger.error("Error reading %s: %s", file_path, exc)
        return False

    start_line = function_info["start_line"] - 1
    end_line = function_info["end_line"]

    replacement = new_func_code if new_func_code.endswith("\n") else new_func_code + "\n"
    updated_lines = lines[:start_line] + [replacement] + lines[end_line:]

    try:
        with open(file_path, "w") as fh:
            fh.writelines(updated_lines)
    except OSError as exc:
        logger.error("Error writing %s: %s", file_path, exc)
        return False

    logger.info("Replaced function '%s' in %s", func_name, file_path)
    return True


def _resolve_file_for_function(
    func_name: str,
    function_metadata: Dict[str, Any],
    project_src_dir: str,
) -> Optional[str]:
    """Return the absolute file path to edit for ``func_name``, if known."""
    if func_name in function_metadata:
        return os.path.join(project_src_dir, function_metadata[func_name]["file_path"])

    variants = [k for k in function_metadata if k.startswith(func_name + "_")]
    if variants:
        return os.path.join(project_src_dir, function_metadata[variants[0]]["file_path"])

    return None


def _walk_for_function(
    func_name: str,
    project_src_dir: str,
    extension: str,
    function_metadata: Dict[str, Any],
) -> Optional[str]:
    """Last-resort: walk the project tree for any file that defines ``func_name``."""
    for root, _, files in os.walk(project_src_dir):
        for name in files:
            if not name.endswith(extension) or name.startswith("Crash_"):
                continue
            file_path = os.path.join(root, name)
            rel_path = os.path.relpath(file_path, project_src_dir)
            metadata_list = extract_function_using_fundef(file_path, func_name)
            if not metadata_list:
                continue
            if isinstance(metadata_list, list):
                for i, metadata in enumerate(metadata_list):
                    unique_key = f"{func_name}_{i + 1}"
                    metadata["file_path"] = rel_path
                    function_metadata[unique_key] = metadata
                return None
            metadata_list["file_path"] = rel_path
            function_metadata[func_name] = metadata_list
            return file_path
    return None


def _rebuild_docker_image(
    project_dir: str,
    project_src_dir: str,
    project_name: str,
    sanitizer: str,
    language: str,
    patch_id: str,
    unharnessed: bool,
) -> Tuple[bool, str, str]:
    """Run the OSS-Fuzz build image to produce a patched binary."""
    docker_image = resolve_project_image(project_name)
    if not docker_image:
        return False, "", f"Failed to find docker image for {project_name}"

    project_sanitizer_name = f"{project_name}-{sanitizer}-{patch_id}"

    out_dir = _safe_makedirs(
        project_dir,
        os.path.join("fuzz-tooling", "build", "out", project_sanitizer_name),
        fallback_prefix="temp_out_",
    )
    work_dir = _safe_makedirs(
        project_dir,
        os.path.join("fuzz-tooling", "build", "work", project_sanitizer_name),
        fallback_prefix="temp_work_",
    )

    fuzz_language = _FUZZING_LANGUAGE_C if language.startswith("c") else _FUZZING_LANGUAGE_JAVA

    cmd_args = [
        "docker", "run",
        "--privileged",
        "--shm-size=8g",
        "--platform", "linux/amd64",
        "--rm",
        "-e", "FUZZING_ENGINE=libfuzzer",
        "-e", f"SANITIZER={sanitizer}",
        "-e", "ARCHITECTURE=x86_64",
        "-e", f"PROJECT_NAME={project_name}",
        "-e", "HELPER=True",
        "-e", f"FUZZING_LANGUAGE={fuzz_language}",
        "-v", f"{project_src_dir}:/src/{project_name}",
        "-v", f"{out_dir}:/out",
        "-v", f"{work_dir}:/work",
        docker_image,
    ]

    if unharnessed:
        task_dir_build_sh = os.path.join(project_dir, f"build-{sanitizer}.sh")
        if os.path.exists(task_dir_build_sh):
            logger.info(
                "Adding build.sh volume mount for UNHARNESSED task: %s", task_dir_build_sh
            )
            cmd_args = (
                cmd_args[:-1]
                + ["-v", f"{task_dir_build_sh}:/src/build.sh"]
                + cmd_args[-1:]
            )
        else:
            logger.warning("UNHARNESSED task but no %s found", task_dir_build_sh)

    logger.info("Running build: %s", " ".join(cmd_args))
    build_start = time.time()
    try:
        result = subprocess.run(
            cmd_args,
            shell=False,
            env=os.environ.copy(),
            cwd=project_dir,
            capture_output=True,
            text=True,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return False, "", f"{sanitizer} build error: {exc}"

    logger.info(
        "Build finished in %.2fs (%.2fm)",
        time.time() - build_start,
        (time.time() - build_start) / 60,
    )

    if result.returncode != 0:
        logger.error("Build failed for %s: %s", sanitizer, result.stderr[:500])
        return False, "", f"\n{sanitizer} build error: {result.stderr}"

    return True, f"\n{sanitizer} build output: {result.stdout}", ""


def _safe_makedirs(project_dir: str, relative: str, fallback_prefix: str) -> str:
    """Create ``project_dir/relative`` with a project-dir-scoped fallback on PermissionError."""
    target = os.path.join(project_dir, relative)
    try:
        os.makedirs(target, exist_ok=True)
        return target
    except PermissionError:
        fallback = os.path.join(project_dir, fallback_prefix + os.path.basename(relative))
        os.makedirs(fallback, exist_ok=True)
        logger.warning("Permission denied on %s; falling back to %s", target, fallback)
        return fallback


def apply_patch(
    patch_code_dict: Dict[str, str],
    project_dir: str,
    project_src_dir: str,
    language: str,
    pov_metadata: Dict[str, Any],
    patch_id: str,
    function_metadata: Dict[str, Any],
    *,
    unharnessed: bool = False,
) -> Tuple[bool, str, str]:
    """Apply every entry in ``patch_code_dict`` and rebuild the project image.

    Args:
        patch_code_dict: Mapping of function name to replacement body.
        project_dir: Project root on host.
        project_src_dir: Patched source tree under ``project_dir``.
        language: ``"c"`` / ``"java"``.
        pov_metadata: Carries ``project_name`` and ``sanitizer``.
        patch_id: Unique patch id (used to namespace the rebuild dirs).
        function_metadata: Pre-computed metadata from
            :func:`common.patch.metadata.find_function_metadata`. Updated
            in place when extra entries are discovered.
        unharnessed: Whether this task runs without a fuzzer harness,
            in which case the caller's ``build-{sanitizer}.sh`` is
            mounted into the build container.

    Returns:
        ``(build_success, build_output, build_error)``.
    """
    ensure_patch_workspace_git(project_src_dir)
    logger.info("Applying %d patches", len(patch_code_dict))

    extension = _C_EXTENSION if language.startswith("c") else _JAVA_EXTENSION

    for func_name, new_code in patch_code_dict.items():
        file_path = _resolve_file_for_function(func_name, function_metadata, project_src_dir)
        if file_path is not None:
            logger.debug("Resolved %s via metadata -> %s", func_name, file_path)
            if replace_function(project_src_dir, file_path, func_name, new_code):
                continue
            logger.warning("Replacement failed for '%s' in %s", func_name, file_path)

        logger.debug("Function %s not in metadata; scanning project", func_name)
        walked = _walk_for_function(func_name, project_src_dir, extension, function_metadata)
        if walked is not None:
            if replace_function(project_src_dir, walked, func_name, new_code):
                continue
            logger.warning("Replacement failed for '%s' in %s", func_name, walked)

        logger.warning("Function '%s' not found; skipping", func_name)
        if len(patch_code_dict) == 1:
            return False, "", f"Function '{func_name}' not found in any source file"

    return _rebuild_docker_image(
        project_dir=project_dir,
        project_src_dir=project_src_dir,
        project_name=pov_metadata["project_name"],
        sanitizer=pov_metadata["sanitizer"],
        language=language,
        patch_id=patch_id,
        unharnessed=unharnessed,
    )
