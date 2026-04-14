"""Crash input extraction and verification.

Given a directory of candidate crash files produced by a fuzzer, walks them
newest-first and returns the first one that is confirmed to still reproduce
a crash when re-run inside the project's OSS-Fuzz container.
"""
from __future__ import annotations

import glob
import logging
import os
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from common.fuzzing.image import resolve_project_image

logger = logging.getLogger(__name__)

# Sentinel file that opts a task into treating libFuzzer timeouts as crashes.
DETECT_TIMEOUT_CRASH_SENTINEL = "detect_timeout_crash"

# Substrings in fuzzer output that indicate a real crash was observed.
_CRASH_INDICATORS: Tuple[str, ...] = (
    "==ERROR:",
    "WARNING: MemorySanitizer:",
    "SUMMARY: AddressSanitizer:",
    "Segmentation fault",
    "AddressSanitizer: heap-use-after-free",
    "AddressSanitizer: heap-buffer-overflow",
    "AddressSanitizer: SEGV",
    "UndefinedBehaviorSanitizer: undefined-behavior",
    "runtime error:",
    "AddressSanitizer:DEADLYSIGNAL",
    "Java Exception: com.code_intelligence.jazzer",
    "ERROR: HWAddressSanitizer:",
    "WARNING: ThreadSanitizer:",
    "libfuzzer exit=1",
)


def _reproduces_crash(
    crash_file: str,
    *,
    fuzzer_name: str,
    out_dir_x: str,
    project_name: str,
    sanitizer: str,
    sanitizer_project_dir: str,
) -> bool:
    """Run the fuzzer on one candidate input and check for crash output."""
    logger.debug("Testing crash file: %s", crash_file)

    relative_path = (
        "crashes/" + os.path.basename(crash_file)
        if "crashes/" in crash_file
        else os.path.basename(crash_file)
    )

    docker_image = resolve_project_image(project_name)
    if not docker_image:
        logger.error("No docker image available for %s", project_name)
        return False

    docker_cmd = [
        "docker", "run", "--rm",
        "--platform", "linux/amd64",
        "-e", "FUZZING_ENGINE=libfuzzer",
        "-e", f"SANITIZER={sanitizer}",
        "-e", "ARCHITECTURE=x86_64",
        "-e", f"PROJECT_NAME={project_name}",
        "-v", f"{sanitizer_project_dir}:/src/{project_name}",
        "-v", f"{out_dir_x}:/out",
        "-v", f"{os.path.dirname(crash_file)}:/crashes",
        docker_image,
        f"/out/{fuzzer_name}",
        "-timeout=30",
        "-timeout_exitcode=99",
        f"/out/{relative_path}",
    ]

    try:
        result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        logger.warning("Timeout while testing %s", crash_file)
        return False
    except (subprocess.SubprocessError, OSError) as exc:
        logger.error("Error testing crash file %s: %s", crash_file, exc)
        return False

    combined = result.stdout + result.stderr
    if any(indicator in combined for indicator in _CRASH_INDICATORS):
        logger.debug("Crash confirmed for %s", crash_file)
        return True

    logger.debug("No crash reproduced for %s", crash_file)
    return False


def _collect_crash_files(crash_dir: str, project_dir: str) -> List[str]:
    """Return candidate crash files newest-first, including timeouts if opted in."""
    patterns = [os.path.join(crash_dir, "crash-*")]

    sentinel = Path(project_dir) / DETECT_TIMEOUT_CRASH_SENTINEL
    if os.environ.get("DETECT_TIMEOUT_CRASH") == "1" or sentinel.exists():
        patterns.append(os.path.join(crash_dir, "timeout-*"))

    files: List[str] = []
    for pattern in patterns:
        files.extend(glob.glob(pattern))
    files.sort(key=os.path.getctime, reverse=True)
    return files


def extract_and_save_crash_input(
    crash_dir: str,
    fuzzer_name: str,
    out_dir_x: str,
    project_name: str,
    sanitizer: str,
    project_dir: str,
    sanitizer_project_dir: str,
) -> Tuple[Optional[bytes], Optional[str]]:
    """Return the newest crash file (bytes + path) that still reproduces.

    Walks ``crash_dir`` newest-first. For each candidate, re-runs the fuzzer
    inside the project container on that single input; the first one that
    produces a sanitiser error is returned.

    Args:
        crash_dir: Directory containing ``crash-*`` (and optionally
            ``timeout-*``) files produced by libFuzzer.
        fuzzer_name: Fuzzer binary name, without path.
        out_dir_x: Host path mounted to ``/out`` inside the container.
        project_name: OSS-Fuzz project name (used to locate the docker image).
        sanitizer: Sanitizer label (``address``, ``memory``, ``undefined``...).
        project_dir: Project root on host; used to detect the timeout-crash
            sentinel file.
        sanitizer_project_dir: Host path mounted to ``/src/{project_name}``.

    Returns:
        ``(crash_bytes, crash_path)`` for the first reproducing input, or
        ``(None, None)`` if no candidate reproduces.
    """
    candidates = _collect_crash_files(crash_dir, project_dir)
    if not candidates:
        logger.debug("No crash files found under %s", crash_dir)
        return None, None

    logger.debug("Found %d candidate crash files", len(candidates))

    for crash_file in candidates:
        reproduces = _reproduces_crash(
            crash_file,
            fuzzer_name=fuzzer_name,
            out_dir_x=out_dir_x,
            project_name=project_name,
            sanitizer=sanitizer,
            sanitizer_project_dir=sanitizer_project_dir,
        )
        if not reproduces:
            continue

        try:
            with open(crash_file, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            logger.error("Failed to read crash file %s: %s", crash_file, exc)
            continue

        if data:
            logger.debug("Returning reproducing crash: %s", crash_file)
            return data, crash_file

    logger.debug("No candidate crash files reproduced")
    return None, None
