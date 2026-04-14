"""libFuzzer execution with streaming output, coverage parsing, and crash detection.

This module runs a fuzzer binary inside the project's OSS-Fuzz docker image,
collects its output with a watchdog timeout, strips libFuzzer progress noise,
condenses the ``-print_coverage=1`` section, and on crash delegates to
``common.crash.extract.extract_and_save_crash_input`` to grab a reproducing
input.

It also exposes :func:`run_fuzzer_with_input` for the "run the fuzzer on
one pre-generated blob" path used by POV iteration loops.
"""
from __future__ import annotations

import logging
import os
import select
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import List, Optional, Tuple

from common.crash.extract import extract_and_save_crash_input
from common.fuzzing.image import resolve_project_image

logger = logging.getLogger(__name__)

# Lines in the fuzzer output that indicate a real crash (vs. a benign warning
# or clean exit). Kept as module-level tuple for cheap iteration.
_CRASH_INDICATORS: Tuple[str, ...] = (
    "ERROR: AddressSanitizer:",
    "ERROR: MemorySanitizer:",
    "WARNING: MemorySanitizer:",
    "ERROR: ThreadSanitizer:",
    "ERROR: UndefinedBehaviorSanitizer:",
    "SEGV on unknown address",
    "Segmentation fault",
    "runtime error:",
    "AddressSanitizer: heap-buffer-overflow",
    "AddressSanitizer: heap-use-after-free",
    "UndefinedBehaviorSanitizer: undefined-behavior",
    "AddressSanitizer:DEADLYSIGNAL",
    "Java Exception: com.code_intelligence.jazzer",
    "ERROR: HWAddressSanitizer:",
    "WARNING: ThreadSanitizer:",
    "libfuzzer exit=1",
)

_DEFAULT_MAX_LINE_LENGTH = 200
_DEFAULT_FUZZER_TIMEOUT_SECONDS = 55
_DEFAULT_SUBPROCESS_TIMEOUT_SECONDS = 60


def _build_docker_command(
    *,
    docker_image: str,
    fuzzer_name: str,
    project_name: str,
    sanitizer: str,
    sanitizer_project_dir: str,
    out_dir_x: str,
    work_dir: str,
    seed_corpus_dir: str,
    fuzzer_timeout: int,
) -> List[str]:
    """Build the ``docker run`` argv for invoking the fuzzer under libFuzzer."""
    corpus_container_path = "/corpus"
    return [
        "docker", "run", "--rm",
        "--platform", "linux/amd64",
        "-e", "FUZZING_ENGINE=libfuzzer",
        "-e", f"SANITIZER={sanitizer}",
        "-e", "ARCHITECTURE=x86_64",
        "-e", f"PROJECT_NAME={project_name}",
        "-v", f"{sanitizer_project_dir}:/src/{project_name}",
        "-v", f"{out_dir_x}:/out",
        "-v", f"{work_dir}:/work",
        "-v", f"{seed_corpus_dir}:{corpus_container_path}",
        docker_image,
        f"/out/{fuzzer_name}",
        "-print_coverage=1",
        f"-max_total_time={fuzzer_timeout}",
        "-max_len=262144",
        "-verbosity=0",
        "-detect_leaks=0",
        "-artifact_prefix=/out/crashes/",
        corpus_container_path,
    ]


def _run_with_watchdog(
    cmd: List[str],
    timeout: int,
) -> Tuple[str, str, Optional[int], bool]:
    """Run ``cmd`` with a streaming reader and a wall-clock watchdog.

    The fuzzer is invoked via a ``Popen`` so we can start consuming stdout
    / stderr before it exits. Some libFuzzer error lines would otherwise
    block us waiting for ``communicate()`` to return.

    Returns:
        ``(stdout_text, stderr_text, returncode, timed_out)``.
    """
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="backslashreplace",
        text=True,
        bufsize=1,
    )

    stdout_data: List[str] = []
    stderr_data: List[str] = []
    start = time.time()
    timed_out = False

    while process.poll() is None:
        if time.time() - start > timeout:
            logger.debug("Watchdog timeout reached; terminating %s", cmd[0])
            process.terminate()
            timed_out = True
            time.sleep(10)
            if process.poll() is None:
                process.kill()
            break

        readable, _, _ = select.select([process.stdout, process.stderr], [], [], 0.1)
        for stream in readable:
            line = stream.readline()
            if not line:
                continue
            if line.startswith("Error: in prepare") or "unknown option" in line:
                continue
            if stream is process.stdout:
                stdout_data.append(line)
            else:
                stderr_data.append(line)

    # Drain anything left after exit.
    rest_stdout, rest_stderr = process.communicate()
    if rest_stdout:
        stdout_data.append(rest_stdout)
    if rest_stderr:
        stderr_data.append(rest_stderr)

    return "".join(stdout_data), "".join(stderr_data), process.returncode, timed_out


def _filter_libfuzzer_noise(
    combined_output: str,
    max_line_length: int = _DEFAULT_MAX_LINE_LENGTH,
) -> str:
    """Drop progress spam and sanitiser warnings from a libFuzzer transcript.

    Progress lines such as ``#42 REDUCE cov:`` are discarded except the ones
    that contain ``NEW_FUNC`` (new function discoveries). Lines longer than
    ``max_line_length`` are truncated with a marker.
    """
    output_lines: List[str] = []
    for line in combined_output.split("\n"):
        stripped = line.strip()
        if stripped.startswith("#") and any(
            marker in line for marker in ("REDUCE cov:", "INITED cov:", "NEW    cov:")
        ):
            if "NEW_FUNC" in line:
                output_lines.append(line)
            continue

        if len(line) > max_line_length:
            output_lines.append(
                line[:max_line_length]
                + f" ... (truncated, full length: {len(line)})"
            )
            continue

        if line.lstrip().startswith("WARNING:"):
            continue

        output_lines.append(line)

    return "\n".join(output_lines)


def _split_coverage(filtered_output: str) -> Tuple[str, str]:
    """Split a filtered transcript on the ``COVERAGE:`` marker.

    Returns ``(fuzzer_section, coverage_section)``. When no marker is
    present, the whole input becomes the fuzzer section and coverage is
    the empty string.
    """
    if "COVERAGE:" not in filtered_output:
        return filtered_output, ""

    head, tail = filtered_output.split("COVERAGE:", 1)
    return head.strip(), tail.strip()


def _condense_coverage(coverage_section: str) -> str:
    """Reduce the libFuzzer coverage dump to a bounded summary.

    Keeps every ``COVERED_FUNC`` line, up to 3 unique ``UNCOVERED_PC`` lines
    per current function, and appends an uncovered-function summary (first
    10 followed by a count of the remainder).
    """
    if not coverage_section:
        return ""

    condensed: List[str] = []
    uncovered_funcs: List[str] = []
    current_func: Optional[str] = None
    seen_uncovered_pcs: set = set()

    for line in coverage_section.split("\n"):
        if line.startswith("COVERED_FUNC:") and "/src/" in line:
            current_func = line
            condensed.append(line)
            continue

        if line.startswith("UNCOVERED_FUNC:") and "/src/" in line:
            uncovered_funcs.append(line)
            continue

        if line.startswith("  UNCOVERED_PC:"):
            if ":0" in line or not line.startswith("  UNCOVERED_PC: /src/"):
                continue
            pcs_so_far = sum(1 for l in condensed if l.startswith("  UNCOVERED_PC:"))
            if line not in seen_uncovered_pcs and current_func and pcs_so_far < 3:
                seen_uncovered_pcs.add(line)
                condensed.append(line)

    condensed.append(f"\nUNCOVERED FUNCTIONS SUMMARY: {len(uncovered_funcs)} functions")
    condensed.extend(uncovered_funcs[:10])
    if len(uncovered_funcs) > 10:
        condensed.append(f"... and {len(uncovered_funcs) - 10} more uncovered functions")

    return "COVERAGE:\n" + "\n".join(condensed)


def _looks_like_crash(combined_output: str) -> bool:
    """True if any known sanitiser / libFuzzer crash marker is in the output."""
    return any(indicator in combined_output for indicator in _CRASH_INDICATORS)


def _log_excerpt(
    text: str,
    max_line_length: int = _DEFAULT_MAX_LINE_LENGTH,
    head_lines: int = 200,
    tail_lines: int = 200,
) -> None:
    """Log the first and last N lines of a long transcript at debug level."""
    lines = text.splitlines()
    if not lines:
        return

    def _truncate(line: str) -> str:
        if len(line) <= max_line_length:
            return line
        return line[:max_line_length] + f" ... (truncated, full length: {len(line)})"

    head = [_truncate(l) for l in lines[:head_lines]]
    logger.debug("Fuzzer output START (first %d lines):\n%s", head_lines, "\n".join(head))

    if len(lines) > head_lines:
        skipped = max(0, len(lines) - head_lines - tail_lines)
        if skipped:
            logger.debug("\n... (%d lines skipped) ...\n", skipped)
        tail = [_truncate(l) for l in lines[-tail_lines:]]
        logger.debug("Fuzzer output END (last %d lines):\n%s", tail_lines, "\n".join(tail))


def run_fuzzer_with_coverage(
    fuzzer_path: str,
    project_dir: str,
    focus: str,
    sanitizer: str,
    project_name: str,
    seed_corpus_dir: str,
    pov_phase: int,
) -> Tuple[bool, str, str, Optional[bytes]]:
    """Run a libFuzzer harness against a seed corpus and collect coverage.

    Args:
        fuzzer_path: Absolute path to the fuzzer binary on the host.
        project_dir: Project workspace root on the host.
        focus: Project focus directory (mounted as ``/src/{project_name}``).
        sanitizer: Sanitiser label (``address`` / ``memory`` / ``undefined``).
        project_name: OSS-Fuzz project name, used to resolve the image.
        seed_corpus_dir: Host directory mounted as ``/corpus``.
        pov_phase: Phase index; used to namespace the per-run ``out_dir_x``.

    Returns:
        ``(crash_detected, fuzzer_output, coverage_output, crash_input)``.
        On error the tuple is ``(False, error_message, "", None)``.
    """
    try:
        logger.debug("Running fuzzer %s against %s", fuzzer_path, seed_corpus_dir)

        fuzzer_name = os.path.basename(fuzzer_path)
        sanitizer_project_dir = os.path.join(project_dir, focus)
        out_dir = os.path.dirname(fuzzer_path)
        out_dir_x = os.path.join(out_dir, f"ap{pov_phase}")
        work_dir = os.path.join(
            project_dir, "fuzz-tooling", "build", "work", f"{project_name}-{sanitizer}"
        )
        crash_dir = os.path.join(out_dir_x, "crashes")
        os.makedirs(crash_dir, exist_ok=True)

        docker_image = resolve_project_image(project_name)
        if not docker_image:
            logger.error("Failed to find docker image for %s", project_name)
            return False, "", "", None
        logger.debug("Using docker image %s", docker_image)

        docker_cmd = _build_docker_command(
            docker_image=docker_image,
            fuzzer_name=fuzzer_name,
            project_name=project_name,
            sanitizer=sanitizer,
            sanitizer_project_dir=sanitizer_project_dir,
            out_dir_x=out_dir_x,
            work_dir=work_dir,
            seed_corpus_dir=seed_corpus_dir,
            fuzzer_timeout=_DEFAULT_FUZZER_TIMEOUT_SECONDS,
        )
        logger.debug("Running docker command: %s", " ".join(docker_cmd))

        stdout_text, stderr_text, returncode, timed_out = _run_with_watchdog(
            docker_cmd, timeout=_DEFAULT_SUBPROCESS_TIMEOUT_SECONDS
        )
        combined_output = stdout_text + "\n" + stderr_text

        filtered = _filter_libfuzzer_noise(combined_output)
        fuzzer_output, coverage_section = _split_coverage(filtered)
        coverage_output = _condense_coverage(coverage_section)
        _log_excerpt(fuzzer_output)

        logger.debug("Fuzzer exited with returncode: %s", returncode)

        # A runtime error in libFuzzer trumps the watchdog (we have real output).
        if "runtime error:" in combined_output:
            timed_out = False

        crash_detected = False
        crash_input: Optional[bytes] = None

        java_nocdef = (
            returncode == 77
            and "Java Exception: java.lang.NoClassDefFoundError:" in combined_output
        )

        if java_nocdef:
            logger.debug("Fuzzer exited with %s but only NoClassDefFoundError", returncode)
        elif (returncode not in (0, None) and not timed_out) or "ABORTING" in combined_output:
            if _looks_like_crash(combined_output):
                logger.info(
                    "Fuzzer crashed with exit code %s — candidate vulnerability",
                    returncode,
                )
                crash_detected = True
                crash_input, _ = extract_and_save_crash_input(
                    crash_dir,
                    fuzzer_name,
                    out_dir_x,
                    project_name,
                    sanitizer,
                    project_dir,
                    sanitizer_project_dir,
                )
            else:
                logger.debug(
                    "Fuzzer exited with %s but no crash indicators", returncode
                )
        elif timed_out:
            logger.debug("Fuzzer timed out; returning partial output")
            fuzzer_output = "Execution timed out, partial output:\n" + fuzzer_output
        else:
            logger.debug("Fuzzer ran to completion without crashing")

        return crash_detected, fuzzer_output, coverage_output, crash_input

    except Exception as exc:  # noqa: BLE001 — top-level runner barrier
        logger.exception("Error running fuzzer: %s", exc)
        return False, str(exc), "", None


# ---------------------------------------------------------------------------
# run_fuzzer_with_input: single-blob reproduction run
# ---------------------------------------------------------------------------


_INPUT_CRASH_INDICATORS: Tuple[str, ...] = _CRASH_INDICATORS + ("Assertion failed:",)
_INPUT_FUZZER_WATCHDOG_SECONDS = 60
_TIMEOUT_SENTINEL = "detect_timeout_crash"


def _build_input_docker_command(
    *,
    docker_image: str,
    fuzzer_name: str,
    project_name: str,
    sanitizer: str,
    sanitizer_project_dir: str,
    out_dir_x: str,
    work_dir: str,
    container_blob_path: str,
) -> List[str]:
    """Build the docker command that runs a single crash input."""
    return [
        "docker", "run", "--rm",
        "--platform", "linux/amd64",
        "-e", "FUZZING_ENGINE=libfuzzer",
        "-e", f"SANITIZER={sanitizer}",
        "-e", "ARCHITECTURE=x86_64",
        "-e", f"PROJECT_NAME={project_name}",
        "-v", f"{sanitizer_project_dir}:/src/{project_name}",
        "-v", f"{out_dir_x}:/out",
        "-v", f"{work_dir}:/work",
        docker_image,
        f"/out/{fuzzer_name}",
        "-timeout=30",
        "-timeout_exitcode=99",
        container_blob_path,
    ]


def _timeout_crash_enabled(project_dir: str) -> bool:
    """Return True if timeouts should count as crashes for this project."""
    if os.environ.get("DETECT_TIMEOUT_CRASH") == "1":
        return True
    return (Path(project_dir) / _TIMEOUT_SENTINEL).exists()


def run_fuzzer_with_input(
    fuzzer_path: str,
    project_dir: str,
    focus: str,
    sanitizer: str,
    project_name: str,
    blob_path: str,
    pov_phase: int = 0,
) -> Tuple[bool, str]:
    """Run ``fuzzer_path`` against a single blob inside the project container.

    The blob is copied into a unique per-run file under ``out_dir_x``
    so that parallel invocations don't stomp on each other. Returns
    ``(crash_detected, combined_output)``.

    ``project_name`` / ``sanitizer`` must be supplied by the caller;
    legacy code derived them from the ``fuzz-tooling/build/out/{project}-{san}``
    path component, which is brittle when projects contain hyphens.
    ``common.config.StrategyConfig`` already exposes both values so
    strategies should pass them explicitly.

    Args:
        fuzzer_path: Path to the fuzzer binary on the host.
        project_dir: Project workspace root on the host.
        focus: Project focus directory (mounted as ``/src/{project_name}``).
        sanitizer: Sanitiser label.
        project_name: OSS-Fuzz project name (also used to locate the
            docker image).
        blob_path: Path to the candidate crash blob on the host.
        pov_phase: Phase index used to namespace ``out_dir_x``.

    Returns:
        ``(crash_detected, combined_output)``. ``combined_output`` is
        the stderr+stdout transcript on success, or an error message
        when the runner itself failed.
    """
    try:
        logger.debug("Running %s with %s", fuzzer_path, blob_path)

        fuzzer_name = os.path.basename(fuzzer_path)
        sanitizer_project_dir = os.path.join(project_dir, focus)
        out_dir = os.path.dirname(fuzzer_path)
        out_dir_x = os.path.join(out_dir, f"ap{pov_phase}")
        work_dir = os.path.join(
            project_dir, "fuzz-tooling", "build", "work", f"{project_name}-{sanitizer}"
        )
        os.makedirs(out_dir_x, exist_ok=True)

        unique_blob_name = f"x_{uuid.uuid4().hex[:8]}.bin"
        staged_blob_path = os.path.join(out_dir_x, unique_blob_name)
        try:
            shutil.copy(blob_path, staged_blob_path)
            logger.debug("Copied blob to %s", staged_blob_path)
        except OSError as exc:
            logger.error("Failed to copy blob %s -> %s: %s", blob_path, staged_blob_path, exc)
            return False, f"Blob staging failed: {exc}"

        docker_image = resolve_project_image(project_name)
        if not docker_image:
            logger.error("Failed to find docker image for %s", project_name)
            return False, f"Failed to find docker image for {project_name}"
        logger.debug("Using docker image %s", docker_image)

        docker_cmd = _build_input_docker_command(
            docker_image=docker_image,
            fuzzer_name=fuzzer_name,
            project_name=project_name,
            sanitizer=sanitizer,
            sanitizer_project_dir=sanitizer_project_dir,
            out_dir_x=out_dir_x,
            work_dir=work_dir,
            container_blob_path=f"/out/{unique_blob_name}",
        )
        logger.debug("Running docker command: %s", " ".join(docker_cmd))

        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=_INPUT_FUZZER_WATCHDOG_SECONDS,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Fuzzer execution timed out after %ds", _INPUT_FUZZER_WATCHDOG_SECONDS)
            return False, "Execution timed out"

        combined_output = (result.stderr or "") + "\n" + (result.stdout or "")

        # Clean exit, no abort -> no crash.
        if result.returncode == 0 and "ABORTING" not in combined_output:
            logger.debug("Fuzzer ran successfully without crashing")
            return False, combined_output

        # Java NoClassDefFoundError is noisy but not a real crash.
        if (
            result.returncode == 77
            and "Java Exception: java.lang.NoClassDefFoundError:" in combined_output
        ):
            logger.debug("Fuzzer exited 77 with NoClassDefFoundError; ignoring")
            return False, combined_output

        if result.stderr:
            logger.debug("Fuzzer stderr: %s", result.stderr)

        crash_indicators = list(_INPUT_CRASH_INDICATORS)
        if _timeout_crash_enabled(project_dir):
            logger.debug("Adding libFuzzer timeout indicators (DETECT_TIMEOUT_CRASH set)")
            crash_indicators.extend(("ERROR: libFuzzer: timeout", "libfuzzer exit=99"))

        if result.returncode != 0 or "ABORTING" in combined_output:
            if any(ind in combined_output for ind in crash_indicators):
                logger.info(
                    "Fuzzer crashed with exit code %s — candidate vulnerability",
                    result.returncode,
                )
                return True, combined_output
            logger.debug(
                "Fuzzer exited %s but no crash indicators", result.returncode
            )
            return False, combined_output

        return False, combined_output

    except Exception as exc:  # noqa: BLE001 — top-level runner barrier
        logger.exception("Error running fuzzer with input: %s", exc)
        return False, str(exc)
