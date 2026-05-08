# SPDX-License-Identifier: Apache-2.0
"""Run LLM-generated Python snippets.

The CRS asks the LLM to emit a Python script that writes a reproducing
blob to ``x.bin`` (or ``x1.bin``) in some working directory, then the
strategy feeds that blob to the fuzzer. This module runs such scripts
in a child ``python3`` process and reports whether the expected blob
was produced.

No sandboxing is applied: the strategy is already running inside the
project's docker container (see ``common.fuzzing.runner``), so the
threat model is "trust the LLM-generated code within the container
boundary". Do **not** call this helper from contexts where that is
not true.
"""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from typing import Tuple

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_SECONDS = 30
_EXPECTED_BLOB_NAMES = ("x1.bin", "x.bin")


def run_python_code(
    code: str,
    working_dir: str,
    timeout: int = _DEFAULT_TIMEOUT_SECONDS,
) -> Tuple[bool, str, str]:
    """Run ``code`` with ``python3`` inside ``working_dir``.

    Expects the script to create ``x.bin`` (or the variant ``x1.bin``)
    in ``working_dir``. Returns success/failure plus captured stdio.

    Args:
        code: Python source to execute.
        working_dir: Directory to ``cd`` into before running. Must
            exist.
        timeout: Wall-clock timeout in seconds.

    Returns:
        ``(success, stdout, stderr)``. ``success`` is True when the
        expected output blob exists after the run.
    """
    if not working_dir or not os.path.isdir(working_dir):
        msg = f"Invalid working directory: {working_dir!r}"
        logger.error(msg)
        return False, "", msg

    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as script_file:
        script_file.write(code.encode("utf-8"))
        script_path = script_file.name

    try:
        logger.debug("Running generated Python code from %s in %s", script_path, working_dir)
        try:
            result = subprocess.run(
                ["python3", script_path],
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Python code execution timed out after %ds", timeout)
            return False, "", "Execution timed out"
        except (subprocess.SubprocessError, OSError) as exc:
            logger.error("Error running Python code: %s", exc)
            return False, "", str(exc)

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        logger.debug("Python stdout: %s", stdout)
        if stderr:
            logger.debug("Python stderr: %s", stderr)

        for blob_name in _EXPECTED_BLOB_NAMES:
            blob_path = os.path.join(working_dir, blob_name)
            if os.path.exists(blob_path):
                logger.debug(
                    "%s created successfully (%d bytes)",
                    blob_name,
                    os.path.getsize(blob_path),
                )
                return True, stdout, stderr

        logger.warning("No expected output blob (x.bin / x1.bin) produced")
        return False, stdout, stderr
    finally:
        try:
            os.unlink(script_path)
        except OSError as exc:
            logger.debug("Failed to remove temp script %s: %s", script_path, exc)
