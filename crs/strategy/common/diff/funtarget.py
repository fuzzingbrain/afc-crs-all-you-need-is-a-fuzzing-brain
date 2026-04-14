"""Wrapper around the ``funtarget`` binary for diff-function extraction.

``funtarget`` is a small Go/C helper shipped alongside the strategy
worker; given a diff and a source directory it returns a JSON array of
per-function metadata. This module encapsulates the filesystem
conventions (cache file, binary location, diff path) and swallows the
usual failure modes (missing binary, bad JSON, timeout) by returning
``None``.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_FUNTARGET_BINARY = os.path.expanduser("~/funtarget/funtarget")
_FUNTARGET_TIMEOUT_SECONDS = 60


def extract_diff_functions_using_funtarget(
    project_src_dir: str,
    out_dir: str,
) -> Optional[List[Dict[str, Any]]]:
    """Run ``funtarget`` over the task diff and return its JSON output.

    Results are cached at ``{out_dir}/funtarget_output.json``; subsequent
    calls reuse that cached payload when it exists.

    Args:
        project_src_dir: Source directory to run the tool against.
        out_dir: Working directory the binary is launched in, also used
            for the output cache.

    Returns:
        Parsed list of function metadata dicts, or ``None`` when the
        binary is missing, the diff file is missing, the process
        failed, or the output was not valid JSON.
    """
    cache_file = os.path.join(out_dir, "funtarget_output.json")
    if os.path.exists(cache_file):
        logger.debug("Found cached funtarget output: %s", cache_file)
        try:
            with open(cache_file, "r") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to read funtarget cache %s: %s", cache_file, exc)

    logger.debug("Running funtarget on %s", project_src_dir)

    if not os.path.exists(_FUNTARGET_BINARY):
        logger.warning(
            "funtarget not found at %s, skipping diff function extraction",
            _FUNTARGET_BINARY,
        )
        return None

    diff_path = os.path.join(project_src_dir, "..", "diff", "ref.diff")
    if not os.path.exists(diff_path):
        logger.warning("diff file not found at %s", diff_path)
        return None

    try:
        result = subprocess.run(
            [_FUNTARGET_BINARY, diff_path, project_src_dir],
            cwd=out_dir,
            capture_output=True,
            text=True,
            timeout=_FUNTARGET_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        logger.warning("funtarget timed out")
        return None
    except (subprocess.SubprocessError, OSError) as exc:
        logger.error("Error running funtarget: %s", exc)
        return None

    if result.returncode != 0:
        logger.warning("funtarget failed with return code %s", result.returncode)
        if result.stderr:
            logger.debug("funtarget stderr: %s", result.stderr)
        return None

    if not result.stdout:
        return None

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse funtarget output as JSON: %s", exc)
        return None

    try:
        with open(cache_file, "w") as fh:
            json.dump(data, fh, indent=2)
    except OSError as exc:
        logger.warning("Failed to write funtarget cache %s: %s", cache_file, exc)
    else:
        logger.debug("Saved funtarget output to %s", cache_file)

    return data
