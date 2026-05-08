# SPDX-License-Identifier: Apache-2.0
"""POV metadata on-disk store.

Strategies save a JSON ``pov_metadata_*.json`` alongside a Python
script that generates the crash blob, the blob itself, and a
serialised conversation. This module provides readers for that store
and a couple of "is another worker done?" sentinel probes used to
coordinate parallel runs.

The writer side lives in :mod:`common.pov.lifecycle` (next to the
post-crash-detected workflow) so that readers can live here without a
cycle.
"""
from __future__ import annotations

import glob
import json
import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_POV_METADATA_PREFIX = "pov_metadata_"
_POV_METADATA_SUFFIX = ".json"
_SUCCESS_SENTINEL_PREFIX = "successful_povs"


def _looks_like_pov_present(directory: str) -> bool:
    """Return True when ``directory`` contains any ``successful_povs*`` sentinel."""
    pattern = os.path.join(directory, f"{_SUCCESS_SENTINEL_PREFIX}*")
    for match in glob.glob(pattern):
        if os.path.isfile(match) or os.path.isdir(match):
            logger.debug("Found successful POV sentinel: %s", match)
            return True
    return False


def has_successful_pov0(fuzzer_path: str) -> bool:
    """Check the directory holding the fuzzer binary for a success sentinel."""
    return _looks_like_pov_present(os.path.dirname(fuzzer_path))


def has_successful_pov(fuzzer_path: str, project_dir: str) -> bool:
    """Check both the fuzzer directory and ``project_dir`` for a success sentinel."""
    for directory in (os.path.dirname(fuzzer_path), project_dir):
        if _looks_like_pov_present(directory):
            return True
    return False


def load_all_pov_metadata(pov_success_dir: str) -> List[Dict[str, Any]]:
    """Load every ``pov_metadata_*.json`` under ``pov_success_dir``.

    Entries whose ``blob_file`` cannot be located are skipped so the
    caller can assume the blob is actually reproducible.

    Args:
        pov_success_dir: Directory that the strategy uses to store
            successful POV artefacts.

    Returns:
        List of parsed metadata dicts (possibly empty).
    """
    if not os.path.exists(pov_success_dir):
        logger.debug("POV metadata directory %s does not exist", pov_success_dir)
        return []

    metadata_files = [
        f
        for f in os.listdir(pov_success_dir)
        if f.startswith(_POV_METADATA_PREFIX) and f.endswith(_POV_METADATA_SUFFIX)
    ]
    if not metadata_files:
        logger.debug("No POV metadata files found in %s", pov_success_dir)
        return []

    logger.debug("Found %d POV metadata files", len(metadata_files))

    loaded: List[Dict[str, Any]] = []
    for filename in metadata_files:
        path = os.path.join(pov_success_dir, filename)
        try:
            with open(path, "r") as fh:
                metadata = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Error loading metadata %s: %s", filename, exc)
            continue

        blob_file = metadata.get("blob_file")
        if not blob_file:
            logger.debug("Metadata %s has no blob_file, skipping", filename)
            continue
        if not os.path.exists(os.path.join(pov_success_dir, blob_file)):
            logger.debug("Blob file missing for metadata %s, skipping", filename)
            continue

        loaded.append(metadata)

    logger.debug("Loaded %d valid POV metadata entries", len(loaded))
    return loaded
