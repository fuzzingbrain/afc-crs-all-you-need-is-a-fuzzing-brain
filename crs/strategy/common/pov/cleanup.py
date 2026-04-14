"""POV seed-corpus cleanup utilities."""
from __future__ import annotations

import logging
import os
import time

logger = logging.getLogger(__name__)


def cleanup_seed_corpus(dir_path: str, max_age_minutes: int = 10) -> None:
    """Remove files in a seed-corpus directory older than ``max_age_minutes``.

    Silently no-ops if ``dir_path`` does not exist. Individual file errors are
    logged but do not interrupt cleanup of the remaining files.

    Args:
        dir_path: Directory holding the seed corpus files to prune.
        max_age_minutes: Files older than this (by mtime) are removed.
    """
    if not os.path.exists(dir_path):
        return

    cutoff = time.time() - max_age_minutes * 60

    try:
        entries = os.listdir(dir_path)
    except OSError as exc:
        logger.error("Failed to list seed corpus dir %s: %s", dir_path, exc)
        return

    for filename in entries:
        file_path = os.path.join(dir_path, filename)
        try:
            if not os.path.isfile(file_path):
                continue
            if os.path.getmtime(file_path) >= cutoff:
                continue
            os.remove(file_path)
            logger.debug("Removed stale seed file: %s", filename)
        except OSError as exc:
            logger.error("Failed to remove seed file %s: %s", file_path, exc)
