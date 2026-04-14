"""Java-specific helpers (jar selection, etc.)."""
from __future__ import annotations

import glob
import logging
import os
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Prefixes that identify helper / instrumentation jars that should be
# skipped when picking a project jar.
_HELPER_JAR_PREFIXES: Tuple[str, ...] = ("jacoco", "jazzer", "metrics-")


def pick_fallback_jar(jar_dir: str) -> Optional[str]:
    """Return the first plausible project jar under ``jar_dir``.

    Sorts the ``*.jar`` entries in ``jar_dir`` by name and returns the
    first one whose basename does not start with any of the
    :data:`_HELPER_JAR_PREFIXES` (``jacoco``, ``jazzer``, ``metrics-``).
    Returns ``None`` when no suitable jar is present.
    """
    for jar in sorted(glob.glob(os.path.join(jar_dir, "*.jar"))):
        base = os.path.basename(jar)
        if not any(base.startswith(prefix) for prefix in _HELPER_JAR_PREFIXES):
            return jar
    return None
