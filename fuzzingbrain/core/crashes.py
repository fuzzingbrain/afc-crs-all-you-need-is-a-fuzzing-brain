# SPDX-License-Identifier: Apache-2.0
"""A crashing input becomes a crash: signature, dedup, package, report.

Every source comes through record_crash(): a VH agent's create_poc, the
global fuzzer and the VH fuzzers. The attempt row is already written; this
gives it its signature, and the crashes table (one row per distinct
signature in the run) says whether it is new. A new crash gets a report and
a package (results/pocs/crash_<id>/ and its zip).
"""

import hashlib
from dataclasses import dataclass
from typing import Optional

import logging

from ..db.store import get_store

logger = logging.getLogger(__name__)


def _sig():
    # Imported on use: fuzzer/__init__ pulls in the agents, which import the
    # PoC tools, which import this module.
    from ..fuzzer import signature

    return signature


@dataclass
class CrashResult:
    crash_id: str
    is_new: bool
    signature: str  # what crashes.signature holds
    key: str  # readable: class plus frames
    describe: str
    vuln_type: str


def crash_signature(output: str, harness: str, blob: bytes):
    """(stored signature, readable key, description) of a crash.

    A crash whose report names no class and no frame cannot be compared with
    another, so it gets one of its own (from the input): counted once, never
    merged into a different bug.
    """
    sig = _sig().compute_signature(output or "", harness_names=[harness] if harness else [])
    if sig:
        return sig.short, sig.key, sig.describe()
    own = "unsigned-" + hashlib.sha256(blob).hexdigest()[:16]
    return own, own, "unrecognised crash"


def is_real_fault(output: str) -> bool:
    """A sanitizer class or fatal signal, not a plain exit()."""
    return bool(_sig().extract_class(output or ""))


def record_crash(
    attempt_id,
    output: str,
    harness: str,
    blob: bytes,
    vuln_type: Optional[str] = None,
) -> CrashResult:
    short, key, describe = crash_signature(output, harness, blob)
    vuln_type = vuln_type or _sig().extract_class(output or "") or "unknown"
    crash_id, is_new = get_store().attempt_crashed(attempt_id, short, vuln_type, output)
    return CrashResult(str(crash_id), is_new, short, key, describe, vuln_type)


def package_crash(crash_id, results_dir: str, analyzer_socket: Optional[str] = None):
    """Report and package a new crash (the report agent runs here)."""
    from .poc_packager import POCPackager

    try:
        return POCPackager(results_dir, analyzer_socket_path=analyzer_socket).package_crash(
            crash_id
        )
    except Exception as e:
        logger.error(f"[crash {str(crash_id)[:8]}] packaging failed: {e}")
        return None


async def package_crash_async(crash_id, results_dir: str, analyzer_socket: Optional[str] = None):
    from .poc_packager import POCPackager

    try:
        return await POCPackager(
            results_dir, analyzer_socket_path=analyzer_socket
        ).package_crash_async(crash_id)
    except Exception as e:
        logger.error(f"[crash {str(crash_id)[:8]}] packaging failed: {e}")
        return None
