# SPDX-License-Identifier: Apache-2.0
"""Task-scoped input-file loaders.

Small JSON readers for inputs that ride in the per-task working
directory: ``suspected_vulns.json`` (pre-seeded by upstream tooling
with hand-curated targets) and ``security_findings.json`` (emitted by
the Claude-agent security analyser). Both helpers return empty lists
on any error rather than raising so callers can treat "nothing to
work with" as a normal state.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def load_suspected_vulns(project_dir: str) -> List[Dict[str, Any]]:
    """Load ``suspected_vulns.json`` from a project directory.

    Args:
        project_dir: Directory that may contain ``suspected_vulns.json``.

    Returns:
        The parsed JSON array, or ``[]`` when the file is missing or
        fails to parse.
    """
    vuln_file = os.path.join(project_dir, "suspected_vulns.json")
    if not os.path.exists(vuln_file):
        return []

    try:
        with open(vuln_file, "r") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Error loading suspected_vulns.json: %s", exc)
        return []


def load_security_findings(project_dir: str) -> List[Dict[str, Any]]:
    """Load ``security_findings.json`` emitted by the security analyser.

    Searches three locations, returning the first that exists:

    1. ``{project_dir}/security_findings/security_findings.json``
    2. ``{project_dir}/security_findings.json``
    3. ``{dirname(project_dir)}/security_findings/security_findings.json``

    Findings are extracted from the top-level ``vulnerabilities`` key
    and sorted (verified first, then by severity high > medium > low).
    """
    candidates = [
        os.path.join(project_dir, "security_findings", "security_findings.json"),
        os.path.join(project_dir, "security_findings.json"),
        os.path.join(os.path.dirname(project_dir), "security_findings", "security_findings.json"),
    ]

    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Error loading %s: %s", path, exc)
            continue

        findings = data.get("vulnerabilities", [])
        if not findings:
            continue

        logger.info("Loaded %d security findings from %s", len(findings), path)
        findings.sort(
            key=lambda v: (
                0 if v.get("verified") else 1,
                _SEVERITY_ORDER.get(v.get("severity", "medium"), 1),
            )
        )
        return findings

    return []
