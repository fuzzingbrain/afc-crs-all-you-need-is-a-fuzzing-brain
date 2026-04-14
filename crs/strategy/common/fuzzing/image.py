"""Docker image resolution for OSS-Fuzz / AIXCC project containers."""
from __future__ import annotations

import logging
import subprocess
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Candidate repositories searched in order; the first tag found wins. The
# AIXCC variant is kept for any legacy workspace that still has those images
# cached, otherwise we fall back to the public OSS-Fuzz tags.
_DEFAULT_REPOSITORIES: Tuple[str, ...] = (
    "aixcc-afc/{project}",
    "gcr.io/oss-fuzz/{project}",
)


def resolve_project_image(
    project_name: str,
    repositories: Tuple[str, ...] = _DEFAULT_REPOSITORIES,
) -> Optional[str]:
    """Return the first locally-available docker image tag for a project.

    Args:
        project_name: OSS-Fuzz project name (substituted into each
            repository template).
        repositories: Repository templates to try, in order. Each template
            must contain ``{project}``.

    Returns:
        A ``repo:tag`` string, or ``None`` if no candidate image is
        present in the local docker daemon.
    """
    for template in repositories:
        repo = template.format(project=project_name)
        try:
            result = subprocess.run(
                ["docker", "images", repo, "--format", "{{.Repository}}:{{.Tag}}"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("docker images lookup failed for %s: %s", repo, exc)
            continue

        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n", 1)[0]

    return None
