# SPDX-License-Identifier: Apache-2.0
"""Task metadata loading.

Historically this module held fuzzer execution, crash extraction, corpus
cleanup, and docker process-lifecycle management. All of that has been
migrated to domain subpackages under ``common/``; only the task-detail
loader remains here. Legacy import paths keep working via the re-exports
below.
"""
from __future__ import annotations

import json
import os
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from common.logging.logger import StrategyLogger

# Backward-compatibility re-exports. The canonical homes are listed next to
# each import; new code should import from the canonical modules directly.
from common.crash.extract import extract_and_save_crash_input  # noqa: F401  moved to common.crash.extract
from common.fuzzing.runner import run_fuzzer_with_coverage  # noqa: F401  moved to common.fuzzing.runner
from common.pov.cleanup import cleanup_seed_corpus  # noqa: F401  moved to common.pov.cleanup


def load_task_detail(fuzz_dir: str, logger: Optional['StrategyLogger'] = None) -> Optional[dict]:
    """Load ``task_detail.json`` from a fuzzing directory.

    Args:
        fuzz_dir: Path to the fuzzing directory that should contain
            ``task_detail.json``.
        logger: Optional StrategyLogger used for progress / error messages.
            Absent logging is tolerated; this helper is frequently called
            from non-strategy contexts.

    Returns:
        The parsed task detail mapping, or ``None`` when the file is
        missing or unparseable.
    """
    task_detail_path = os.path.join(fuzz_dir, "task_detail.json")

    if not os.path.exists(task_detail_path):
        if logger:
            logger.warning(f"Task detail file not found at {task_detail_path}")
        return None

    try:
        with open(task_detail_path, 'r') as f:
            task_detail = json.load(f)
    except json.JSONDecodeError as e:
        if logger:
            logger.error(f"Failed to parse task_detail.json: {str(e)}")
        return None
    except OSError as e:
        if logger:
            logger.error(f"Error loading task_detail.json: {str(e)}")
        return None

    required_fields = ("task_id", "type", "metadata", "deadline", "focus", "project_name")
    for field in required_fields:
        if field not in task_detail and logger:
            logger.warning(f"Required field '{field}' missing from task_detail.json")

    if logger:
        logger.log(
            f"Successfully loaded task detail for project: "
            f"{task_detail.get('project_name', 'unknown')}"
        )
    return task_detail
