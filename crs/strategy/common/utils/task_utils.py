"""
Task and file utilities
"""
import os
import json
import subprocess
import signal
import atexit
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from common.logging.logger import StrategyLogger

# Backward-compatibility re-exports. The canonical homes are listed next to
# each import; new code should import from the canonical modules directly.
from common.crash.extract import extract_and_save_crash_input  # noqa: F401  moved to common.crash.extract
from common.fuzzing.runner import run_fuzzer_with_coverage  # noqa: F401  moved to common.fuzzing.runner
from common.pov.cleanup import cleanup_seed_corpus  # noqa: F401  moved to common.pov.cleanup

# Global cleanup flag to prevent recursive cleanup
_cleanup_in_progress = False

def _cleanup_docker_containers():
    """Stop all running Docker containers on exit (skip if running inside Docker)"""
    global _cleanup_in_progress
    if _cleanup_in_progress:
        return
    _cleanup_in_progress = True

    # Skip cleanup if running inside Docker to avoid stopping the parent container
    if os.path.exists('/.dockerenv'):
        return

    try:
        # Get all running containers
        result = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True,
            text=True,
            timeout=5
        )
        container_ids = result.stdout.strip().split('\n')
        container_ids = [cid for cid in container_ids if cid]

        if container_ids:
            print(f"\n⚠️  Stopping {len(container_ids)} Docker container(s)...")
            # Stop all containers
            subprocess.run(
                ["docker", "stop"] + container_ids,
                timeout=10,
                capture_output=True
            )
    except Exception as e:
        print(f"Warning: Could not clean up Docker containers: {e}")

def _signal_handler(signum, frame):
    """Handle interrupt signals"""
    print(f"\n⚠️  Received signal {signum}, cleaning up...")
    _cleanup_docker_containers()
    os._exit(130)

# Register cleanup handlers
atexit.register(_cleanup_docker_containers)
signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


def load_task_detail(fuzz_dir: str, logger: Optional['StrategyLogger'] = None) -> Optional[dict]:
    """
    Load TaskDetail from the task_detail.json file in the fuzzing directory

    Args:
        fuzz_dir: Path to the fuzzing directory
        logger: Optional StrategyLogger for logging

    Returns:
        The TaskDetail as a dictionary, or None if the file doesn't exist or can't be parsed
    """
    task_detail_path = os.path.join(fuzz_dir, "task_detail.json")

    if not os.path.exists(task_detail_path):
        if logger:
            logger.warning(f"Task detail file not found at {task_detail_path}")
        return None

    try:
        with open(task_detail_path, 'r') as f:
            task_detail = json.load(f)

        # Validate required fields
        required_fields = ["task_id", "type", "metadata", "deadline", "focus", "project_name"]
        for field in required_fields:
            if field not in task_detail:
                if logger:
                    logger.warning(f"Required field '{field}' missing from task_detail.json")

        if logger:
            logger.log(f"Successfully loaded task detail for project: {task_detail.get('project_name', 'unknown')}")
        return task_detail

    except json.JSONDecodeError as e:
        if logger:
            logger.error(f"Failed to parse task_detail.json: {str(e)}")
        return None
    except Exception as e:
        if logger:
            logger.error(f"Error loading task_detail.json: {str(e)}")
        return None
