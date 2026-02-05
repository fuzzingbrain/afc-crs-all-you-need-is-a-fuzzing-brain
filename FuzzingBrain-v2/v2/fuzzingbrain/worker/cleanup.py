"""
Worker Cleanup

Cleans up worker workspace after task completion.
Only removes git-tracked files, keeps all generated files.
"""

import shutil
import subprocess
from pathlib import Path

from ..core import logger


def cleanup_worker_workspace(workspace_path: str, keep_results: bool = True):
    """
    Clean up worker workspace after completion.

    Strategy:
    - For repo/: Remove only git-tracked files, keep generated files
    - For fuzz-tooling/: Remove entirely (no generated files expected)
    - For diff/: Remove entirely
    - For results/: Always keep

    Args:
        workspace_path: Path to worker workspace
        keep_results: Whether to keep results directory (default True)
    """
    workspace = Path(workspace_path)

    if not workspace.exists():
        logger.warning(f"Workspace does not exist: {workspace}")
        return

    logger.info(f"Cleaning up workspace: {workspace}")

    # Clean repo/ using git
    repo_path = workspace / "repo"
    if repo_path.exists():
        _cleanup_git_tracked(repo_path)

    # Remove fuzz-tooling/ entirely
    fuzz_tooling_path = workspace / "fuzz-tooling"
    if fuzz_tooling_path.exists():
        shutil.rmtree(fuzz_tooling_path)
        logger.info(f"Removed: {fuzz_tooling_path}")

    # Remove diff/ entirely
    diff_path = workspace / "diff"
    if diff_path.exists():
        shutil.rmtree(diff_path)
        logger.info(f"Removed: {diff_path}")

    # Results are always kept
    results_path = workspace / "results"
    if results_path.exists():
        logger.info(f"Preserved: {results_path}")

    logger.info(f"Cleanup completed for: {workspace}")


def _cleanup_git_tracked(repo_path: Path):
    """
    Remove only git-tracked files from repo, keep generated files.

    Args:
        repo_path: Path to git repository
    """
    git_dir = repo_path / ".git"

    if not git_dir.exists():
        # No git, just remove everything except known generated dirs
        logger.warning(f"No .git found in {repo_path}, removing entire directory")
        shutil.rmtree(repo_path)
        return

    try:
        # Get list of tracked files
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_path,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            logger.warning("git ls-files failed, removing entire repo")
            shutil.rmtree(repo_path)
            return

        tracked_files = result.stdout.strip().split("\n")
        tracked_files = [f for f in tracked_files if f]  # Remove empty strings

        # Delete tracked files
        deleted_count = 0
        for file in tracked_files:
            file_path = repo_path / file
            if file_path.exists() and file_path.is_file():
                file_path.unlink()
                deleted_count += 1

        # Delete empty directories
        _remove_empty_dirs(repo_path)

        # Delete .git directory to save space
        if git_dir.exists():
            shutil.rmtree(git_dir)

        logger.info(f"Removed {deleted_count} tracked files from {repo_path}")

    except Exception as e:
        logger.exception(f"Git cleanup failed: {e}, removing entire repo")
        shutil.rmtree(repo_path)


def _remove_empty_dirs(path: Path):
    """Remove all empty directories recursively."""
    for dir_path in sorted(path.rglob("*"), reverse=True):
        if dir_path.is_dir():
            try:
                dir_path.rmdir()  # Only removes if empty
            except OSError:
                pass  # Directory not empty, skip
