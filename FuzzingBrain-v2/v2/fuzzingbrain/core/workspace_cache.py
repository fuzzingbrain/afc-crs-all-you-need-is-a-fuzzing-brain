"""
Workspace Cache

Caches built workspaces to avoid redundant compilation.
Cache key: {project}_{commit}_{sanitizers}

Usage:
    cache = WorkspaceCache(Path("workspace/cache"))

    # Check for existing cache
    cached = cache.find_cache("libpng", "abc123", ["address"])
    if cached:
        cache.restore_to(cached, task_workspace)
        cache.restore_db_data(cached, task_id, repos)
    else:
        # Build normally...
        cache.save_from(task_workspace, "libpng", "abc123", ["address"])
        cache.save_db_data(cache_path, task_id, repos)
"""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, TYPE_CHECKING

from .logging import logger

if TYPE_CHECKING:
    from ..db import RepositoryManager


class WorkspaceCache:
    """
    Manages workspace caching for faster task startup.

    Cache structure:
        cache_dir/
        ├── libpng_abc123_address/
        │   ├── fuzz-tooling/
        │   ├── repo/
        │   ├── fuzz-tooling-introspector/
        │   └── cache_meta.json
        └── libxml2_def456_address_memory/
            └── ...
    """

    # Directories to cache
    CACHE_DIRS = [
        "fuzz-tooling",
        "repo",
        "fuzz-tooling-introspector",
    ]

    def __init__(self, cache_dir: Path):
        """
        Initialize workspace cache.

        Args:
            cache_dir: Root directory for cache storage (e.g., workspace/cache)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_cache_key(self, project: str, commit: str, sanitizers: List[str]) -> str:
        """
        Generate cache key from project, commit, and sanitizers.

        Args:
            project: Project name
            commit: Commit hash (will be truncated to 8 chars)
            sanitizers: List of sanitizers

        Returns:
            Cache key string
        """
        commit_short = commit[:8] if commit else "unknown"
        sanitizers_str = "_".join(sorted(sanitizers)) if sanitizers else "none"
        return f"{project}_{commit_short}_{sanitizers_str}"

    def find_cache(
        self,
        project: str,
        commit: str,
        sanitizers: List[str]
    ) -> Optional[Path]:
        """
        Find matching cache entry.

        Supports sanitizer subset matching:
        - Request: ["address"], Cache: ["address", "memory"] -> Match
        - Request: ["address"], Cache: ["memory"] -> No match

        Args:
            project: Project name
            commit: Commit hash
            sanitizers: Required sanitizers

        Returns:
            Path to cache directory if found, None otherwise
        """
        if not self.cache_dir.exists():
            return None

        commit_short = commit[:8] if commit else "unknown"
        requested_sanitizers = set(sanitizers) if sanitizers else set()

        # Look for exact match first
        exact_key = self.get_cache_key(project, commit, sanitizers)
        exact_path = self.cache_dir / exact_key
        if exact_path.exists() and self._is_valid_cache(exact_path):
            logger.info(f"[Cache] Found exact match: {exact_key}")
            return exact_path

        # Look for superset match (cache has more sanitizers than requested)
        for cache_entry in self.cache_dir.iterdir():
            if not cache_entry.is_dir():
                continue

            # Parse cache entry name: {project}_{commit}_{sanitizers}
            parts = cache_entry.name.split("_")
            if len(parts) < 3:
                continue

            cache_project = parts[0]
            cache_commit = parts[1]
            cache_sanitizers = set(parts[2:])  # All remaining parts are sanitizers

            # Check project and commit match
            if cache_project != project or cache_commit != commit_short:
                continue

            # Check if cache sanitizers contain all requested sanitizers
            if requested_sanitizers.issubset(cache_sanitizers):
                if self._is_valid_cache(cache_entry):
                    logger.info(f"[Cache] Found superset match: {cache_entry.name}")
                    return cache_entry

        logger.info(f"[Cache] No cache found for {project}_{commit_short}")
        return None

    def _is_valid_cache(self, cache_path: Path) -> bool:
        """Check if cache directory is valid (has required subdirs)."""
        meta_file = cache_path / "cache_meta.json"
        fuzz_tooling = cache_path / "fuzz-tooling"

        # Must have meta file and fuzz-tooling directory
        if not meta_file.exists() or not fuzz_tooling.exists():
            return False

        # Check meta file is readable
        try:
            with open(meta_file) as f:
                meta = json.load(f)
            return meta.get("valid", False)
        except Exception:
            return False

    def restore_to(self, cache_path: Path, target_workspace: Path) -> bool:
        """
        Restore cache to target workspace.

        Args:
            cache_path: Path to cache directory
            target_workspace: Target workspace path

        Returns:
            True if successful
        """
        try:
            target_workspace.mkdir(parents=True, exist_ok=True)

            for dir_name in self.CACHE_DIRS:
                src = cache_path / dir_name
                dst = target_workspace / dir_name

                if src.exists():
                    if dst.exists():
                        shutil.rmtree(dst)
                    logger.debug(f"[Cache] Copying {dir_name}...")
                    shutil.copytree(src, dst, symlinks=True)

            # Update cache metadata (last used)
            self._update_last_used(cache_path)

            logger.info(f"[Cache] Restored workspace from cache: {cache_path.name}")
            return True

        except Exception as e:
            logger.error(f"[Cache] Failed to restore cache: {e}")
            return False

    def save_from(
        self,
        workspace: Path,
        project: str,
        commit: str,
        sanitizers: List[str]
    ) -> Optional[Path]:
        """
        Save workspace to cache.

        Args:
            workspace: Source workspace path
            project: Project name
            commit: Commit hash
            sanitizers: List of sanitizers

        Returns:
            Path to cache directory if successful, None otherwise
        """
        try:
            cache_key = self.get_cache_key(project, commit, sanitizers)
            cache_path = self.cache_dir / cache_key

            # Use temp directory to avoid partial writes
            temp_path = self.cache_dir / f".tmp_{cache_key}"
            if temp_path.exists():
                shutil.rmtree(temp_path)
            temp_path.mkdir(parents=True)

            # Copy directories
            for dir_name in self.CACHE_DIRS:
                src = workspace / dir_name
                dst = temp_path / dir_name

                if src.exists():
                    logger.debug(f"[Cache] Saving {dir_name}...")
                    shutil.copytree(src, dst, symlinks=True)

            # Write metadata
            meta = {
                "valid": True,
                "project": project,
                "commit": commit,
                "sanitizers": sanitizers,
                "created_at": datetime.now().isoformat(),
                "last_used": datetime.now().isoformat(),
            }
            with open(temp_path / "cache_meta.json", "w") as f:
                json.dump(meta, f, indent=2)

            # Atomic move
            if cache_path.exists():
                shutil.rmtree(cache_path)
            temp_path.rename(cache_path)

            logger.info(f"[Cache] Saved workspace to cache: {cache_key}")
            return cache_path

        except Exception as e:
            logger.error(f"[Cache] Failed to save cache: {e}")
            # Cleanup temp directory
            if temp_path.exists():
                shutil.rmtree(temp_path)
            return None

    def _update_last_used(self, cache_path: Path):
        """Update last_used timestamp in cache metadata."""
        meta_file = cache_path / "cache_meta.json"
        try:
            if meta_file.exists():
                with open(meta_file) as f:
                    meta = json.load(f)
                meta["last_used"] = datetime.now().isoformat()
                with open(meta_file, "w") as f:
                    json.dump(meta, f, indent=2)
        except Exception:
            pass

    def list_caches(self) -> List[Dict[str, Any]]:
        """List all cache entries with metadata."""
        entries = []

        if not self.cache_dir.exists():
            return entries

        for cache_entry in sorted(self.cache_dir.iterdir()):
            if not cache_entry.is_dir() or cache_entry.name.startswith("."):
                continue

            meta_file = cache_entry / "cache_meta.json"
            if meta_file.exists():
                try:
                    with open(meta_file) as f:
                        meta = json.load(f)
                    meta["path"] = str(cache_entry)
                    meta["size_mb"] = self._get_dir_size(cache_entry) / (1024 * 1024)
                    entries.append(meta)
                except Exception:
                    pass

        return entries

    def _get_dir_size(self, path: Path) -> int:
        """Get total size of directory in bytes."""
        total = 0
        for p in path.rglob("*"):
            if p.is_file():
                total += p.stat().st_size
        return total

    def clear_cache(self, older_than_days: int = None) -> int:
        """
        Clear cache entries.

        Args:
            older_than_days: If specified, only clear entries older than this

        Returns:
            Number of entries cleared
        """
        cleared = 0

        if not self.cache_dir.exists():
            return 0

        now = datetime.now()

        for cache_entry in list(self.cache_dir.iterdir()):
            if not cache_entry.is_dir() or cache_entry.name.startswith("."):
                continue

            should_clear = True

            if older_than_days is not None:
                meta_file = cache_entry / "cache_meta.json"
                if meta_file.exists():
                    try:
                        with open(meta_file) as f:
                            meta = json.load(f)
                        last_used = datetime.fromisoformat(meta.get("last_used", meta.get("created_at", "")))
                        age_days = (now - last_used).days
                        should_clear = age_days > older_than_days
                    except Exception:
                        pass

            if should_clear:
                try:
                    shutil.rmtree(cache_entry)
                    cleared += 1
                    logger.info(f"[Cache] Cleared: {cache_entry.name}")
                except Exception as e:
                    logger.warning(f"[Cache] Failed to clear {cache_entry.name}: {e}")

        return cleared

    def save_db_data(
        self,
        cache_path: Path,
        task_id: str,
        repos: "RepositoryManager",
    ) -> bool:
        """
        Save database data (functions, fuzzers, callgraph) to cache.

        Args:
            cache_path: Path to cache directory
            task_id: Task ID to export data from
            repos: Database repository manager

        Returns:
            True if successful
        """
        try:
            db_data = {
                "functions": [],
                "fuzzers": [],
                "callgraph_nodes": [],
            }

            # Export functions
            functions = repos.functions.find_by_task(task_id)
            for func in functions:
                func_dict = func.to_dict() if hasattr(func, 'to_dict') else vars(func).copy()
                # Remove task-specific fields that will be replaced on restore
                func_dict.pop('_id', None)
                func_dict.pop('task_id', None)
                db_data["functions"].append(func_dict)

            # Export fuzzers
            fuzzers = repos.fuzzers.find_by_task(task_id)
            for fuzzer in fuzzers:
                fuzzer_dict = fuzzer.to_dict() if hasattr(fuzzer, 'to_dict') else vars(fuzzer).copy()
                fuzzer_dict.pop('_id', None)
                fuzzer_dict.pop('task_id', None)
                db_data["fuzzers"].append(fuzzer_dict)

            # Export callgraph nodes (critical for reachability analysis)
            callgraph_nodes = repos.callgraph_nodes.find_by_task(task_id)
            for node in callgraph_nodes:
                node_dict = node.to_dict() if hasattr(node, 'to_dict') else vars(node).copy()
                node_dict.pop('_id', None)
                node_dict.pop('task_id', None)
                node_dict.pop('node_id', None)  # MUST remove so __post_init__ regenerates with new task_id
                db_data["callgraph_nodes"].append(node_dict)

            # Write to cache
            db_file = cache_path / "db_data.json"
            with open(db_file, "w") as f:
                json.dump(db_data, f, indent=2, default=str)

            logger.info(f"[Cache] Saved {len(db_data['functions'])} functions, {len(db_data['fuzzers'])} fuzzers, {len(db_data['callgraph_nodes'])} callgraph nodes to cache")
            return True

        except Exception as e:
            logger.error(f"[Cache] Failed to save db data: {e}")
            return False

    def restore_db_data(
        self,
        cache_path: Path,
        task_id: str,
        repos: "RepositoryManager",
    ) -> bool:
        """
        Restore database data from cache.

        Args:
            cache_path: Path to cache directory
            task_id: New task ID to assign to restored data
            repos: Database repository manager

        Returns:
            True if successful
        """
        try:
            db_file = cache_path / "db_data.json"
            if not db_file.exists():
                logger.warning(f"[Cache] No db_data.json found in cache")
                return False

            with open(db_file) as f:
                db_data = json.load(f)

            # Import functions with new task_id
            from .models import Function
            functions_imported = 0
            for func_dict in db_data.get("functions", []):
                func_dict["task_id"] = task_id
                try:
                    func = Function.from_dict(func_dict)
                    repos.functions.save(func)
                    functions_imported += 1
                except Exception as e:
                    logger.debug(f"[Cache] Failed to import function: {e}")

            # Import fuzzers with new task_id
            from .models import Fuzzer
            fuzzers_imported = 0
            for fuzzer_dict in db_data.get("fuzzers", []):
                fuzzer_dict["task_id"] = task_id
                try:
                    # Fuzzer.from_dict handles status enum conversion
                    fuzzer = Fuzzer.from_dict(fuzzer_dict)
                    repos.fuzzers.save(fuzzer)
                    fuzzers_imported += 1
                except Exception as e:
                    logger.debug(f"[Cache] Failed to import fuzzer: {e}")

            # Import callgraph nodes with new task_id (critical for reachability)
            from .models import CallGraphNode
            callgraph_imported = 0
            for node_dict in db_data.get("callgraph_nodes", []):
                node_dict["task_id"] = task_id
                try:
                    node = CallGraphNode.from_dict(node_dict)
                    repos.callgraph_nodes.save(node)
                    callgraph_imported += 1
                except Exception as e:
                    logger.debug(f"[Cache] Failed to import callgraph node: {e}")

            logger.info(f"[Cache] Restored {functions_imported} functions, {fuzzers_imported} fuzzers, {callgraph_imported} callgraph nodes from cache")
            return True

        except Exception as e:
            logger.error(f"[Cache] Failed to restore db data: {e}")
            return False
