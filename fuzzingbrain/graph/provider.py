# SPDX-License-Identifier: Apache-2.0
"""Where a run's index file comes from.

A provider produces one index file. Two exist: a graph somebody already built
(the artifact ships them, converted with convert.py), and tree-sitter over the
source when there is no graph, which gives functions and no calls.
"""

import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .schema import create

_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp"}
# Not the software under test: build trees, VCS metadata, the fuzzing toolchain.
_SKIP_DIRS = {".git", "fuzz-tooling", "aflplusplus", "afl", "libfuzzer", "build", "out"}


class FunctionIndexProvider(ABC):
    """Yields the path of a ready index file for a run."""

    @abstractmethod
    def provide(self) -> Path: ...


class ConvertedGraph(FunctionIndexProvider):
    """An index file that already exists (a converted or generated call graph)."""

    def __init__(self, path):
        self.path = Path(path)

    def provide(self) -> Path:
        if not self.path.is_file():
            raise FileNotFoundError(f"call graph file not found: {self.path}")
        return self.path


class SourceFunctions(FunctionIndexProvider):
    """Functions found by tree-sitter in a source tree; no call edges.

    It reads source text, so functions a macro generates or the build writes
    are missing; that is the price of having no compiler-backed graph.
    File paths are relative to the source root.
    """

    def __init__(self, repo_dir, out_path, commit: Optional[str] = None):
        self.repo_dir = Path(repo_dir)
        self.out_path = Path(out_path)
        self.commit = commit

    def provide(self) -> Path:
        from ..analysis.parsers.c_parser import parse_c_file

        if self.out_path.exists():
            self.out_path.unlink()
        db = create(self.out_path)
        seen = set()
        n_files = 0
        rows = []
        try:
            for root, dirs, files in os.walk(self.repo_dir):
                dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
                for fn in sorted(files):
                    if os.path.splitext(fn)[1].lower() not in _SOURCE_SUFFIXES:
                        continue
                    path = Path(root) / fn
                    rel = str(path.relative_to(self.repo_dir))
                    try:
                        found = parse_c_file(path)
                    except Exception:
                        continue
                    n_files += 1
                    for f in found:
                        # A prototype or a one-line macro is not a body to read.
                        if not f.name or not f.content or "\n" not in f.content:
                            continue
                        key = (rel, f.name, f.start_line or None)
                        if key in seen:
                            continue
                        seen.add(key)
                        rows.append((f.name, rel, rel, f.start_line or None,
                                     f.end_line or None, f.content, "c"))
            db.executemany(
                "INSERT INTO functions (name, file_path, file_path_rel, start_line,"
                " end_line, content, language) VALUES (?,?,?,?,?,?,?)",
                rows,
            )
            meta = {
                "producer": "tree-sitter (functions only)",
                "commit": self.commit or "",
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "n_functions": str(len(rows)),
                "n_edges": "0",
                "n_indirect_edges": "0",
                "n_files": str(n_files),
            }
            db.executemany("INSERT INTO meta VALUES (?, ?)", meta.items())
            db.commit()
        finally:
            db.close()
        return self.out_path
