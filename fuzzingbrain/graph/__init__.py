# SPDX-License-Identifier: Apache-2.0
"""Function index and call graph: one SQLite file per software commit.

Every run has a function index. With a call graph it also has edges and each
harness's reachability; without one it is the functions tree-sitter finds in
the source. Either way downstream code reads functions one way, from here.

- schema.py   the file layout
- convert.py  artifact per-harness JSON -> index file
- source.py   tree-sitter -> index file (functions only)
- store.py    CallGraph, the reader
"""

from .provider import FunctionIndexProvider, ConvertedGraph, SourceFunctions
from .schema import file_sha256
from .store import ENTRY, CallGraph, GraphError

__all__ = [
    "CallGraph",
    "ConvertedGraph",
    "ENTRY",
    "FunctionIndexProvider",
    "GraphError",
    "SourceFunctions",
    "file_sha256",
]
