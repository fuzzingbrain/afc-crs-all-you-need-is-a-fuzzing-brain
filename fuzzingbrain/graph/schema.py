# SPDX-License-Identifier: Apache-2.0
"""The function index / call graph file: one SQLite file per software commit.

A file always has `meta` and `functions`. A call graph adds `edges`, and each
harness it knows adds a `harnesses` row and its `reach` marks. Without a call
graph (tree-sitter only) the last three tables exist and are empty, so readers
need no second code path. docs/db-design.md §3 explains the layout.

The main graph is stored once per software: every harness reaches a subset of
the same functions, and a harness is that subset (`reach`), not a copy.
"""

import hashlib
import sqlite3
from pathlib import Path

FORMAT_VERSION = "1"

DDL = """
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE functions (
    id                    INTEGER PRIMARY KEY,
    name                  TEXT NOT NULL,
    file_path             TEXT NOT NULL,
    file_path_rel         TEXT,
    -- NULL when the producer did not know it (never 0).
    start_line            INTEGER CHECK (start_line > 0),
    end_line              INTEGER,
    content               TEXT NOT NULL DEFAULT '',
    cyclomatic_complexity INTEGER,
    language              TEXT,
    symbol                TEXT,
    -- Called but not defined in the analysed code (libc, sanitizer hooks).
    external              INTEGER NOT NULL DEFAULT 0,
    UNIQUE (file_path, name, start_line)
);
CREATE INDEX functions_name ON functions (name);
CREATE INDEX functions_file ON functions (file_path);

-- One row per caller -> callee pair, the union over every harness's analysis.
CREATE TABLE edges (
    src      INTEGER NOT NULL REFERENCES functions (id),
    dst      INTEGER NOT NULL REFERENCES functions (id),
    -- 1: inferred through a function pointer or virtual call.
    indirect INTEGER NOT NULL,
    PRIMARY KEY (src, dst)
) WITHOUT ROWID;
CREATE INDEX edges_dst ON edges (dst, src);

CREATE TABLE harnesses (
    id                INTEGER PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    entry_function_id INTEGER REFERENCES functions (id)
);

-- The functions in a harness's graph, with the shortest call depth from its
-- entry. depth is NULL when the producer put a function in the harness's graph
-- without a depth.
CREATE TABLE reach (
    harness_id  INTEGER NOT NULL REFERENCES harnesses (id),
    function_id INTEGER NOT NULL REFERENCES functions (id),
    depth       INTEGER CHECK (depth >= 0),
    reached_via TEXT,
    PRIMARY KEY (harness_id, function_id)
) WITHOUT ROWID;
"""


def create(path: Path) -> sqlite3.Connection:
    """A new, empty index file at `path` (which must not exist)."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript(DDL)
    db.execute("INSERT INTO meta VALUES ('format_version', ?)", (FORMAT_VERSION,))
    return db


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
