# SPDX-License-Identifier: Apache-2.0
"""
FuzzingBrain Database Layer

MongoDB connection and repository pattern for all models.
"""

from .connection import MongoDB, get_database
from .repository import (
    BaseRepository,
    RunRepository,
    POVRepository,
    PatchRepository,
    WorkerRepository,
    FuzzerRepository,
    RepositoryManager,
    get_repos,
    init_repos,
)

__all__ = [
    # Connection
    "MongoDB",
    "get_database",
    # Repositories
    "BaseRepository",
    "RunRepository",
    "POVRepository",
    "PatchRepository",
    "WorkerRepository",
    "FuzzerRepository",
    "RepositoryManager",
    "get_repos",
    "init_repos",
]
