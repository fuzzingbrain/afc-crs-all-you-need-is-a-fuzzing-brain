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


def connect_repositories() -> RepositoryManager:
    """Where every process gets its repositories.

    They still talk to MongoDB, which is no longer configured or started; until
    they move to PostgreSQL (refactor-2 step B) nothing can run, and this says
    so instead of failing somewhere deeper.
    """
    raise RuntimeError(
        "FuzzingBrain cannot run yet: the repositories are moving from MongoDB "
        "to PostgreSQL (refactor-2 step B)"
    )


__all__ = [
    "connect_repositories",
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
