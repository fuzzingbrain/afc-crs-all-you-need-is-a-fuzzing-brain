"""
FuzzingBrain Database Layer

MongoDB connection and repository pattern for all models.
"""

from .connection import MongoDB, get_database
from .repository import (
    BaseRepository,
    TaskRepository,
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
    "TaskRepository",
    "POVRepository",
    "PatchRepository",
    "WorkerRepository",
    "FuzzerRepository",
    "RepositoryManager",
    "get_repos",
    "init_repos",
]
