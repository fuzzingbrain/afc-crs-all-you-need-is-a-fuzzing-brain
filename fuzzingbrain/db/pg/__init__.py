# SPDX-License-Identifier: Apache-2.0
"""PostgreSQL storage: the schema (models.py) and its migrations."""

from pathlib import Path

from alembic import command
from alembic.config import Config

from .models import Base

MIGRATIONS = Path(__file__).parent / "migrations"


def alembic_config(url: str) -> Config:
    """An Alembic config for this package, pointed at ``url``.

    The URL travels in ``attributes`` rather than the ini options, which run
    through configparser interpolation and would mangle a ``%`` in a password.
    """
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.attributes["url"] = url
    return cfg


def migrate(url: str, revision: str = "head") -> None:
    """Bring the database at ``url`` to ``revision``."""
    command.upgrade(alembic_config(url), revision)


__all__ = ["Base", "alembic_config", "migrate"]
