# SPDX-License-Identifier: Apache-2.0
"""Alembic environment: online migrations against the URL the caller passed."""

from alembic import context
from sqlalchemy import create_engine, pool

from fuzzingbrain.db.pg.models import Base

url = context.config.attributes["url"]
engine = create_engine(url, poolclass=pool.NullPool)

with engine.connect() as connection:
    context.configure(
        connection=connection,
        target_metadata=Base.metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()
