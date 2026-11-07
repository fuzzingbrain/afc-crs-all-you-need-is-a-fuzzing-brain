# SPDX-License-Identifier: Apache-2.0
"""llm_calls.prices: the unit prices each cost was computed from

Revision ID: 0002
Revises: 0001
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("llm_calls", sa.Column("prices", postgresql.JSONB(), nullable=True))
    # Rows written before this revision have a cost and no prices.
    op.execute(
        "UPDATE llm_calls SET prices = '{\"unknown\": true}'::jsonb "
        "WHERE cost IS NOT NULL AND prices IS NULL"
    )
    op.create_check_constraint(
        op.f("ck_llm_calls_cost_with_prices"), "llm_calls", "(cost IS NULL) = (prices IS NULL)"
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_llm_calls_cost_with_prices"), "llm_calls", type_="check")
    op.drop_column("llm_calls", "prices")
