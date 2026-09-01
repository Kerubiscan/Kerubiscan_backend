"""Add ports to assets

Revision ID: a550e29e2d1a
Revises: f9129a3b61bd
Create Date: 2026-08-28 10:22:55.962707

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a550e29e2d1a'
down_revision: Union[str, None] = 'f9129a3b61bd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('assets', sa.Column('ports', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('assets', 'ports')
