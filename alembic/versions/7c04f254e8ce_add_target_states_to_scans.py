"""Add target_states to ScanEntity

Revision ID: 7c04f254e8ce
Revises: 6f03f254e8cd
Create Date: 2026-09-04 19:58:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7c04f254e8ce'
down_revision: Union[str, None] = '6f03f254e8cd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('target_states', sa.JSON(), server_default='{}', nullable=False))


def downgrade() -> None:
    op.drop_column('scans', 'target_states')
