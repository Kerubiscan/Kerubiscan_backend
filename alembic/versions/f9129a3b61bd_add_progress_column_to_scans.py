"""add progress column to scans

Revision ID: f9129a3b61bd
Revises: 8c2b3d4e5f6g
Create Date: 2026-08-26 08:33:55.378536

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f9129a3b61bd'
down_revision: Union[str, None] = '8c2b3d4e5f6g'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('progress', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('scans', sa.Column('executive_summary', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('scans', 'executive_summary')
    op.drop_column('scans', 'progress')
