"""add_services_to_assets

Revision ID: d9129a3b61bf
Revises: 7c04f254e8ce, 9e8d7c6b5a4f
Create Date: 2026-09-20 01:25:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'd9129a3b61bf'
down_revision: Union[str, Sequence[str], None] = '9e8d7c6b5a4f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Add services column
    op.add_column('assets', sa.Column('services', sa.Text(), nullable=True))

def downgrade() -> None:
    # Drop services column
    op.drop_column('assets', 'services')
