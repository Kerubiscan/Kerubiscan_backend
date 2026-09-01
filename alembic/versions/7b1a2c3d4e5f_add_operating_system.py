"""add_operating_system

Revision ID: 7b1a2c3d4e5f
Revises: 65ed2134896e
Create Date: 2026-08-19 11:25:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7b1a2c3d4e5f'
down_revision: Union[str, None] = '65ed2134896e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Pure SQL migration to add operating_system column
    op.execute("ALTER TABLE assets ADD COLUMN operating_system VARCHAR;")


def downgrade() -> None:
    # Pure SQL migration to remove operating_system column
    op.execute("ALTER TABLE assets DROP COLUMN operating_system;")
