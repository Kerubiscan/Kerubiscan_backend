"""scans.scan_depth: duration chosen at launch (RAPIDE, STANDARD, APPROFONDI)

Revision ID: e5f8a2c4d7b1
Revises: d4e7a1b9c2f6
Create Date: 2026-10-11 12:00:00.000000

Nullable: existing scans keep no value, which means STANDARD (their behaviour so far).
"""
from alembic import op
import sqlalchemy as sa

revision = 'e5f8a2c4d7b1'
down_revision = 'd4e7a1b9c2f6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('scan_depth', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('scans', 'scan_depth')
