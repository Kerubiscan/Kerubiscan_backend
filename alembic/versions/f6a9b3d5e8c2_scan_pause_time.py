"""scans.paused_at / scans.paused_seconds: time spent paused, left out of the elapsed time

Revision ID: f6a9b3d5e8c2
Revises: e5f8a2c4d7b1
Create Date: 2026-10-13 10:00:00.000000

The elapsed time of a scan counted its pauses (17 h shown after a night paused). paused_at is the
start of the current pause, paused_seconds the total of the previous ones. Nullable: existing
scans were never paused with this accounting.
"""
from alembic import op
import sqlalchemy as sa

revision = 'f6a9b3d5e8c2'
down_revision = 'e5f8a2c4d7b1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('paused_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('scans', sa.Column('paused_seconds', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('scans', 'paused_seconds')
    op.drop_column('scans', 'paused_at')
