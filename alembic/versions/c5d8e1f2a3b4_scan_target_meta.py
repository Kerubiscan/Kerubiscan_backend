"""scans.target_meta: per-target timestamps, failure reason and engine task id

Revision ID: c5d8e1f2a3b4
Revises: b7e4c2a9d1f0
Create Date: 2026-10-08 10:00:00.000000

Without it a target whose follow-up was lost (worker restart, OpenVAS queue, Celery time limit)
stayed IN_PROGRESS forever, and the reason of a failure was only in the worker logs.
"""
from alembic import op
import sqlalchemy as sa

revision = 'c5d8e1f2a3b4'
down_revision = 'b7e4c2a9d1f0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('target_meta', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('scans', 'target_meta')
