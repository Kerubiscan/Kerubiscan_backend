"""add_policy_and_credential_to_scans

Revision ID: 9e8d7c6b5a4f
Revises: 4df5bad16769
Create Date: 2026-09-13 11:04:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '9e8d7c6b5a4f'
down_revision: Union[str, None] = '4df5bad16769'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    try:
        op.add_column('scans', sa.Column('policy_id', sa.String(length=36), sa.ForeignKey('policies.id'), nullable=True))
    except Exception:
        pass
    try:
        op.add_column('scans', sa.Column('credential_id', sa.String(length=36), sa.ForeignKey('credentials.id'), nullable=True))
    except Exception:
        pass

def downgrade() -> None:
    try:
        op.drop_column('scans', 'credential_id')
    except Exception:
        pass
    try:
        op.drop_column('scans', 'policy_id')
    except Exception:
        pass
