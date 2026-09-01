"""create_vulnerabilities_table

Revision ID: 8c2b3d4e5f6g
Revises: 7b1a2c3d4e5f
Create Date: 2026-08-19 11:30:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '8c2b3d4e5f6g'
down_revision: Union[str, None] = '7b1a2c3d4e5f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Pure SQL migration to create vulnerabilities table
    op.execute("""
    CREATE TABLE vulnerabilities (
        id SERIAL PRIMARY KEY,
        asset_id INTEGER NOT NULL,
        cve_id VARCHAR,
        title VARCHAR NOT NULL,
        description TEXT,
        remediation TEXT,
        cvss_base_score FLOAT,
        cvss_vector VARCHAR,
        contextual_risk_score FLOAT,
        severity VARCHAR NOT NULL DEFAULT 'Info',
        status VARCHAR NOT NULL DEFAULT 'New',
        first_detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
        last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
        CONSTRAINT fk_vulnerabilities_asset_id FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
    );
    CREATE INDEX idx_vulnerabilities_asset_id ON vulnerabilities(asset_id);
    CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
    """)


def downgrade() -> None:
    # Pure SQL migration to drop vulnerabilities table
    op.execute("DROP TABLE vulnerabilities;")
