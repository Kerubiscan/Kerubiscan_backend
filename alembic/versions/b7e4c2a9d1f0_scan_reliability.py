"""scan reliability: assets.resolved_ip, scanner engines without NESSUS and with OWASP_ZAP

Revision ID: b7e4c2a9d1f0
Revises: e123a3b61bf0
Create Date: 2026-10-07 10:00:00.000000

- assets.resolved_ip keeps the IP of a scanned domain without overwriting the domain.
- The `scannerengine` PostgreSQL enum created by a93e432317eb never contained OWASP_ZAP
  (only databases initialised with create_all had it) and still contained NESSUS, which is
  no longer part of the project. Existing NESSUS scans never produced results: they are
  soft-deleted, and NESSUS schedules are paused.
"""
from alembic import op
import sqlalchemy as sa

revision = 'b7e4c2a9d1f0'
down_revision = 'e123a3b61bf0'
branch_labels = None
depends_on = None

NEW_ENGINES = "('OPENVAS', 'NMAP', 'NUCLEI', 'OWASP_ZAP')"
OLD_ENGINES = "('OPENVAS', 'NMAP', 'NUCLEI', 'NESSUS', 'OWASP_ZAP')"


def _swap_engine_enum(values: str) -> None:
    op.execute("ALTER TYPE scannerengine RENAME TO scannerengine_old")
    op.execute(f"CREATE TYPE scannerengine AS ENUM {values}")
    op.execute("ALTER TABLE scans ALTER COLUMN scanner_engine DROP DEFAULT")
    op.execute("ALTER TABLE scans ALTER COLUMN scanner_engine TYPE scannerengine USING scanner_engine::text::scannerengine")
    op.execute("ALTER TABLE scans ALTER COLUMN scanner_engine SET DEFAULT 'OPENVAS'")
    op.execute("DROP TYPE scannerengine_old")


def upgrade() -> None:
    op.add_column('assets', sa.Column('resolved_ip', sa.String(), nullable=True))

    op.execute("UPDATE scans SET is_deleted = true, scanner_engine = 'OPENVAS' WHERE scanner_engine::text = 'NESSUS'")
    op.execute("UPDATE schedules SET status = 'Paused', scanner_engine = 'OPENVAS' WHERE scanner_engine = 'NESSUS'")
    _swap_engine_enum(NEW_ENGINES)


def downgrade() -> None:
    _swap_engine_enum(OLD_ENGINES)
    op.drop_column('assets', 'resolved_ip')
