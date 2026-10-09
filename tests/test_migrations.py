"""Migrations tested on a SYNTHETIC old-version PostgreSQL schema.

The enum swap (NESSUS -> OWASP_ZAP) is PostgreSQL-specific and cannot run on SQLite, so this test
is skipped unless TEST_POSTGRES_URL points at a THROWAWAY database. Never point it at the recette
database: this test creates and drops schema objects.

    createdb kvs_migtest
    TEST_POSTGRES_URL=postgresql://user:pass@localhost:5432/kvs_migtest \
        python -m pytest tests/test_migrations.py -v
"""
import os

import pytest

PG_URL = os.getenv("TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set TEST_POSTGRES_URL (throwaway PostgreSQL) to run migration tests")


@pytest.fixture()
def old_schema_db():
    from sqlalchemy import create_engine, text
    engine = create_engine(PG_URL)
    with engine.begin() as c:
        # Minimal old-version schema: companies, scans (enum with NESSUS), schedules
        c.execute(text("DROP TABLE IF EXISTS scans, schedules, assets, audit_logs CASCADE"))
        c.execute(text("DROP TYPE IF EXISTS scannerengine, scantype, scanstatus CASCADE"))
        c.execute(text("CREATE TYPE scannerengine AS ENUM ('OPENVAS','NMAP','NUCLEI','NESSUS')"))
        c.execute(text("CREATE TYPE scantype AS ENUM ('DISCOVERY','VULNERABILITY','WEB_APP')"))
        c.execute(text("CREATE TYPE scanstatus AS ENUM ('PENDING','IN_PROGRESS','PAUSED','COMPLETED','FAILED')"))
        c.execute(text("""CREATE TABLE scans (
            id varchar(36) PRIMARY KEY, company_id varchar(36), name varchar, target varchar,
            scan_type scantype, scanner_engine scannerengine DEFAULT 'OPENVAS',
            status scanstatus DEFAULT 'PENDING', progress int DEFAULT 0, is_deleted boolean DEFAULT false,
            created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now())"""))
        c.execute(text("""CREATE TABLE schedules (
            id varchar(36) PRIMARY KEY, target varchar, scanner_engine varchar DEFAULT 'OPENVAS',
            status varchar DEFAULT 'Active')"""))
        c.execute(text("""CREATE TABLE assets (
            id varchar(36) PRIMARY KEY, name varchar, ip_address varchar,
            updated_at timestamptz DEFAULT now())"""))
        c.execute(text("INSERT INTO scans (id, name, target, scan_type, scanner_engine, status) "
                       "VALUES ('s-nessus','old','1.2.3.4','VULNERABILITY','NESSUS','COMPLETED')"))
        c.execute(text("INSERT INTO schedules (id, target, scanner_engine) VALUES ('sch-nessus','1.2.3.4','NESSUS')"))
        # Stamp alembic at the revision just before this branch's migrations
        c.execute(text("CREATE TABLE IF NOT EXISTS alembic_version (version_num varchar(32) PRIMARY KEY)"))
        c.execute(text("DELETE FROM alembic_version"))
        c.execute(text("INSERT INTO alembic_version VALUES ('e123a3b61bf0')"))
    yield engine
    engine.dispose()


def test_upgrade_removes_nessus_and_adds_columns(old_schema_db, monkeypatch):
    from sqlalchemy import text
    import alembic.config
    import alembic.command
    monkeypatch.setenv("POSTGRES_URL", PG_URL)
    cfg = alembic.config.Config("alembic.ini")
    alembic.command.upgrade(cfg, "head")

    with old_schema_db.begin() as c:
        engines = [r[0] for r in c.execute(text(
            "SELECT unnest(enum_range(NULL::scannerengine))::text"))]
        assert "OWASP_ZAP" in engines and "NESSUS" not in engines
        # The NESSUS scan was soft-deleted and its engine reset
        row = c.execute(text("SELECT is_deleted, scanner_engine::text FROM scans WHERE id='s-nessus'")).one()
        assert row[0] is True and row[1] == "OPENVAS"
        assert c.execute(text("SELECT status FROM schedules WHERE id='sch-nessus'")).scalar() == "Paused"
        # New columns exist
        cols = [r[0] for r in c.execute(text(
            "SELECT column_name FROM information_schema.columns WHERE table_name='assets'"))]
        assert "resolved_ip" in cols
        scan_cols = [r[0] for r in c.execute(text(
            "SELECT column_name FROM information_schema.columns WHERE table_name='scans'"))]
        assert "target_meta" in scan_cols
        vuln_cols = [r[0] for r in c.execute(text(
            "SELECT column_name FROM information_schema.columns WHERE table_name='vulnerabilities'"))]
        assert "rule_id" in vuln_cols
