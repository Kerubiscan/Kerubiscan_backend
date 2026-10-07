"""Test setup: an SQLite database replaces PostgreSQL and no scanner binary is executed."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_DB_FILE = Path(tempfile.mkdtemp(prefix="kvs_tests_")) / "test.db"
os.environ["POSTGRES_URL"] = f"sqlite:///{_DB_FILE.as_posix()}"
os.environ.setdefault("REDIS_URL", "memory://")

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def db():
    from src.core.database import Base, engine, SessionLocal
    # Import every entity so that create_all knows all the tables
    from src.companies.domain.entities import CompanyEntity  # noqa: F401
    from src.scans.domain.entities import ScanEntity  # noqa: F401
    from src.assets.domain.entities import AssetEntity  # noqa: F401
    from src.vulnerabilities.domain.entities import VulnerabilityEntity  # noqa: F401
    from src.audit.domain.models import AuditLog  # noqa: F401
    from src.scheduling.domain.entities import ScheduleEntity  # noqa: F401
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture()
def company(db):
    from src.companies.domain.entities import CompanyEntity
    c = CompanyEntity(name="ACME")
    db.add(c)
    db.commit()
    return c


@pytest.fixture()
def make_scan(db, company):
    from src.scans.domain.entities import ScanEntity, ScanType, ScanStatus, ScannerEngine

    def _make(target: str, engine: str = "NUCLEI"):
        targets = [t.strip() for t in target.split(",")]
        scan = ScanEntity(company_id=company.id, name="test", target=target, scan_type=ScanType.VULNERABILITY,
                          scanner_engine=ScannerEngine[engine], status=ScanStatus.IN_PROGRESS,
                          target_states={t: "PENDING" for t in targets})
        db.add(scan)
        db.commit()
        return scan.id
    return _make


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")
