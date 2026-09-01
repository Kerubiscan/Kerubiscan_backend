from src.core.database import engine, Base
from src.companies.domain.entities import CompanyEntity
from src.scans.domain.entities import ScanEntity
from src.policies.domain.entities import PolicyEntity
from src.scheduling.domain.entities import ScheduleEntity
from src.reporting.domain.entities import ReportEntity
from src.assets.domain.entities import AssetEntity
from src.vulnerabilities.domain.entities import VulnerabilityEntity

Base.metadata.create_all(bind=engine)
print("Created tables successfully")
