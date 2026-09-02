from src.core.database import engine, Base
from sqlalchemy import MetaData
import importlib
import pkgutil
from sqlalchemy.schema import DropTable
from sqlalchemy.ext.compiler import compiles

@compiles(DropTable, "postgresql")
def _compile_drop_table(element, compiler, **kwargs):
    return compiler.visit_drop_table(element) + " CASCADE"

# Import all models to ensure they are registered with Base.metadata
from src.companies.domain.entities import CompanyEntity
from src.assets.domain.entities import AssetEntity
from src.scans.domain.entities import ScanEntity
from src.vulnerabilities.domain.entities import VulnerabilityEntity, VulnerabilityHistory
from src.audit.domain.models import AuditLog
from src.scheduling.domain.entities import ScheduleEntity

Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)
print("Database cleared and recreated successfully.")
