from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func
import uuid
from src.core.database import Base

class ScheduleEntity(Base):
    __tablename__ = "schedules"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    company_id = Column(String(36), ForeignKey("companies.id"), nullable=True)
    name = Column(String, nullable=False)
    target = Column(String, nullable=False)
    frequency = Column(String, nullable=False)
    next_run = Column(String, nullable=False)
    status = Column(String, default="Active")
    scan_type = Column(String, default="VULNERABILITY", nullable=False)
    network_zone = Column(String, nullable=True)
    scanner_engine = Column(String, default="OPENVAS", nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
