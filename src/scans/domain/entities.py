from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum as SQLEnum, Boolean, JSON
from sqlalchemy.sql import func
import enum
import uuid
from src.core.database import Base

class ScanType(enum.Enum):
    DISCOVERY = "DISCOVERY"
    VULNERABILITY = "VULNERABILITY"

class ScannerEngine(enum.Enum):
    OPENVAS = "OPENVAS"
    NMAP = "NMAP"
    NUCLEI = "NUCLEI"
    NESSUS = "NESSUS"

class ScanStatus(enum.Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class ScanEntity(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    company_id = Column(String(36), ForeignKey("companies.id"), index=True, nullable=False)
    name = Column(String, nullable=False)
    target = Column(String, nullable=False)
    network_zone = Column(String, nullable=True)
    scan_type = Column(SQLEnum(ScanType), nullable=False)
    scanner_engine = Column(SQLEnum(ScannerEngine), default=ScannerEngine.OPENVAS, nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    progress = Column(Integer, default=0, nullable=False)
    vulnerabilities_found = Column(Integer, default=0, nullable=True)
    executive_summary = Column(String, nullable=True)
    target_states = Column(JSON, default=dict, nullable=False)
    recurrence_rule = Column(String, nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)
    is_deleted = Column(Boolean, default=False, nullable=False)

    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
