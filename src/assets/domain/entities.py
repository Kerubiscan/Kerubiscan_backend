from sqlalchemy import Column, Integer, String, Boolean, Enum as SQLEnum, Text, DateTime, ForeignKey
from sqlalchemy.sql import func
import uuid
from src.core.database import Base
from src.assets.domain.models import CriticalityLevel

class AssetEntity(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    name = Column(String, index=True, nullable=False)
    ip_address = Column(String, index=True, nullable=False)
    company_id = Column(String(36), ForeignKey("companies.id"), index=True, nullable=True)
    criticality = Column(SQLEnum(CriticalityLevel), default=CriticalityLevel.UNASSIGNED, nullable=False)
    environment = Column(String, nullable=True)
    asset_type = Column(String, nullable=True)
    network_zone = Column(String, nullable=True)
    operating_system = Column(String, nullable=True)
    cpe = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    ports = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)
    last_scan_raw_output = Column(Text, nullable=True)
    
    is_deleted = Column(Boolean, default=False, nullable=False, index=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
