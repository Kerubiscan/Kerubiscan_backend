from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.sql import func
from src.core.database import Base

class PolicyEntity(Base):
    __tablename__ = "policies"
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    name = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)
    author = Column(String, nullable=True)
    port_scanning_range = Column(String, default="1-65535", nullable=False)
    safe_checks = Column(Boolean, default=True, nullable=False)
    concurrent_hosts = Column(Integer, default=20, nullable=False)
    concurrent_checks = Column(Integer, default=10, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
