from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func
import uuid
from src.core.database import Base

class ReportEntity(Base):
    __tablename__ = "reports"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    company_id = Column(String(36), ForeignKey("companies.id"), nullable=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="Completed")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
