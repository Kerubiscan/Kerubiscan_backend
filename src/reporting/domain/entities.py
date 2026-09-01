from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func
from src.core.database import Base

class ReportEntity(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="Completed")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
