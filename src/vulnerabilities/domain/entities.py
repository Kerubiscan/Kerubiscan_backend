from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, Text, Enum as SQLEnum
from sqlalchemy.sql import func
from src.core.database import Base
from src.vulnerabilities.domain.models import VulnSeverity, VulnStatus

class VulnerabilityEntity(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(String, index=True, nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    
    cvss_base_score = Column(Float, nullable=True)
    cvss_vector = Column(String, nullable=True)
    contextual_risk_score = Column(Float, nullable=True)
    
    source_engine = Column(String, default="OPENVAS", nullable=False)
    
    severity = Column(SQLEnum(VulnSeverity), default=VulnSeverity.INFO, nullable=False)
    status = Column(SQLEnum(VulnStatus), default=VulnStatus.NEW, nullable=False)
    
    first_detected_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class VulnerabilityHistoryEntity(Base):
    __tablename__ = "vulnerability_history"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    previous_status = Column(SQLEnum(VulnStatus), nullable=False)
    new_status = Column(SQLEnum(VulnStatus), nullable=False)
    changed_by = Column(String, nullable=False)
    changed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
