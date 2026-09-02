from pydantic import BaseModel
from typing import Optional
from enum import Enum
from datetime import datetime

class VulnSeverity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class VulnStatus(str, Enum):
    NEW = "New"
    IN_PROGRESS = "In Progress"
    FIXED = "Fixed"
    FALSE_POSITIVE = "False Positive"
    RISK_ACCEPTED = "Risk Accepted"

class VulnerabilityBase(BaseModel):
    asset_id: str
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    remediation: Optional[str] = None
    cvss_base_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    contextual_risk_score: Optional[float] = None
    source_engine: Optional[str] = None
    severity: VulnSeverity = VulnSeverity.INFO
    status: VulnStatus = VulnStatus.NEW

class VulnerabilityResponse(VulnerabilityBase):
    id: str
    first_detected_at: datetime
    last_seen_at: datetime

    class Config:
        from_attributes = True

class VulnStatusUpdate(BaseModel):
    status: VulnStatus

class VulnerabilityHistoryResponse(BaseModel):
    id: str
    vulnerability_id: str
    previous_status: VulnStatus
    new_status: VulnStatus
    changed_by: str
    changed_at: datetime

    class Config:
        from_attributes = True
