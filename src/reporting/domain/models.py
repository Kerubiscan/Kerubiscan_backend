from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class ReportBase(BaseModel):
    name: str
    type: str
    status: str = "Completed"
    company_id: Optional[str] = None

class ReportCreate(ReportBase):
    pass

class ReportResponse(BaseModel):
    id: str
    asset_id: str
    asset_name: str
    company_id: Optional[str]
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class ReportGenerationRequest(BaseModel):
    executive_summary: Optional[str] = None
    scanner_company_name: Optional[str] = "KERIBU SOC Security"
    target_company_name: Optional[str] = "Client Company"
    language: Optional[str] = "French"
    scan_profile: Optional[str] = "Audit de Sécurité Multi-Moteurs (Full Audit)"
    classification: Optional[str] = "CONFIDENTIEL - USAGE INTERNE"
