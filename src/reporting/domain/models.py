from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class ReportBase(BaseModel):
    name: str
    type: str
    status: str = "Completed"
    company_id: Optional[int] = None

class ReportCreate(ReportBase):
    pass

class ReportResponse(BaseModel):
    id: int
    asset_id: int
    asset_name: str
    company_id: Optional[int]
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class ReportGenerationRequest(BaseModel):
    executive_summary: Optional[str] = None
    scanner_company_name: Optional[str] = "Kerubiscan Security"
    target_company_name: Optional[str] = "Client Company"
