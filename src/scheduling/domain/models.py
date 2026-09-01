from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class ScheduleBase(BaseModel):
    name: str
    target: str
    frequency: str
    next_run: str
    status: str = "Active"
    company_id: Optional[int] = None
    scan_type: str = "VULNERABILITY"
    network_zone: Optional[str] = None
    scanner_engine: str = "OPENVAS"

class ScheduleCreate(ScheduleBase):
    pass

class ScheduleResponse(ScheduleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
