import uuid
import datetime
from typing import Optional
from pydantic import BaseModel

class AuditLogCreate(BaseModel):
    user_id: str
    username: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    details: Optional[dict] = None

class AuditLogResponse(AuditLogCreate):
    id: str
    timestamp: datetime.datetime

    class Config:
        from_attributes = True
