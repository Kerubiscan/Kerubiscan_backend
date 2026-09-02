from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class PolicyBase(BaseModel):
    name: str
    scan_type: str
    author: Optional[str] = None
    company_id: Optional[int] = None
    port_scanning_range: str = "1-65535"
    safe_checks: bool = True
    concurrent_hosts: int = 20
    concurrent_checks: int = 10

class PolicyCreate(PolicyBase):
    pass

class PolicyResponse(PolicyBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
