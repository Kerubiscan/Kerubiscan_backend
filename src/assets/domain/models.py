from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum
from datetime import datetime

class CriticalityLevel(str, Enum):
    UNASSIGNED = "Unassigned"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class AssetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    ip_address: str = Field(..., description="IP Address or Hostname")
    company_id: Optional[str] = None
    criticality: CriticalityLevel = CriticalityLevel.UNASSIGNED
    environment: Optional[str] = Field(None, max_length=100)
    asset_type: Optional[str] = Field(None, max_length=100)
    network_zone: Optional[str] = Field(None, max_length=100)
    operating_system: Optional[str] = Field(None, max_length=100)
    cpe: Optional[str] = Field(None, max_length=255, description="Common Platform Enumeration string")
    description: Optional[str] = None
    ports: Optional[str] = None
    mac_address: Optional[str] = None

class AssetCreate(AssetBase):
    pass

class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    ip_address: Optional[str] = None
    criticality: Optional[CriticalityLevel] = None
    environment: Optional[str] = Field(None, max_length=100)
    asset_type: Optional[str] = Field(None, max_length=100)
    network_zone: Optional[str] = Field(None, max_length=100)
    operating_system: Optional[str] = Field(None, max_length=100)
    cpe: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    ports: Optional[str] = None
    mac_address: Optional[str] = None

class AssetResponse(AssetBase):
    id: str
    is_deleted: bool
    created_at: datetime
    updated_at: datetime
    last_scan_raw_output: Optional[str] = None

    class Config:
        from_attributes = True

class AssetSummaryGenerateRequest(BaseModel):
    language: str = "French"
    instructions: str = ""

class AssetReportRequest(BaseModel):
    executive_summary: str = ""
    scanner_company: str = "Kerubiscan Security"
    target_company: str = "Client Company"
