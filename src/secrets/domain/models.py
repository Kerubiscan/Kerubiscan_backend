from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum
from datetime import datetime

class CredentialType(str, Enum):
    SSH = "SSH"
    SMB = "SMB"
    SNMPV2 = "SNMPv2"
    SNMPV3 = "SNMPv3"
    HTTP = "HTTP"
    DATABASE = "DATABASE"
    AWS = "AWS"

class CredentialBase(BaseModel):
    name: str = Field(..., max_length=255, description="A friendly name for this credential")
    asset_id: int = Field(..., description="The ID of the asset this credential belongs to")
    credential_type: CredentialType

# ----- CREATION SCHEMAS (These accept plain-text secrets, but never return them) -----

class SSHCredentialCreate(CredentialBase):
    credential_type: CredentialType = CredentialType.SSH
    username: str
    password: Optional[str] = None
    private_key: Optional[str] = None
    passphrase: Optional[str] = None
    port: int = 22

class SMBCredentialCreate(CredentialBase):
    credential_type: CredentialType = CredentialType.SMB
    username: str
    password: str
    domain: Optional[str] = None

class SNMPv2CredentialCreate(CredentialBase):
    credential_type: CredentialType = CredentialType.SNMPV2
    community_string: str

class SNMPv3CredentialCreate(CredentialBase):
    credential_type: CredentialType = CredentialType.SNMPV3
    username: str
    auth_password: Optional[str] = None
    priv_password: Optional[str] = None

# ----- RESPONSE SCHEMAS -----

class HTTPBasicAuthCredentialCreate(CredentialBase):
    credential_type: CredentialType = CredentialType.HTTP
    username: str
    password: str

class DatabaseCredentialCreate(CredentialBase):
    credential_type: CredentialType = CredentialType.DATABASE
    username: str
    password: str
    db_name: Optional[str] = None
    port: int

class AWSCredentialCreate(CredentialBase):
    credential_type: CredentialType = CredentialType.AWS
    access_key_id: str
    secret_access_key: str


class CredentialResponse(BaseModel):
    id: int
    name: str
    asset_id: int
    credential_type: CredentialType
    vault_path: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
