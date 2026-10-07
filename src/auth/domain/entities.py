from enum import Enum

class Permission(str, Enum):
    # Asset permissions
    ASSET_READ = "asset:read"
    ASSET_WRITE = "asset:write"
    ASSET_DELETE = "asset:delete"
    
    # Secret permissions
    SECRET_READ = "secret:read"
    SECRET_WRITE = "secret:write"
    SECRET_DELETE = "secret:delete"
    
    # Scan permissions (launching a scan is an offensive action on a target)
    SCAN_READ = "scan:read"
    SCAN_EXECUTE = "scan:execute"
    SCAN_DELETE = "scan:delete"

    # Audit permissions
    AUDIT_READ = "audit:read"
    
    # Auth/User permissions
    USER_READ = "user:read"
    USER_WRITE = "user:write"

class Role(str, Enum):
    READER = "Reader"
    SECURITY_ANALYST = "Security Analyst"
    SYSTEMS_ADMINISTRATOR = "Systems Administrator"
    ADMINISTRATOR = "Platform Administrator"
