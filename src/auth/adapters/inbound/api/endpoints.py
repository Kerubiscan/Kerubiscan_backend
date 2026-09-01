from fastapi import APIRouter, Depends, Request
from typing import List
from sqlalchemy.orm import Session

from src.core.rate_limit import limiter
from src.core.database import get_db
from src.auth.adapters.inbound.api.dependencies import get_current_user
from src.auth.application.services.rbac_service import RBACService
from src.audit.adapters.outbound.audit_adapter import AuditService

router = APIRouter()

@router.get("/me", response_model=dict)
@limiter.limit("20/minute")
async def get_current_user_permissions(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get the current user's details and resolved permissions.
    """
    realm_access = current_user.get("realm_access", {})
    user_roles = realm_access.get("roles", [])
    
    # Resolve permissions
    user_permissions = RBACService.resolve_permissions(user_roles)
    
    # Audit log
    audit_svc = AuditService(db)
    audit_svc.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="USER_LOGIN_SESSION",
        resource_type="User",
        resource_id=current_user.get("sub", "unknown"),
        details={"roles": user_roles}
    )
    
    return {
        "user": {
            "sub": current_user.get("sub"),
            "preferred_username": current_user.get("preferred_username"),
            "roles": user_roles
        },
        "permissions": [perm.value for perm in user_permissions]
    }
