from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional
from src.auth.adapters.outbound.keycloak_admin_adapter import KeycloakAdminAdapter
from src.auth.adapters.inbound.api.dependencies import get_current_user

# Assuming get_current_user extracts token roles and we can enforce 'Platform Administrator'

router = APIRouter(prefix="/admin/users", tags=["Admin Users"])
admin_adapter = KeycloakAdminAdapter()

class UserCreate(BaseModel):
    username: str
    email: str
    first_name: str
    last_name: str
    enabled: bool = True
    role: Optional[str] = None
    password: Optional[str] = None

class RoleAssign(BaseModel):
    role_name: str

@router.get("")
def list_users(current_user: dict = Depends(get_current_user)):
    # Basic role check
    realm_access = current_user.get("realm_access", {}).get("roles", [])
    if "Platform Administrator" not in realm_access:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    users = admin_adapter.get_users()
    return users

@router.post("")
def create_user(user: UserCreate, current_user: dict = Depends(get_current_user)):
    realm_access = current_user.get("realm_access", {}).get("roles", [])
    if "Platform Administrator" not in realm_access:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    try:
        user_id = admin_adapter.create_user(
            username=user.username,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            enabled=user.enabled,
            password=user.password
        )
        if user.role:
            admin_adapter.assign_role(user_id, user.role)
            
        # TODO: Log this action in Audit module
        
        return {"id": user_id, "message": "User created successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/{user_id}/roles")
def assign_role(user_id: str, role: RoleAssign, current_user: dict = Depends(get_current_user)):
    realm_access = current_user.get("realm_access", {}).get("roles", [])
    if "Platform Administrator" not in realm_access:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    try:
        admin_adapter.assign_role(user_id, role.role_name)
        # TODO: Log this action in Audit module
        return {"message": "Role assigned successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
