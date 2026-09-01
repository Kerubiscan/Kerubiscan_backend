from typing import List, Callable
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from src.auth.ports.outbound.token_decoder import TokenDecoderPort
from src.auth.adapters.outbound.keycloak_adapter import KeycloakAdapter
from src.auth.domain.entities import Permission
from src.auth.application.services.rbac_service import RBACService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_token_decoder() -> TokenDecoderPort:
    return KeycloakAdapter()

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    decoder = get_token_decoder()
    user_data = decoder.decode_token(token)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user_data

def require_permissions(required_permissions: List[Permission]) -> Callable:
    def permission_checker(current_user: dict = Depends(get_current_user)):
        roles = current_user.get("realm_access", {}).get("roles", [])
        user_permissions = RBACService.resolve_permissions(roles)
        if not all(p in user_permissions for p in required_permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user
    return permission_checker

def require_role(allowed_roles: List[str]) -> Callable:
    """Legacy role checker."""
    def role_checker(current_user: dict = Depends(get_current_user)):
        user_roles = current_user.get("realm_access", {}).get("roles", [])
        if not any(role in allowed_roles for role in user_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user
    return role_checker
