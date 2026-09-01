import uuid
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List

from src.core.database import get_db
from src.core.rate_limit import limiter
from src.auth.adapters.inbound.api.dependencies import require_permissions
from src.auth.domain.entities import Permission
from src.audit.adapters.outbound.audit_adapter import AuditService

from src.assets.adapters.outbound.repository import AssetRepository
from src.secrets.adapters.outbound.repository import CredentialRepository
from src.secrets.adapters.outbound.vault import VaultAdapter
from src.secrets.domain.models import (
    SSHCredentialCreate, 
    SMBCredentialCreate, 
    SNMPv2CredentialCreate, 
    SNMPv3CredentialCreate,
    HTTPBasicAuthCredentialCreate,
    DatabaseCredentialCreate,
    AWSCredentialCreate,
    CredentialResponse
)

router = APIRouter()

def get_credential_repository(db: Session = Depends(get_db)) -> CredentialRepository:
    return CredentialRepository(db)

def get_asset_repository(db: Session = Depends(get_db)) -> AssetRepository:
    return AssetRepository(db)

def get_audit_service(db: Session = Depends(get_db)) -> AuditService:
    return AuditService(db)

def get_vault_adapter() -> VaultAdapter:
    return VaultAdapter()

from src.core.pagination import PaginationParams, PaginatedResponse

# Define strict role: ONLY Systems Administrator can manage secrets
# (This is now managed via Permission.SECRET_WRITE in the RBAC service)

@router.get("", response_model=PaginatedResponse[CredentialResponse])
@limiter.limit("50/minute")
async def get_credentials(
    request: Request,
    pagination: PaginationParams = Depends(),
    repo: CredentialRepository = Depends(get_credential_repository),
    current_user: dict = Depends(require_permissions([Permission.SECRET_WRITE]))
):
    skip = (pagination.page - 1) * pagination.size
    items, total = repo.get_all(skip=skip, limit=pagination.size)
    pages = (total + pagination.size - 1) // pagination.size
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        size=pagination.size,
        pages=pages
    )

@router.post("/ssh", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_ssh_credential(
    request: Request,
    cred_in: SSHCredentialCreate,
    repo: CredentialRepository = Depends(get_credential_repository),
    asset_repo: AssetRepository = Depends(get_asset_repository),
    vault: VaultAdapter = Depends(get_vault_adapter),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.SECRET_WRITE]))
):
    # Verify asset exists
    asset = asset_repo.get_by_id(cred_in.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Generate unique Vault path
    vault_path = f"kimia/assets/{cred_in.asset_id}/ssh/{uuid.uuid4()}"
    
    # Store plain-text in Vault (exclude non-sensitive metadata from vault if desired, but storing all is fine)
    secret_data = cred_in.model_dump(exclude={"name", "asset_id", "credential_type"})
    success = vault.store_secret(vault_path, secret_data)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to securely store credential in Vault")

    # Store metadata in PostgreSQL
    cred_entity = repo.create(
        name=cred_in.name,
        asset_id=cred_in.asset_id,
        credential_type=cred_in.credential_type,
        vault_path=vault_path
    )

    audit.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="CREATE_SSH_CREDENTIAL",
        resource_type="Credential",
        resource_id=str(cred_entity.id),
        details={"asset_id": cred_in.asset_id, "name": cred_in.name}
    )

    return cred_entity


@router.post("/smb", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_smb_credential(
    request: Request,
    cred_in: SMBCredentialCreate,
    repo: CredentialRepository = Depends(get_credential_repository),
    asset_repo: AssetRepository = Depends(get_asset_repository),
    vault: VaultAdapter = Depends(get_vault_adapter),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.SECRET_WRITE]))
):
    asset = asset_repo.get_by_id(cred_in.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    vault_path = f"kimia/assets/{cred_in.asset_id}/smb/{uuid.uuid4()}"
    secret_data = cred_in.model_dump(exclude={"name", "asset_id", "credential_type"})
    
    if not vault.store_secret(vault_path, secret_data):
        raise HTTPException(status_code=500, detail="Failed to securely store credential in Vault")

    cred_entity = repo.create(
        name=cred_in.name,
        asset_id=cred_in.asset_id,
        credential_type=cred_in.credential_type,
        vault_path=vault_path
    )

    audit.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="CREATE_SMB_CREDENTIAL",
        resource_type="Credential",
        resource_id=str(cred_entity.id),
        details={"asset_id": cred_in.asset_id, "name": cred_in.name}
    )
    return cred_entity


@router.post("/snmpv2", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_snmpv2_credential(
    request: Request,
    cred_in: SNMPv2CredentialCreate,
    repo: CredentialRepository = Depends(get_credential_repository),
    asset_repo: AssetRepository = Depends(get_asset_repository),
    vault: VaultAdapter = Depends(get_vault_adapter),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.SECRET_WRITE]))
):
    asset = asset_repo.get_by_id(cred_in.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    vault_path = f"kimia/assets/{cred_in.asset_id}/snmpv2/{uuid.uuid4()}"
    secret_data = cred_in.model_dump(exclude={"name", "asset_id", "credential_type"})
    
    if not vault.store_secret(vault_path, secret_data):
        raise HTTPException(status_code=500, detail="Failed to securely store credential in Vault")

    cred_entity = repo.create(
        name=cred_in.name,
        asset_id=cred_in.asset_id,
        credential_type=cred_in.credential_type,
        vault_path=vault_path
    )

    audit.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="CREATE_SNMPV2_CREDENTIAL",
        resource_type="Credential",
        resource_id=str(cred_entity.id),
        details={"asset_id": cred_in.asset_id, "name": cred_in.name}
    )
    return cred_entity


@router.post("/snmpv3", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_snmpv3_credential(
    request: Request,
    cred_in: SNMPv3CredentialCreate,
    repo: CredentialRepository = Depends(get_credential_repository),
    asset_repo: AssetRepository = Depends(get_asset_repository),
    vault: VaultAdapter = Depends(get_vault_adapter),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.SECRET_WRITE]))
):
    asset = asset_repo.get_by_id(cred_in.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    vault_path = f"kimia/assets/{cred_in.asset_id}/snmpv3/{uuid.uuid4()}"
    secret_data = cred_in.model_dump(exclude={"name", "asset_id", "credential_type"})
    
    if not vault.store_secret(vault_path, secret_data):
        raise HTTPException(status_code=500, detail="Failed to securely store credential in Vault")

    cred_entity = repo.create(
        name=cred_in.name,
        asset_id=cred_in.asset_id,
        credential_type=cred_in.credential_type,
        vault_path=vault_path
    )

    audit.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="CREATE_SNMPV3_CREDENTIAL",
        resource_type="Credential",
        resource_id=str(cred_entity.id),
        details={"asset_id": cred_in.asset_id, "name": cred_in.name}
    )
    return cred_entity


@router.post("/http-basic", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_http_credential(
    request: Request,
    cred_in: HTTPBasicAuthCredentialCreate,
    repo: CredentialRepository = Depends(get_credential_repository),
    asset_repo: AssetRepository = Depends(get_asset_repository),
    vault: VaultAdapter = Depends(get_vault_adapter),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.SECRET_WRITE]))
):
    asset = asset_repo.get_by_id(cred_in.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    vault_path = f"kimia/assets/{cred_in.asset_id}/http/{uuid.uuid4()}"
    secret_data = cred_in.model_dump(exclude={"name", "asset_id", "credential_type"})
    
    if not vault.store_secret(vault_path, secret_data):
        raise HTTPException(status_code=500, detail="Failed to securely store credential in Vault")

    cred_entity = repo.create(
        name=cred_in.name,
        asset_id=cred_in.asset_id,
        credential_type=cred_in.credential_type,
        vault_path=vault_path
    )

    audit.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="CREATE_HTTP_CREDENTIAL",
        resource_type="Credential",
        resource_id=str(cred_entity.id),
        details={"asset_id": cred_in.asset_id, "name": cred_in.name}
    )
    return cred_entity


@router.post("/database", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_database_credential(
    request: Request,
    cred_in: DatabaseCredentialCreate,
    repo: CredentialRepository = Depends(get_credential_repository),
    asset_repo: AssetRepository = Depends(get_asset_repository),
    vault: VaultAdapter = Depends(get_vault_adapter),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.SECRET_WRITE]))
):
    asset = asset_repo.get_by_id(cred_in.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    vault_path = f"kimia/assets/{cred_in.asset_id}/database/{uuid.uuid4()}"
    secret_data = cred_in.model_dump(exclude={"name", "asset_id", "credential_type"})
    
    if not vault.store_secret(vault_path, secret_data):
        raise HTTPException(status_code=500, detail="Failed to securely store credential in Vault")

    cred_entity = repo.create(
        name=cred_in.name,
        asset_id=cred_in.asset_id,
        credential_type=cred_in.credential_type,
        vault_path=vault_path
    )

    audit.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="CREATE_DATABASE_CREDENTIAL",
        resource_type="Credential",
        resource_id=str(cred_entity.id),
        details={"asset_id": cred_in.asset_id, "name": cred_in.name}
    )
    return cred_entity


@router.post("/aws", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_aws_credential(
    request: Request,
    cred_in: AWSCredentialCreate,
    repo: CredentialRepository = Depends(get_credential_repository),
    asset_repo: AssetRepository = Depends(get_asset_repository),
    vault: VaultAdapter = Depends(get_vault_adapter),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.SECRET_WRITE]))
):
    asset = asset_repo.get_by_id(cred_in.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    vault_path = f"kimia/assets/{cred_in.asset_id}/aws/{uuid.uuid4()}"
    secret_data = cred_in.model_dump(exclude={"name", "asset_id", "credential_type"})
    
    if not vault.store_secret(vault_path, secret_data):
        raise HTTPException(status_code=500, detail="Failed to securely store credential in Vault")

    cred_entity = repo.create(
        name=cred_in.name,
        asset_id=cred_in.asset_id,
        credential_type=cred_in.credential_type,
        vault_path=vault_path
    )

    audit.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="CREATE_AWS_CREDENTIAL",
        resource_type="Credential",
        resource_id=str(cred_entity.id),
        details={"asset_id": cred_in.asset_id, "name": cred_in.name}
    )
    return cred_entity


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("20/minute")
async def delete_credential(
    request: Request,
    credential_id: int,
    repo: CredentialRepository = Depends(get_credential_repository),
    vault: VaultAdapter = Depends(get_vault_adapter),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.SECRET_DELETE]))
):
    cred_entity = repo.get_by_id(credential_id)
    if not cred_entity:
        raise HTTPException(status_code=404, detail="Credential not found")
        
    # Delete from Vault first!
    if not vault.delete_secret(cred_entity.vault_path):
        raise HTTPException(status_code=500, detail="Failed to delete credential from Vault")
        
    # Then delete from Postgres
    if not repo.delete(credential_id):
        raise HTTPException(status_code=500, detail="Failed to delete credential reference from DB")
        
    audit.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="DELETE_CREDENTIAL",
        resource_type="Credential",
        resource_id=str(credential_id),
        details={"name": cred_entity.name}
    )
    return None
