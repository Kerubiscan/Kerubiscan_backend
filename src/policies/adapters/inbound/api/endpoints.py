from fastapi import APIRouter, Depends, Query, Request, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional

from src.core.database import get_db
from src.core.pagination import PaginationParams, PaginatedResponse
from src.auth.adapters.inbound.api.dependencies import require_permissions
from src.auth.domain.entities import Permission
from src.core.rate_limit import limiter

from src.policies.domain.models import PolicyResponse, PolicyCreate, PolicyUpdate
from src.policies.adapters.outbound.repository import PolicyRepository

router = APIRouter()

def get_policy_repository(db: Session = Depends(get_db)) -> PolicyRepository:
    return PolicyRepository(db)

@router.get("", response_model=PaginatedResponse[PolicyResponse])
@limiter.limit("50/minute")
async def get_policies(
    request: Request,
    company_id: Optional[str] = Query(None, description="Filter by company ID"),
    pagination: PaginationParams = Depends(),
    repo: PolicyRepository = Depends(get_policy_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    skip = (pagination.page - 1) * pagination.size
    items, total = repo.get_all(skip=skip, limit=pagination.size, company_id=company_id)
    pages = (total + pagination.size - 1) // pagination.size
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        size=pagination.size,
        pages=pages
    )

@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_policy(
    request: Request,
    policy_in: PolicyCreate,
    repo: PolicyRepository = Depends(get_policy_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_WRITE]))
):
    return repo.create(policy_in)

@router.put("/{policy_id}", response_model=PolicyResponse)
@limiter.limit("20/minute")
async def update_policy(
    request: Request,
    policy_id: str,
    policy_in: PolicyUpdate,
    repo: PolicyRepository = Depends(get_policy_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_WRITE]))
):
    entity = repo.update(policy_id, policy_in)
    if not entity:
        raise HTTPException(status_code=404, detail="Policy not found")
    return entity

@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("20/minute")
async def delete_policy(
    request: Request,
    policy_id: str,
    repo: PolicyRepository = Depends(get_policy_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_WRITE]))
):
    if not repo.delete(policy_id):
        raise HTTPException(status_code=404, detail="Policy not found")
