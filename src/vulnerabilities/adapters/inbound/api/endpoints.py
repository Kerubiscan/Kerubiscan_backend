from fastapi import APIRouter, Depends, Query, Request, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional

from src.core.database import get_db
from src.core.pagination import PaginationParams, PaginatedResponse
from src.auth.adapters.inbound.api.dependencies import require_permissions
from src.auth.domain.entities import Permission
from src.core.rate_limit import limiter

from src.vulnerabilities.domain.models import VulnerabilityResponse, VulnStatusUpdate, VulnerabilityHistoryResponse
from src.vulnerabilities.adapters.outbound.repository import VulnerabilityRepository
from src.audit.adapters.outbound.audit_adapter import AuditService
from typing import List

router = APIRouter()

def get_vuln_repository(db: Session = Depends(get_db)) -> VulnerabilityRepository:
    return VulnerabilityRepository(db)

def get_audit_service(db: Session = Depends(get_db)) -> AuditService:
    return AuditService(db)

@router.get("", response_model=PaginatedResponse[VulnerabilityResponse])
@limiter.limit("50/minute")
async def get_vulnerabilities(
    request: Request,
    company_id: Optional[str] = Query(None, description="Filter by company ID"),
    network_zone: Optional[str] = Query(None, description="Filter by network zone"),
    asset_id: Optional[str] = Query(None, description="Filter by asset ID"),
    pagination: PaginationParams = Depends(),
    repo: VulnerabilityRepository = Depends(get_vuln_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    skip = (pagination.page - 1) * pagination.size
    vulns, total = repo.get_all(skip=skip, limit=pagination.size, company_id=company_id, network_zone=network_zone, asset_id=asset_id)
    
    pages = (total + pagination.size - 1) // pagination.size
    
    return PaginatedResponse(
        items=vulns,
        total=total,
        page=pagination.page,
        size=pagination.size,
        pages=pages
    )

@router.patch("/{vuln_id}/status", response_model=VulnerabilityResponse)
@limiter.limit("20/minute")
async def update_vulnerability_status(
    request: Request,
    vuln_id: str,
    status_update: VulnStatusUpdate,
    repo: VulnerabilityRepository = Depends(get_vuln_repository),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.ASSET_WRITE]))
):
    username = current_user.get("preferred_username") or current_user.get("sub") or "System"
    vuln = repo.update_status(vuln_id, status_update.status, changed_by=username)
    
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
        
    audit.log_action(
        user_id=current_user.get("sub", "system"),
        username=username,
        action="VULNERABILITY_STATUS_UPDATED",
        resource_type="Vulnerabilities",
        resource_id=str(vuln_id),
        details={"new_status": status_update.status.value},
        ip_address=request.client.host if request.client else None
    )
        
    return vuln

@router.get("/{vuln_id}/history", response_model=List[VulnerabilityHistoryResponse])
@limiter.limit("20/minute")
async def get_vulnerability_history(
    request: Request,
    vuln_id: str,
    repo: VulnerabilityRepository = Depends(get_vuln_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    history = repo.get_history(vuln_id)
    return history
