from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from typing import List, Optional

from src.core.database import get_db
from src.core.pagination import PaginationParams, PaginatedResponse
from src.auth.adapters.inbound.api.dependencies import require_permissions
from src.auth.domain.entities import Permission
from src.audit.adapters.outbound.audit_adapter import AuditService
from src.core.rate_limit import limiter

from src.assets.domain.models import AssetResponse, AssetCreate, AssetUpdate, AssetSummaryGenerateRequest, AssetReportRequest
from src.assets.adapters.outbound.repository import AssetRepository
from src.vulnerabilities.domain.entities import VulnerabilityEntity
from src.vulnerabilities.domain.models import VulnStatus
from src.ai.application.services.nlp import generate_executive_summary
from src.reporting.application.services.pdf_generator import generate_vulnerability_pdf
from fastapi.responses import StreamingResponse
import io

router = APIRouter()

def get_asset_repository(db: Session = Depends(get_db)) -> AssetRepository:
    return AssetRepository(db)

def get_audit_service(db: Session = Depends(get_db)) -> AuditService:
    return AuditService(db)

@router.get("", response_model=PaginatedResponse[AssetResponse])
@limiter.limit("50/minute")
async def get_assets(
    request: Request,
    company_id: Optional[str] = Query(None, description="Filter by company ID"),
    network_zone: Optional[str] = Query(None, description="Filter by network zone"),
    pagination: PaginationParams = Depends(),
    repo: AssetRepository = Depends(get_asset_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    skip = (pagination.page - 1) * pagination.size
    assets, total = repo.get_all(skip=skip, limit=pagination.size, company_id=company_id, network_zone=network_zone)
    
    pages = (total + pagination.size - 1) // pagination.size
    
    return PaginatedResponse(
        items=assets,
        total=total,
        page=pagination.page,
        size=pagination.size,
        pages=pages
    )

@router.get("/{asset_id}", response_model=AssetResponse)
@limiter.limit("50/minute")
async def get_asset(
    request: Request,
    asset_id: str,
    repo: AssetRepository = Depends(get_asset_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    asset = repo.get_by_id(asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset

@router.get("/{asset_id}/exposure")
@limiter.limit("50/minute")
async def get_asset_exposure(
    request: Request,
    asset_id: str,
    db: Session = Depends(get_db),
    repo: AssetRepository = Depends(get_asset_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    asset = repo.get_by_id(asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
        
    from src.vulnerabilities.domain.entities import VulnerabilityEntity
    from src.vulnerabilities.domain.models import VulnStatus
    from sqlalchemy import func
    
    # Simple cumulative view: count of vulnerabilities by first_detected_at
    results = db.query(
        func.date(VulnerabilityEntity.first_detected_at).label("date"),
        func.count(VulnerabilityEntity.id).label("count")
    ).filter(
        VulnerabilityEntity.asset_id == asset_id,
        VulnerabilityEntity.status != VulnStatus.FIXED
    ).group_by(func.date(VulnerabilityEntity.first_detected_at)).order_by("date").all()
    
    return [{"date": str(r.date), "count": r.count} for r in results]

@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_asset(
    request: Request,
    asset_in: AssetCreate,
    repo: AssetRepository = Depends(get_asset_repository),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.ASSET_WRITE]))
):
    # Prevent exact duplicates to avoid DB pollution during auto-discovery
    existing = repo.get_by_ip_and_name(str(asset_in.ip_address), asset_in.name)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An asset with this name and IP already exists")
        
    asset = repo.create(asset_in)
    
    audit.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="CREATE_ASSET",
        resource_type="Asset",
        resource_id=str(asset.id),
        details={"name": asset.name, "ip": asset.ip_address}
    )
    
    return asset

@router.put("/{asset_id}", response_model=AssetResponse)
@router.patch("/{asset_id}", response_model=AssetResponse)
@limiter.limit("20/minute")
async def update_asset(
    request: Request,
    asset_id: str,
    asset_in: AssetUpdate,
    repo: AssetRepository = Depends(get_asset_repository),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.ASSET_WRITE]))
):
    asset = repo.update(asset_id, asset_in)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
        
    from fastapi.encoders import jsonable_encoder
    audit.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="UPDATE_ASSET",
        resource_type="Asset",
        resource_id=str(asset.id),
        details=jsonable_encoder(asset_in.model_dump(exclude_unset=True))
    )
    
    return asset

@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("20/minute")
async def delete_asset(
    request: Request,
    asset_id: str,
    repo: AssetRepository = Depends(get_asset_repository),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.ASSET_DELETE]))
):
    success = repo.delete(asset_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
        
    audit.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="DELETE_ASSET",
        resource_type="Asset",
        resource_id=str(asset_id),
        details={"soft_delete": True}
    )
    
    return None

@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("5/minute")
async def delete_all_assets(
    request: Request,
    repo: AssetRepository = Depends(get_asset_repository),
    audit: AuditService = Depends(get_audit_service),
    current_user: dict = Depends(require_permissions([Permission.ASSET_DELETE]))
):
    count = repo.delete_all()
        
    audit.log_action(
        user_id=current_user.get("sub", "unknown"),
        username=current_user.get("preferred_username"),
        action="DELETE_ALL_ASSETS",
        resource_type="Asset",
        resource_id="ALL",
        details={"soft_delete": True, "count": count}
    )
    
    return None

@router.post("/{asset_id}/generate-summary", response_model=dict)
@limiter.limit("10/minute")
async def generate_asset_summary(
    request: Request,
    asset_id: str,
    req: AssetSummaryGenerateRequest,
    db: Session = Depends(get_db),
    repo: AssetRepository = Depends(get_asset_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    asset = repo.get_by_id(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    # Top 5 unresolved vulns
    vulns = db.query(VulnerabilityEntity).filter(
        VulnerabilityEntity.asset_id == asset_id,
        VulnerabilityEntity.status != VulnStatus.FIXED
    ).order_by(VulnerabilityEntity.contextual_risk_score.desc()).limit(5).all()
    
    vuln_data = [{"title": v.title, "cvss": v.cvss_base_score, "severity": getattr(v.severity, "name", str(v.severity))} for v in vulns]
    
    summary = await generate_executive_summary(vuln_data, language=req.language, extra_instructions=req.instructions)
    return {"executive_summary": summary}

@router.post("/{asset_id}/report/pdf")
@limiter.limit("5/minute")
async def download_asset_report(
    request: Request,
    asset_id: str,
    req: AssetReportRequest,
    db: Session = Depends(get_db),
    repo: AssetRepository = Depends(get_asset_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    asset = repo.get_by_id(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    # Get all unresolved vulns
    vulns = db.query(VulnerabilityEntity).filter(
        VulnerabilityEntity.asset_id == asset_id,
        VulnerabilityEntity.status != VulnStatus.FIXED
    ).all()
    
    pdf_bytes = generate_vulnerability_pdf(
        asset=asset,
        vulnerabilities=vulns,
        executive_summary=req.executive_summary,
        scanner_company_name=req.scanner_company,
        target_company_name=req.target_company
    )
    
    return StreamingResponse(
        io.BytesIO(pdf_bytes), 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename=rapport_{asset.name}.pdf"}
    )
