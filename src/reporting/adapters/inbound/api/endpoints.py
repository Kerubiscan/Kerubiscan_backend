from fastapi import APIRouter, Response, Depends, HTTPException, Query, Request
from src.core.database import get_db
from sqlalchemy.orm import Session
from src.assets.domain.entities import AssetEntity
from src.vulnerabilities.domain.entities import VulnerabilityEntity

from typing import Optional
from src.core.pagination import PaginationParams, PaginatedResponse
from src.auth.adapters.inbound.api.dependencies import require_permissions
from src.auth.domain.entities import Permission
from src.core.rate_limit import limiter
from src.reporting.domain.models import ReportResponse, ReportGenerationRequest
from src.reporting.adapters.outbound.repository import ReportRepository

router = APIRouter()

def get_report_repository(db: Session = Depends(get_db)) -> ReportRepository:
    return ReportRepository(db)

@router.get("", response_model=PaginatedResponse[ReportResponse])
@limiter.limit("50/minute")
async def get_reports(
    request: Request,
    company_id: Optional[str] = Query(None, description="Filter by company ID"),
    pagination: PaginationParams = Depends(),
    repo: ReportRepository = Depends(get_report_repository),
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

@router.post("/{asset_id}/pdf", response_class=Response)
async def generate_executive_report(
    asset_id: str, 
    request_data: ReportGenerationRequest,
    db: Session = Depends(get_db)
):
    asset = db.query(AssetEntity).filter(AssetEntity.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    vulnerabilities = db.query(VulnerabilityEntity).filter(VulnerabilityEntity.asset_id == asset_id).all()
    
    from src.reporting.application.services.pdf_generator import generate_vulnerability_pdf
    
    pdf_bytes = generate_vulnerability_pdf(
        asset=asset,
        vulnerabilities=vulnerabilities,
        executive_summary=request_data.executive_summary,
        scanner_company_name=request_data.scanner_company_name,
        target_company_name=request_data.target_company_name
    )
    
    return Response(content=pdf_bytes, media_type="application/pdf", headers={
        "Content-Disposition": f"attachment; filename=report_{asset.name.replace(' ', '_')}.pdf"
    })
