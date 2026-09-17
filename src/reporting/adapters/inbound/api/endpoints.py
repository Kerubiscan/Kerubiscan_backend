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

async def enrich_vulnerabilities_with_ai(db: Session, vulnerabilities: list, language: str):
    import asyncio
    from src.ai.application.services.nlp import generate_vulnerability_remediation
    
    sorted_vulns = sorted(vulnerabilities, key=lambda x: x.cvss_base_score or 0.0, reverse=True)
    
    async def enrich(v):
        if not v.remediation or v.remediation.strip() == "":
            try:
                ai_rem = await generate_vulnerability_remediation(v.title, v.description or "", language)
                if ai_rem:
                    v.remediation = ai_rem
                    db.add(v)
            except Exception:
                pass

    # Enrich top 10 vulnerabilities concurrently to keep report generation reasonably fast
    await asyncio.gather(*(enrich(v) for v in sorted_vulns[:10]))
    db.commit()

@router.post("/{asset_id}/html", response_class=Response)
async def generate_executive_report_html(
    asset_id: str, 
    request_data: ReportGenerationRequest,
    db: Session = Depends(get_db)
):
    asset = db.query(AssetEntity).filter(AssetEntity.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    vulnerabilities = db.query(VulnerabilityEntity).filter(VulnerabilityEntity.asset_id == asset_id).all()
    
    # Generate missing AI remediations before creating the report
    await enrich_vulnerabilities_with_ai(db, vulnerabilities, request_data.language or "French")
    
    exec_summary = request_data.executive_summary
    if not exec_summary:
        from src.ai.application.services.nlp import generate_executive_summary
        vuln_dicts = [
            {
                "title": v.title,
                "severity": getattr(v.severity, "value", str(v.severity)),
                "cvss": v.cvss_base_score,
                "cve": v.cve_id
            } for v in vulnerabilities[:10]
        ]
        exec_summary = await generate_executive_summary(vuln_dicts, language=request_data.language or "French")

    from src.reporting.application.services.html_generator import generate_vulnerability_html
    
    html_bytes = generate_vulnerability_html(
        assets=[asset],
        all_vulnerabilities={str(asset.id): vulnerabilities},
        executive_summary=exec_summary,
        scanner_company_name=request_data.scanner_company_name or "KERIBU SOC Security",
        target_company_name=request_data.target_company_name or "Client Company",
        scan_name=f"Rapport d'Audit : {asset.name} ({asset.ip_address})",
        scan_profile=request_data.scan_profile or "Audit de Sécurité Multi-Moteurs (Full Audit)",
        classification=request_data.classification or "CONFIDENTIEL - USAGE INTERNE"
    )
    
    return Response(content=html_bytes, media_type="text/html", headers={
        "Content-Disposition": f"attachment; filename=report_{asset.name.replace(' ', '_')}.html"
    })

@router.post("/{asset_id}/pdf", response_class=Response)
async def generate_executive_report_pdf(
    asset_id: str, 
    request_data: ReportGenerationRequest,
    db: Session = Depends(get_db)
):
    asset = db.query(AssetEntity).filter(AssetEntity.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    vulnerabilities = db.query(VulnerabilityEntity).filter(VulnerabilityEntity.asset_id == asset_id).all()
    
    # Generate missing AI remediations before creating the report
    await enrich_vulnerabilities_with_ai(db, vulnerabilities, request_data.language or "French")
    
    exec_summary = request_data.executive_summary
    if not exec_summary:
        from src.ai.application.services.nlp import generate_executive_summary
        vuln_dicts = [
            {
                "title": v.title,
                "severity": getattr(v.severity, "value", str(v.severity)),
                "cvss": v.cvss_base_score,
                "cve": v.cve_id
            } for v in vulnerabilities[:10]
        ]
        exec_summary = await generate_executive_summary(vuln_dicts, language=request_data.language or "French")

    from src.reporting.application.services.pdf_generator import generate_vulnerability_pdf
    
    pdf_bytes = generate_vulnerability_pdf(
        asset=asset,
        vulnerabilities=vulnerabilities,
        executive_summary=exec_summary,
        scanner_company_name=request_data.scanner_company_name or "KERIBU SOC Security",
        target_company_name=request_data.target_company_name or "Client Company"
    )
    
    return Response(content=pdf_bytes, media_type="application/pdf", headers={
        "Content-Disposition": f"attachment; filename=report_{asset.name.replace(' ', '_')}.pdf"
    })
