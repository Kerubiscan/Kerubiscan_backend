from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from src.core.database import get_db
from src.companies.domain.entities import CompanyEntity
from src.scans.domain.entities import ScanEntity, ScanType, ScanStatus, ScannerEngine
from src.assets.domain.entities import AssetEntity
from src.auth.adapters.inbound.api.dependencies import get_current_user
from src.audit.domain.models import AuditLog
from typing import List, Optional

router = APIRouter()

class ScannerStatus(BaseModel):
    status: str
    scans_in_progress: int
    scheduled_scans: int
    last_scan_time: str

class CompanyResponse(BaseModel):
    id: str
    name: str
    class Config:
        from_attributes = True

class ScanCreateRequest(BaseModel):
    company_name: str
    target: str
    network_zone: Optional[str] = None
    scan_type: str # "DISCOVERY" or "VULNERABILITY"
    scanner_engine: str = "OPENVAS" # "OPENVAS", "NMAP", "NUCLEI", "NESSUS"
    scheduled_for: Optional[str] = None
    recurrence_rule: Optional[str] = None

class ScanUpdateRequest(BaseModel):
    name: Optional[str] = None
    target: Optional[str] = None
    network_zone: Optional[str] = None
    scanner_engine: Optional[str] = None

class ScanResponse(BaseModel):
    id: str
    company_id: str
    name: str
    target: str
    network_zone: Optional[str] = None
    scan_type: str
    scanner_engine: str
    status: str
    progress: int = 0
    executive_summary: Optional[str] = None
    recurrence_rule: Optional[str] = None
    next_run_at: Optional[str] = None
    created_at: Optional[str] = None
    class Config:
        from_attributes = True

from src.scheduling.domain.entities import ScheduleEntity

@router.get("/status", response_model=ScannerStatus)
def get_scanner_status(db: Session = Depends(get_db)):
    in_progress = db.query(ScanEntity).filter(ScanEntity.status == ScanStatus.IN_PROGRESS).count()
    scheduled = db.query(ScheduleEntity).count()
    
    last_scan = db.query(ScanEntity).filter(
        ScanEntity.status.in_([ScanStatus.COMPLETED, ScanStatus.FAILED])
    ).order_by(ScanEntity.created_at.desc()).first()
    
    # Calculate time ago roughly, or just format
    if last_scan and last_scan.created_at:
        last_scan_time = last_scan.created_at.strftime("%Y-%m-%d %H:%M")
    else:
        last_scan_time = "Aucun"

    return ScannerStatus(
        status="Opérationnel",
        scans_in_progress=in_progress,
        scheduled_scans=scheduled,
        last_scan_time=last_scan_time
    )

@router.get("/companies", response_model=List[CompanyResponse])
def get_companies(db: Session = Depends(get_db)):
    return db.query(CompanyEntity).all()

@router.post("", response_model=ScanResponse)
def create_scan(req: ScanCreateRequest, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    company = db.query(CompanyEntity).filter(CompanyEntity.name == req.company_name).first()
    if not company:
        company = CompanyEntity(name=req.company_name)
        db.add(company)
        db.commit()
        db.refresh(company)
        
    s_type = ScanType.DISCOVERY if req.scan_type.upper() == "DISCOVERY" else ScanType.VULNERABILITY
    s_engine = ScannerEngine[req.scanner_engine.upper()] if req.scanner_engine.upper() in ScannerEngine.__members__ else ScannerEngine.OPENVAS
    
    scan = ScanEntity(
        company_id=company.id,
        name=f"Scan for {req.target}",
        target=req.target,
        network_zone=req.network_zone,
        scan_type=s_type,
        scanner_engine=s_engine,
        status=ScanStatus.PENDING if req.scheduled_for else ScanStatus.IN_PROGRESS,
        recurrence_rule=req.recurrence_rule,
        next_run_at=req.scheduled_for
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    audit = AuditLog(
        user_id=current_user.get("sub") or current_user.get("id", "unknown"),
        username=current_user.get("preferred_username") or current_user.get("username", "system"),
        action="CREATE",
        resource_type="SCAN",
        resource_id=str(scan.id),
        details={"scan_name": scan.name, "target": scan.target}
    )
    db.add(audit)
    db.commit()
    
    # Queue the scan via Celery
    from src.scans.application.services.tasks import run_discovery_scan, run_vulnerability_scan
    
    if s_type == ScanType.DISCOVERY:
        run_discovery_scan.delay(scan.id, req.target, req.network_zone or "Internal", company.id)
    else:
        # Default config_id for 'Full and fast'
        config_id = "daba56c8-73ec-11df-a475-002264764cea"
        run_vulnerability_scan.delay(scan.id, req.target, req.target, config_id)
        
    return ScanResponse(
        id=scan.id,
        company_id=scan.company_id,
        name=scan.name,
        target=scan.target,
        network_zone=scan.network_zone,
        scan_type=scan.scan_type.name,
        scanner_engine=scan.scanner_engine.name,
        status=scan.status.name,
        progress=scan.progress,
        executive_summary=scan.executive_summary,
        recurrence_rule=scan.recurrence_rule,
        next_run_at=scan.next_run_at.isoformat() if scan.next_run_at else None,
        created_at=scan.created_at.isoformat() if scan.created_at else None
    )

@router.get("", response_model=List[ScanResponse])
def get_scans(company_id: Optional[int] = None, network_zone: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(ScanEntity).filter(ScanEntity.is_deleted.is_not(True))
    if company_id:
        query = query.filter(ScanEntity.company_id == company_id)
    if network_zone:
        query = query.filter(ScanEntity.network_zone == network_zone)
    scans = query.order_by(ScanEntity.created_at.desc()).all()
    
    # mapping enum to string
    return [
        ScanResponse(
            id=s.id,
            company_id=s.company_id,
            name=s.name,
            target=s.target,
            network_zone=s.network_zone,
            scan_type=s.scan_type.name,
            scanner_engine=s.scanner_engine.name,
            status=s.status.name,
            progress=s.progress,
            executive_summary=s.executive_summary,
            recurrence_rule=s.recurrence_rule,
            next_run_at=s.next_run_at.isoformat() if s.next_run_at else None,
            created_at=s.created_at.isoformat() if s.created_at else None
        ) for s in scans
    ]

@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    scan.is_deleted = True
    
    audit = AuditLog(
        user_id=current_user.get("id", "unknown"),
        username=current_user.get("username", "system"),
        action="DELETE",
        resource_type="SCAN",
        resource_id=str(scan.id),
        details={"scan_name": scan.name}
    )
    db.add(audit)
    db.commit()
    return None

@router.put("/{scan_id}", response_model=ScanResponse)
def update_scan(scan_id: str, req: ScanUpdateRequest, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan or scan.is_deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    old_details = {"name": scan.name, "target": scan.target, "network_zone": scan.network_zone, "scanner_engine": scan.scanner_engine.name}
    
    if req.name is not None:
        scan.name = req.name
    if req.target is not None:
        scan.target = req.target
    if req.network_zone is not None:
        scan.network_zone = req.network_zone
    if req.scanner_engine is not None:
        s_engine = ScannerEngine[req.scanner_engine.upper()] if req.scanner_engine.upper() in ScannerEngine.__members__ else ScannerEngine.OPENVAS
        scan.scanner_engine = s_engine
        
    audit = AuditLog(
        user_id=current_user.get("id", "unknown"),
        username=current_user.get("username", "system"),
        action="UPDATE",
        resource_type="SCAN",
        resource_id=str(scan.id),
        details={"old": old_details, "new": {"name": scan.name, "target": scan.target, "network_zone": scan.network_zone, "scanner_engine": scan.scanner_engine.name}}
    )
    db.add(audit)
    db.commit()
    db.refresh(scan)
    
    return ScanResponse(
        id=scan.id,
        company_id=scan.company_id,
        name=scan.name,
        target=scan.target,
        network_zone=scan.network_zone,
        scan_type=scan.scan_type.name,
        scanner_engine=scan.scanner_engine.name,
        status=scan.status.name,
        progress=scan.progress,
        executive_summary=scan.executive_summary,
        recurrence_rule=scan.recurrence_rule,
        next_run_at=scan.next_run_at.isoformat() if scan.next_run_at else None,
        created_at=scan.created_at.isoformat() if scan.created_at else None
    )



class SummaryGenerateRequest(BaseModel):
    language: str = "French"
    instructions: str = ""

class SummaryUpdateRequest(BaseModel):
    summary: str

@router.post("/{scan_id}/generate-summary", response_model=ScanResponse)
async def generate_scan_summary(scan_id: str, req: SummaryGenerateRequest, db: Session = Depends(get_db)):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    from src.vulnerabilities.domain.entities import VulnerabilityEntity
    
    # Get top 5 vulnerabilities by contextual_risk_score
    vulns = db.query(VulnerabilityEntity).filter(
        VulnerabilityEntity.asset_id.in_(
            db.query(AssetEntity.id).filter(AssetEntity.ip_address == scan.target)
        )
    ).order_by(VulnerabilityEntity.contextual_risk_score.desc()).limit(5).all()
    
    vuln_data = [{"title": v.title, "cvss": v.cvss_base_score, "severity": v.severity.name} for v in vulns]
    
    from src.ai.application.services.nlp import generate_executive_summary
    
    summary = await generate_executive_summary(vuln_data, language=req.language, extra_instructions=req.instructions)
    
    scan.executive_summary = summary
    db.commit()
    db.refresh(scan)
    
    return scan

@router.put("/{scan_id}/summary", response_model=ScanResponse)
def update_scan_summary(scan_id: str, req: SummaryUpdateRequest, db: Session = Depends(get_db)):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    scan.executive_summary = req.summary
    db.commit()
    db.refresh(scan)
    return scan

from fastapi.responses import StreamingResponse
import io

@router.get("/{scan_id}/report/pdf")
def download_scan_report(
    scan_id: str, 
    scanner_company: str = "Kerubiscan Security", 
    target_company: str = "Client Company", 
    db: Session = Depends(get_db)
):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # Get Asset
    asset = db.query(AssetEntity).filter(AssetEntity.ip_address == scan.target).first()
    if not asset:
        # Create a dummy asset for the report if it doesn't exist
        asset = AssetEntity(name=scan.target, ip_address=scan.target, network_zone=scan.network_zone)
        
    # Get Vulnerabilities
    from src.vulnerabilities.domain.entities import VulnerabilityEntity
    vulns = []
    if asset.id:
        vulns = db.query(VulnerabilityEntity).filter(VulnerabilityEntity.asset_id == asset.id).all()
    
    from src.reporting.application.services.pdf_generator import generate_vulnerability_pdf
    
    pdf_bytes = generate_vulnerability_pdf(
        asset=asset,
        vulnerabilities=vulns,
        executive_summary=scan.executive_summary,
        scanner_company_name=scanner_company,
        target_company_name=target_company
    )
    
    return StreamingResponse(
        io.BytesIO(pdf_bytes), 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename=rapport_{scan.target}.pdf"}
    )
