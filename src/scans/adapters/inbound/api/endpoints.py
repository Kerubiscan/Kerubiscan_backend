from fastapi import APIRouter, Depends, HTTPException, status
from datetime import datetime
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
    company_name: Optional[str] = None
    company_id: Optional[str] = None
    target: str
    network_zone: Optional[str] = None
    scan_type: str # "DISCOVERY" or "VULNERABILITY"
    scanner_engine: str = "OPENVAS" # "OPENVAS", "NMAP", "NUCLEI", "NESSUS"
    policy_id: Optional[str] = None
    credential_id: Optional[str] = None
    scheduled_for: Optional[str] = None
    recurrence_rule: Optional[str] = None

class ScanUpdateRequest(BaseModel):
    name: Optional[str] = None
    target: Optional[str] = None
    network_zone: Optional[str] = None
    scanner_engine: Optional[str] = None
    policy_id: Optional[str] = None
    credential_id: Optional[str] = None

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
    target_states: Optional[dict] = None
    executive_summary: Optional[str] = None
    policy_id: Optional[str] = None
    credential_id: Optional[str] = None
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

@router.delete("/companies/{company_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_company(company_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    company = db.query(CompanyEntity).filter(CompanyEntity.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
        
    try:
        db.delete(company)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail="Cannot delete company. It may have associated scans or assets.")
    
    return None


@router.post("", response_model=ScanResponse)
def create_scan(req: ScanCreateRequest, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    company = None
    if req.company_id:
        company = db.query(CompanyEntity).filter(CompanyEntity.id == req.company_id).first()
    elif req.company_name:
        normalized_company_name = req.company_name.strip()
        company = db.query(CompanyEntity).filter(CompanyEntity.name == normalized_company_name).first()
        if not company:
            company = CompanyEntity(name=normalized_company_name)
            db.add(company)
            db.commit()
            db.refresh(company)
            
    if not company:
        raise HTTPException(status_code=400, detail="Either company_id or company_name must be provided and valid")
        
    s_type = ScanType.DISCOVERY if req.scan_type.upper() == "DISCOVERY" else ScanType.VULNERABILITY
    s_engine = ScannerEngine[req.scanner_engine.upper()] if req.scanner_engine.upper() in ScannerEngine.__members__ else ScannerEngine.OPENVAS
    
    targets = [t.strip() for t in req.target.split(",") if t.strip()]
    target_states = {t: "PENDING" for t in targets}
    
    if len(targets) > 1:
        scan_name = f"Multi-Target Scan ({len(targets)} targets)"
    else:
        scan_name = f"Scan for {req.target}"
    
    scan = ScanEntity(
        company_id=company.id,
        name=scan_name,
        target=req.target,
        network_zone=req.network_zone,
        scan_type=s_type,
        scanner_engine=s_engine,
        status=ScanStatus.PENDING if req.scheduled_for else ScanStatus.IN_PROGRESS,
        target_states=target_states,
        policy_id=req.policy_id,
        credential_id=req.credential_id,
        recurrence_rule=req.recurrence_rule,
        next_run_at=req.scheduled_for,
        notify_email=current_user.get("email")
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
        for ip in targets:
            run_vulnerability_scan.delay(scan.id, ip, ip, config_id)
        
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
        target_states=scan.target_states,
        executive_summary=scan.executive_summary,
        policy_id=scan.policy_id,
        credential_id=scan.credential_id,
        recurrence_rule=scan.recurrence_rule,
        next_run_at=scan.next_run_at.isoformat() if scan.next_run_at else None,
        created_at=scan.created_at.isoformat() if scan.created_at else None
    )

@router.get("", response_model=List[ScanResponse])
def get_scans(company_id: Optional[str] = None, network_zone: Optional[str] = None, status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(ScanEntity).filter(ScanEntity.is_deleted.is_not(True))
    if company_id:
        query = query.filter(ScanEntity.company_id == company_id)
    if network_zone:
        query = query.filter(ScanEntity.network_zone == network_zone)
    if status:
        try:
            query = query.filter(ScanEntity.status == ScanStatus[status.upper()])
        except KeyError:
            pass  # ignore invalid status values
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
            target_states=s.target_states,
            executive_summary=s.executive_summary,
            policy_id=s.policy_id,
            credential_id=s.credential_id,
            recurrence_rule=s.recurrence_rule,
            next_run_at=s.next_run_at.isoformat() if s.next_run_at else None,
            created_at=s.created_at.isoformat() if s.created_at else None
        ) for s in scans
    ]

@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    try:
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
            
        scan.is_deleted = True
        
        # User requested: when I delete a scan its values too should also be removed.
        from src.assets.domain.entities import AssetEntity
        from src.vulnerabilities.domain.entities import VulnerabilityEntity
        from src.vulnerabilities.domain.entities import VulnerabilityHistoryEntity
        
        targets = [t.strip() for t in scan.target.split(",")] if scan.target else []
        assets = db.query(AssetEntity).filter(
            AssetEntity.company_id == scan.company_id,
            (AssetEntity.ip_address.in_(targets)) | (AssetEntity.name.in_(targets))
        ).all()
        
        for asset in assets:
            vulns = db.query(VulnerabilityEntity).filter(VulnerabilityEntity.asset_id == asset.id).all()
            for v in vulns:
                db.query(VulnerabilityHistoryEntity).filter(VulnerabilityHistoryEntity.vulnerability_id == v.id).delete(synchronize_session=False)
                db.delete(v)
        
        audit = AuditLog(
            user_id=current_user.get("sub", "unknown"),
            username=current_user.get("preferred_username") or current_user.get("username", "system"),
            action="DELETE",
            resource_type="SCAN",
            resource_id=str(scan.id),
            details={"scan_name": scan.name}
        )
        db.add(audit)
        db.commit()
        return None
    except Exception as e:
        import traceback
        error_msg = traceback.format_exc()
        db.rollback()
        raise HTTPException(status_code=500, detail=str(error_msg))

@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def delete_all_scans(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    try:
        scans = db.query(ScanEntity).filter(ScanEntity.is_deleted == False).all()
        for scan in scans:
            scan.is_deleted = True
            
        from src.vulnerabilities.domain.entities import VulnerabilityEntity
        from src.vulnerabilities.domain.entities import VulnerabilityHistoryEntity
        
        db.query(VulnerabilityHistoryEntity).delete(synchronize_session=False)
        db.query(VulnerabilityEntity).delete(synchronize_session=False)
        
        audit = AuditLog(
            user_id=current_user.get("sub", "unknown"),
            username=current_user.get("preferred_username") or current_user.get("username", "system"),
            action="DELETE_ALL",
            resource_type="SCAN",
            resource_id="ALL",
            details={"count": len(scans)}
        )
        db.add(audit)
        db.commit()
        return None
    except Exception as e:
        import traceback
        error_msg = traceback.format_exc()
        db.rollback()
        raise HTTPException(status_code=500, detail=str(error_msg))

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
        target_states=scan.target_states,
        executive_summary=scan.executive_summary,
        recurrence_rule=scan.recurrence_rule,
        next_run_at=scan.next_run_at.isoformat() if scan.next_run_at else None,
        created_at=scan.created_at.isoformat() if scan.created_at else None
    )



class SummaryGenerateRequest(BaseModel):
    language: str = "French"
    instructions: str = ""
    provider: str = None

class SummaryUpdateRequest(BaseModel):
    summary: str

@router.post("/{scan_id}/generate-summary")
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
    
    vuln_data = [{"title": v.title, "cvss": v.cvss_base_score, "severity": getattr(v.severity, "name", str(v.severity))} for v in vulns]
    
    from src.scans.application.services.tasks import generate_ai_summary_task
    
    # Enqueue task
    task = generate_ai_summary_task.delay(vuln_data, req.language, req.instructions, req.provider)
    
    return {"task_id": task.id, "status": "processing"}

@router.put("/{scan_id}/summary", response_model=ScanResponse)
def update_scan_summary(scan_id: str, req: SummaryUpdateRequest, db: Session = Depends(get_db)):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    scan.executive_summary = req.summary
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
        target_states=scan.target_states,
        executive_summary=scan.executive_summary,
        recurrence_rule=scan.recurrence_rule,
        next_run_at=scan.next_run_at.isoformat() if scan.next_run_at else None,
        created_at=scan.created_at.isoformat() if scan.created_at else None
    )

from fastapi.responses import StreamingResponse
import io

@router.get("/{scan_id}/report/html")
def download_scan_report(
    scan_id: str, 
    scanner_company: str = "Kerubiscan Security", 
    target_company: str = "Client Company", 
    db: Session = Depends(get_db)
):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    import ipaddress
    
    targets = [t.strip() for t in scan.target.split(",")] if scan.target else []
    
    subnets = [t for t in targets if '/' in t]
    exact_ips = [t for t in targets if '/' not in t]
    
    raw_assets = []
    if exact_ips:
        raw_assets.extend(db.query(AssetEntity).filter(AssetEntity.ip_address.in_(exact_ips)).all())
        
    if subnets:
        company_assets = db.query(AssetEntity).filter(AssetEntity.company_id == scan.company_id).all()
        for asset in company_assets:
            if not asset.ip_address: continue
            
            # Skip if already added
            if any(a.id == asset.id for a in raw_assets):
                continue
                
            try:
                asset_ip_obj = ipaddress.ip_address(asset.ip_address)
                for subnet in subnets:
                    try:
                        if asset_ip_obj in ipaddress.ip_network(subnet, strict=False):
                            raw_assets.append(asset)
                            break
                    except ValueError:
                        pass
            except ValueError:
                pass
    
    # Deduplicate: one asset object per unique IP address
    seen_ips: dict = {}
    for a in raw_assets:
        ip = a.ip_address
        if ip not in seen_ips:
            seen_ips[ip] = a
        elif a.ports and not seen_ips[ip].ports:
            seen_ips[ip] = a  # prefer the record that has port data
    assets = list(seen_ips.values())
    
    if not assets:
        assets = [AssetEntity(id="dummy", name=scan.target, ip_address=scan.target, network_zone=scan.network_zone)]
        
    from src.vulnerabilities.domain.entities import VulnerabilityEntity
    all_vulns = {}
    for a in assets:
        if a.id != "dummy":
            vulns = db.query(VulnerabilityEntity).filter(VulnerabilityEntity.asset_id == a.id).all()
            # Also deduplicate vulnerabilities by title
            seen_titles: dict = {}
            deduped = []
            for v in vulns:
                if v.title not in seen_titles:
                    seen_titles[v.title] = True
                    deduped.append(v)
            all_vulns[str(a.id)] = deduped
    
    from src.reporting.application.services.html_generator import generate_vulnerability_html, generate_discovery_html
    
    display_name = scan.name
    if "," in display_name and len(display_name) > 40:
        display_name = "Multi-Target Scan Batch"
    
    if scan.scan_type and getattr(scan.scan_type, 'value', str(scan.scan_type)).lower() == "discovery":
        html_bytes = generate_discovery_html(
            assets=assets,
            scanner_company_name=scanner_company,
            target_company_name=target_company,
            scan_name=display_name
        )
    else:
        html_bytes = generate_vulnerability_html(
            assets=assets,
            all_vulnerabilities=all_vulns,
            executive_summary=scan.executive_summary,
            scanner_company_name=scanner_company,
            target_company_name=target_company,
            scan_name=display_name
        )
    
    # Use a short, clean filename using the scan ID to avoid any browser encoding issues
    short_id = str(scan.id)[:8]
    return StreamingResponse(
        io.BytesIO(html_bytes), 
        media_type="text/html", 
        headers={"Content-Disposition": f'attachment; filename="rapport_{short_id}.html"'}
    )

@router.get("/tasks/{task_id}")
def get_task_status(task_id: str):
    from src.core.celery_app import celery_app
    from celery.result import AsyncResult
    task = AsyncResult(task_id, app=celery_app)
    
    response = {
        "task_id": task_id,
        "status": task.status,
        "result": task.result if task.ready() else None
    }
    return response

class ScannerUpdateRequest(BaseModel):
    engine: str

@router.post("/scanners/update")
def trigger_scanner_update(req: ScannerUpdateRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Triggers an asynchronous update of the scanner database/templates."""
    engine = req.engine.upper()
    
    if engine == "NUCLEI":
        from src.scans.application.services.tasks import update_nuclei_templates
        update_nuclei_templates.delay()
    elif engine == "NMAP":
        from src.scans.application.services.tasks import update_nmap_scripts
        update_nmap_scripts.delay()
    elif engine == "ZAP":
        from src.scans.application.services.tasks import update_zap_addons
        update_zap_addons.delay()
    elif engine == "ALL":
        from src.scans.application.services.tasks import update_nuclei_templates, update_nmap_scripts, update_zap_addons
        update_nuclei_templates.delay()
        update_nmap_scripts.delay()
        update_zap_addons.delay()
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported scanner engine for update: {engine}")
    
    db.add(AuditLog(
        user_id=str(user.id) if user else "system",
        username=user.username if user else "system",
        action="TRIGGER_SCANNER_UPDATE",
        resource_type="SCANNER",
        resource_id=engine,
        details={"status": "STARTED"}
    ))
    db.commit()
    
    return {"message": f"Update triggered for {engine}", "status": "STARTED"}

