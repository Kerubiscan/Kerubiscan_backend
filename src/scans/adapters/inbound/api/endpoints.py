import io
import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.core.database import get_db
from src.companies.domain.entities import CompanyEntity
from src.scans.domain.entities import ScanEntity, ScanType, ScanStatus, ScannerEngine
from src.scans.domain.targets import InvalidTargetError, TargetNotAllowedError, validate_targets, split_targets
from src.assets.domain.entities import AssetEntity
from src.auth.adapters.inbound.api.dependencies import require_permissions
from src.auth.domain.entities import Permission
from src.audit.domain.models import AuditLog
from src.scheduling.domain.entities import ScheduleEntity
from src.scans.application.services.scan_assets import scan_assets

logger = logging.getLogger(__name__)

router = APIRouter()

# Default config_id for 'Full and fast'
OPENVAS_FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"


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
    target: str  # comma separated IPs, CIDRs, domains or http(s) URLs
    network_zone: Optional[str] = None
    scan_type: str  # "DISCOVERY", "VULNERABILITY" or "WEB_APP"
    scanner_engine: str = "OPENVAS"  # "OPENVAS", "NMAP", "NUCLEI", "OWASP_ZAP"
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
    # Reason shown for each target (failure, timeout, OpenVAS queue...) and its timestamps
    target_details: Optional[dict] = None
    vulnerabilities_found: Optional[int] = None
    executive_summary: Optional[str] = None
    policy_id: Optional[str] = None
    credential_id: Optional[str] = None
    recurrence_rule: Optional[str] = None
    next_run_at: Optional[str] = None
    created_at: Optional[str] = None
    # First target started / last target finished (None while the scan runs) and duration in seconds
    # (elapsed time while it runs)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: Optional[int] = None
    # Running scan: estimated seconds before the end (0 = estimate exceeded) and what it is based on
    # ("history": previous runs of this scan, "similar": finished scans of the same target and
    # engine, "progress": extrapolated from the real progress). None = no reliable basis.
    eta_seconds: Optional[int] = None
    eta_basis: Optional[str] = None
    class Config:
        from_attributes = True


def _parse_ts(value) -> Optional[datetime]:
    from src.scans.application.services.progress import parse_ts
    return parse_ts(value)


def _timing(scan: ScanEntity):
    """(started_at, finished_at, duration_seconds) from the per-target timestamps (scans.target_meta).

    A finished scan ends at the last update of its targets; older scans without per-target
    timestamps fall back to created_at / updated_at.
    """
    from src.scans.application.services.progress import run_window
    started, finished = run_window(scan)
    if started is None:
        return None, None, None
    end = finished or (datetime.now(timezone.utc) if scan.status == ScanStatus.IN_PROGRESS else None)
    duration = int((end - started).total_seconds()) if end else None
    return started.isoformat(), finished.isoformat() if finished else None, duration


def _run_date(scan: ScanEntity) -> Optional[datetime]:
    """Date shown on a report: the start of the run it shows (a rerun keeps the row's created_at)."""
    from src.scans.application.services.progress import run_window
    return run_window(scan)[0] or scan.created_at


def _median(values: List[int]) -> Optional[int]:
    values = sorted(v for v in values if v and v > 0)
    if not values:
        return None
    mid = len(values) // 2
    return values[mid] if len(values) % 2 else (values[mid - 1] + values[mid]) // 2


# Beyond this multiple of a past duration, that duration is no longer used as the estimate
OVERRUN_TOLERANCE = 1.15


def _estimate_remaining(db: Session, scan: ScanEntity, elapsed: Optional[int]):
    """(eta_seconds, basis) for a running scan, from real data only (never a made-up figure)."""
    if scan.status != ScanStatus.IN_PROGRESS or elapsed is None:
        return None, None
    # 0. The running engine itself: from its phases (ZAP) or its own pace (Nmap, Nuclei)
    from src.scans.application.services.progress import engine_remaining
    left = engine_remaining(scan)
    if left is not None:
        return left, "engine"
    # 1. Previous complete runs of this very scan (rerun on the same row)
    logs = (db.query(AuditLog).filter(AuditLog.resource_type == "SCAN", AuditLog.resource_id == str(scan.id),
                                      AuditLog.action == "SCAN_COMPLETED")
            .order_by(AuditLog.timestamp.desc()).limit(5).all())
    estimate = _median([(log.details or {}).get("duration_seconds") for log in logs])
    basis = "history" if estimate else None
    # 2. Finished scans of the same target with the same engine
    if not estimate:
        similar = (db.query(ScanEntity).filter(ScanEntity.id != scan.id, ScanEntity.target == scan.target,
                                               ScanEntity.scanner_engine == scan.scanner_engine,
                                               ScanEntity.scan_type == scan.scan_type,
                                               ScanEntity.status == ScanStatus.COMPLETED)
                   .order_by(ScanEntity.created_at.desc()).limit(5).all())
        estimate = _median([_timing(o)[2] for o in similar])
        basis = "similar" if estimate else None
    # A past duration clearly exceeded no longer says anything about this run (engine or target
    # changed): it kept showing "end imminent" for the rest of the scan.
    if estimate and elapsed > estimate * OVERRUN_TOLERANCE:
        estimate, basis = None, None
    # Nor one the real progress contradicts, past its first half: a 5 min past run, 5 min elapsed,
    # but only 18 % done
    if estimate and elapsed >= estimate / 2 and (scan.progress or 0) < 50 * min(elapsed / estimate, 1.0):
        estimate, basis = None, None
    # 3. Extrapolation from the real progress, once past the port discovery (OpenVAS and ZAP report
    # their own %)
    if not estimate and (scan.progress or 0) >= 35:
        estimate = int(elapsed * 100 / scan.progress)
        basis = "progress"
    if not estimate:
        return None, None
    return max(estimate - elapsed, 0), basis


def _to_response(scan: ScanEntity, db: Optional[Session] = None) -> ScanResponse:
    started_at, finished_at, duration = _timing(scan)
    eta, eta_basis = _estimate_remaining(db, scan, duration) if db is not None else (None, None)
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
        target_details=scan.target_meta,
        vulnerabilities_found=scan.vulnerabilities_found,
        executive_summary=scan.executive_summary,
        policy_id=scan.policy_id,
        credential_id=scan.credential_id,
        recurrence_rule=scan.recurrence_rule,
        next_run_at=scan.next_run_at.isoformat() if scan.next_run_at else None,
        created_at=scan.created_at.isoformat() if scan.created_at else None,
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=duration,
        eta_seconds=eta,
        eta_basis=eta_basis,
    )


def _user_id(user: dict) -> str:
    return user.get("sub") or user.get("id") or "unknown"


def _username(user: dict) -> str:
    return user.get("preferred_username") or user.get("username") or "system"


def _parse_engine(value: str) -> ScannerEngine:
    key = (value or "").strip().upper()
    if key == "ZAP":
        key = "OWASP_ZAP"
    if key not in ScannerEngine.__members__:
        raise HTTPException(status_code=400, detail=f"Moteur de scan inconnu : {value!r}. "
                                                    f"Valeurs possibles : {', '.join(ScannerEngine.__members__)}")
    return ScannerEngine[key]


def _parse_scan_type(value: str) -> ScanType:
    key = (value or "").strip().upper()
    if key not in ScanType.__members__:
        raise HTTPException(status_code=400, detail=f"Type de scan inconnu : {value!r}")
    # WEB_APP is stored as VULNERABILITY (as before): the engine choice drives the web scan, and
    # older databases may not have WEB_APP in their PostgreSQL enum.
    return ScanType.DISCOVERY if key == "DISCOVERY" else ScanType.VULNERABILITY


def _validate_scan_targets(raw: str, scan_type: ScanType, user: dict = None) -> List[str]:
    try:
        parsed = validate_targets(raw)
    except TargetNotAllowedError as e:
        # Perimeter guard: refuse (403) and record the attempt in the audit log
        logger.warning(f"Scan refused (outside perimeter) by {_username(user or {})}: {e}")
        raise HTTPException(status_code=403, detail=str(e))
    except InvalidTargetError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if scan_type == ScanType.DISCOVERY and any(t.is_url for t in parsed):
        raise HTTPException(status_code=400, detail="Une découverte d'hôtes porte sur des IP, réseaux ou domaines, pas sur des URL")
    return [t.raw for t in parsed]


def _queue_scan(scan: ScanEntity, targets: List[str]):
    from src.scans.application.services.tasks import run_discovery_scan, run_vulnerability_scan
    if scan.scan_type == ScanType.DISCOVERY:
        run_discovery_scan.delay(scan.id, ",".join(targets), scan.network_zone or "Internal", scan.company_id)
    else:
        for target in targets:
            run_vulnerability_scan.delay(scan.id, target, target, OPENVAS_FULL_AND_FAST)


@router.get("/status", response_model=ScannerStatus)
def get_scanner_status(db: Session = Depends(get_db), current_user: dict = Depends(require_permissions([Permission.SCAN_READ]))):
    in_progress = db.query(ScanEntity).filter(
        ScanEntity.status.in_([ScanStatus.IN_PROGRESS, ScanStatus.PENDING])
    ).count()
    scheduled = db.query(ScheduleEntity).count()

    from src.scans.application.services.progress import last_run_at
    finished = db.query(ScanEntity).filter(
        ScanEntity.status.in_([ScanStatus.COMPLETED, ScanStatus.FAILED]),
        ScanEntity.is_deleted == False,  # noqa: E712
    ).order_by(ScanEntity.updated_at.desc()).limit(20).all()
    # A rerun keeps its row and created_at: the last scan is the one that ran last
    ran = [t for t in (last_run_at(s) for s in finished) if t]
    last_scan_time = max(ran).astimezone().strftime("%Y-%m-%d %H:%M") if ran else "Aucun"

    return ScannerStatus(
        status="Opérationnel",
        scans_in_progress=in_progress,
        scheduled_scans=scheduled,
        last_scan_time=last_scan_time
    )

@router.get("/companies", response_model=List[CompanyResponse])
def get_companies(db: Session = Depends(get_db), current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))):
    return db.query(CompanyEntity).all()

@router.delete("/companies/{company_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_company(company_id: str, db: Session = Depends(get_db),
                   current_user: dict = Depends(require_permissions([Permission.SCAN_DELETE, Permission.ASSET_DELETE]))):
    company = db.query(CompanyEntity).filter(CompanyEntity.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    try:
        db.delete(company)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail="Cannot delete company. It may have associated scans or assets.")

    return None


@router.post("", response_model=ScanResponse)
def create_scan(req: ScanCreateRequest, db: Session = Depends(get_db),
                current_user: dict = Depends(require_permissions([Permission.SCAN_EXECUTE]))):
    s_type = _parse_scan_type(req.scan_type)
    s_engine = _parse_engine(req.scanner_engine)
    targets = _validate_scan_targets(req.target, s_type, current_user)

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

    target_value = ",".join(targets)
    scan_name = f"Multi scan for {company.name}" if len(targets) > 1 else f"Scan for {target_value}"

    scan = ScanEntity(
        company_id=company.id,
        name=scan_name,
        target=target_value,
        network_zone=req.network_zone,
        scan_type=s_type,
        scanner_engine=s_engine,
        status=ScanStatus.PENDING if req.scheduled_for else ScanStatus.IN_PROGRESS,
        target_states={t: "PENDING" for t in targets},
        policy_id=req.policy_id,
        credential_id=req.credential_id,
        recurrence_rule=req.recurrence_rule,
        next_run_at=req.scheduled_for,
        notify_email=current_user.get("email")
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    db.add(AuditLog(
        user_id=_user_id(current_user),
        username=_username(current_user),
        action="CREATE",
        resource_type="SCAN",
        resource_id=str(scan.id),
        details={"scan_name": scan.name, "target": scan.target, "engine": s_engine.name, "type": s_type.name}
    ))
    db.commit()

    if not req.scheduled_for:
        _queue_scan(scan, targets)

    return _to_response(scan)

@router.get("", response_model=List[ScanResponse])
def get_scans(company_id: Optional[str] = None, network_zone: Optional[str] = None, status: Optional[str] = None,
              db: Session = Depends(get_db), current_user: dict = Depends(require_permissions([Permission.SCAN_READ]))):
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
    return [_to_response(s, db) for s in query.order_by(ScanEntity.created_at.desc()).all()]

@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: str, db: Session = Depends(get_db),
                current_user: dict = Depends(require_permissions([Permission.SCAN_DELETE]))):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        scan.is_deleted = True
        db.add(AuditLog(user_id=_user_id(current_user), username=_username(current_user), action="DELETE",
                        resource_type="SCAN", resource_id=str(scan.id), details={"scan_name": scan.name}))
        db.commit()
    except Exception:
        logger.exception(f"Failed to delete scan {scan_id}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Échec de la suppression du scan")
    return None

@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def delete_all_scans(db: Session = Depends(get_db),
                     current_user: dict = Depends(require_permissions([Permission.SCAN_DELETE]))):
    try:
        scans = db.query(ScanEntity).filter(ScanEntity.is_deleted == False).all()  # noqa: E712
        for scan in scans:
            scan.is_deleted = True
        db.add(AuditLog(user_id=_user_id(current_user), username=_username(current_user), action="DELETE_ALL",
                        resource_type="SCAN", resource_id="ALL", details={"count": len(scans)}))
        db.commit()
    except Exception:
        logger.exception("Failed to delete all scans")
        db.rollback()
        raise HTTPException(status_code=500, detail="Échec de la suppression des scans")
    return None

@router.put("/{scan_id}", response_model=ScanResponse)
def update_scan(scan_id: str, req: ScanUpdateRequest, db: Session = Depends(get_db),
                current_user: dict = Depends(require_permissions([Permission.SCAN_EXECUTE]))):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan or scan.is_deleted:
        raise HTTPException(status_code=404, detail="Scan not found")

    old_details = {"name": scan.name, "target": scan.target, "network_zone": scan.network_zone,
                   "scanner_engine": scan.scanner_engine.name, "policy_id": scan.policy_id, "credential_id": scan.credential_id}

    if req.name is not None:
        scan.name = req.name
    if req.target is not None:
        scan.target = ",".join(_validate_scan_targets(req.target, scan.scan_type, current_user))
    if req.network_zone is not None:
        scan.network_zone = req.network_zone
    if req.scanner_engine is not None:
        scan.scanner_engine = _parse_engine(req.scanner_engine)
    # These two fields used to be silently ignored
    if req.policy_id is not None:
        scan.policy_id = req.policy_id or None
    if req.credential_id is not None:
        scan.credential_id = req.credential_id or None

    db.add(AuditLog(
        user_id=_user_id(current_user),
        username=_username(current_user),
        action="UPDATE",
        resource_type="SCAN",
        resource_id=str(scan.id),
        details={"old": old_details, "new": {"name": scan.name, "target": scan.target, "network_zone": scan.network_zone,
                                             "scanner_engine": scan.scanner_engine.name, "policy_id": scan.policy_id,
                                             "credential_id": scan.credential_id}}
    ))
    db.commit()
    db.refresh(scan)
    return _to_response(scan)


class SummaryGenerateRequest(BaseModel):
    language: str = "French"
    instructions: str = ""
    provider: str = None

class SummaryUpdateRequest(BaseModel):
    summary: str

@router.post("/{scan_id}/generate-summary")
async def generate_scan_summary(scan_id: str, req: SummaryGenerateRequest, db: Session = Depends(get_db),
                                current_user: dict = Depends(require_permissions([Permission.SCAN_READ]))):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    from src.vulnerabilities.domain.entities import VulnerabilityEntity
    asset_ids = [a.id for a in scan_assets(db, scan)]
    vulns = db.query(VulnerabilityEntity).filter(
        VulnerabilityEntity.asset_id.in_(asset_ids)
    ).order_by(VulnerabilityEntity.contextual_risk_score.desc().nullslast()).limit(5).all() if asset_ids else []

    vuln_data = [{"title": v.title, "cvss": v.cvss_base_score, "severity": getattr(v.severity, "name", str(v.severity))} for v in vulns]

    from src.scans.application.services.tasks import generate_ai_summary_task
    task = generate_ai_summary_task.delay(vuln_data, req.language, req.instructions, req.provider)
    return {"task_id": task.id, "status": "processing"}

@router.put("/{scan_id}/summary", response_model=ScanResponse)
def update_scan_summary(scan_id: str, req: SummaryUpdateRequest, db: Session = Depends(get_db),
                        current_user: dict = Depends(require_permissions([Permission.SCAN_EXECUTE]))):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.executive_summary = req.summary
    db.commit()
    db.refresh(scan)
    return _to_response(scan)


def _display_name(db: Session, scan: ScanEntity, fallback_company: str) -> str:
    """Report title: the scan name, or "Multi scan for <company>" for multi-target scans."""
    if len(split_targets(scan.target)) > 1 or ("," in scan.name and len(scan.name) > 40):
        company = db.query(CompanyEntity).filter(CompanyEntity.id == scan.company_id).first()
        return f"Multi scan for {company.name if company else fallback_company}"
    return scan.name


def _vulns_by_asset(db: Session, assets: List[AssetEntity], engine: Optional[str] = None) -> dict:
    from src.vulnerabilities.domain.entities import VulnerabilityEntity
    result = {}
    for a in assets:
        q = db.query(VulnerabilityEntity).filter(VulnerabilityEntity.asset_id == a.id)
        if engine:
            q = q.filter(VulnerabilityEntity.source_engine == engine)
        seen, deduped = set(), []
        for v in q.all():
            key = (v.title, v.port)
            if key not in seen:
                seen.add(key)
                deduped.append(v)
        result[str(a.id)] = deduped
    return result


def _scan_report_html(db: Session, scan: ScanEntity, scanner_company: str, target_company: str,
                      executive_summary: Optional[str]) -> bytes:
    """HTML report of a scan. The PDF report is the print rendering of this same document."""
    assets = scan_assets(db, scan)
    if not assets:
        assets = [AssetEntity(id="dummy", name=scan.target, ip_address=scan.target, network_zone=scan.network_zone)]
    engine = scan.scanner_engine.value if scan.scanner_engine else "OPENVAS"
    all_vulns = _vulns_by_asset(db, [a for a in assets if a.id != "dummy"], engine)

    from src.reporting.application.services.html_generator import generate_vulnerability_html, generate_discovery_html

    display_name = _display_name(db, scan, target_company)
    # The network zone is the report heading, where Nessus shows the scan name
    zone = (scan.network_zone or "").strip() or None
    if scan.scan_type == ScanType.DISCOVERY:
        return generate_discovery_html(assets=assets, scanner_company_name=scanner_company,
                                       target_company_name=target_company, scan_name=display_name,
                                       scan_date=_run_date(scan), report_title=zone)
    return generate_vulnerability_html(assets=assets, all_vulnerabilities=all_vulns,
                                       executive_summary=executive_summary,
                                       scanner_company_name=scanner_company,
                                       target_company_name=target_company, scan_name=display_name,
                                       scan_date=_run_date(scan), report_title=zone)


@router.get("/{scan_id}/report/html")
def download_scan_report(
    scan_id: str,
    scanner_company: str = "KVS Security",
    target_company: str = "Client Company",
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permissions([Permission.SCAN_READ]))
):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    html_bytes = _scan_report_html(db, scan, scanner_company, target_company, scan.executive_summary)
    short_id = str(scan.id)[:8]
    return StreamingResponse(
        io.BytesIO(html_bytes),
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="rapport_{short_id}.html"'}
    )


@router.get("/tasks/{task_id}")
def get_task_status(task_id: str, current_user: dict = Depends(require_permissions([Permission.SCAN_READ]))):
    from src.core.celery_app import celery_app
    from celery.result import AsyncResult
    task = AsyncResult(task_id, app=celery_app)
    return {"task_id": task_id, "status": task.status, "result": task.result if task.ready() else None}

class ScannerUpdateRequest(BaseModel):
    engine: str

@router.post("/scanners/update")
def trigger_scanner_update(req: ScannerUpdateRequest, db: Session = Depends(get_db),
                           user: dict = Depends(require_permissions([Permission.SCAN_EXECUTE]))):
    """Triggers an asynchronous update of the scanner database/templates."""
    from src.scans.application.services.tasks import update_nuclei_templates, update_nmap_scripts, update_zap_addons
    engine = req.engine.upper()
    tasks = {
        "NUCLEI": [update_nuclei_templates],
        "NMAP": [update_nmap_scripts],
        "ZAP": [update_zap_addons],
        "OWASP_ZAP": [update_zap_addons],
        "ALL": [update_nuclei_templates, update_nmap_scripts, update_zap_addons],
    }.get(engine)
    if tasks is None:
        raise HTTPException(status_code=400, detail=f"Unsupported scanner engine for update: {engine}")
    for t in tasks:
        t.delay()

    db.add(AuditLog(user_id=_user_id(user), username=_username(user), action="TRIGGER_SCANNER_UPDATE",
                    resource_type="SCANNER", resource_id=engine, details={"status": "STARTED"}))
    db.commit()
    return {"message": f"Update triggered for {engine}", "status": "STARTED"}

class PdfReportRequest(BaseModel):
    language: str = "English"
    executive_summary: str = None

@router.post("/{scan_id}/report/pdf")
def download_scan_report_pdf(
    scan_id: str,
    request_body: PdfReportRequest,
    scanner_company: str = "KVS Security",
    target_company: str = "Client Company",
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permissions([Permission.SCAN_READ]))
):
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    summary = request_body.executive_summary or scan.executive_summary
    html_bytes = _scan_report_html(db, scan, scanner_company, target_company, summary)

    def legacy_pdf() -> bytes:
        from src.reporting.application.services.pdf_generator import generate_scan_vulnerability_pdf
        assets = scan_assets(db, scan)
        return generate_scan_vulnerability_pdf(
            assets=assets,
            all_vulnerabilities=_vulns_by_asset(db, assets, scan.scanner_engine.value if scan.scanner_engine else None),
            executive_summary=summary,
            scanner_company_name=scanner_company,
            target_company_name=target_company,
            scan_name=_display_name(db, scan, target_company),
            scan_date=_run_date(scan)
        )

    from src.reporting.application.services.pdf_renderer import render_pdf
    pdf_bytes = render_pdf(html_bytes, fallback=legacy_pdf)

    short_id = str(scan.id)[:8]
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report_{short_id}.pdf"'}
    )


@router.put("/{scan_id}/pause", response_model=ScanResponse)
def pause_scan(scan_id: str, db: Session = Depends(get_db),
               current_user: dict = Depends(require_permissions([Permission.SCAN_EXECUTE]))):
    """Pauses a running scan at the queue level by aborting pending target tasks."""
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan or scan.is_deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.IN_PROGRESS and scan.status != ScanStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Cannot pause scan in state {scan.status.name}")

    scan.status = ScanStatus.PAUSED
    db.add(AuditLog(user_id=_user_id(current_user), username=_username(current_user), action="PAUSE",
                    resource_type="SCAN", resource_id=str(scan.id), details={"status": "PAUSED"}))
    db.commit()
    db.refresh(scan)
    return _to_response(scan)

@router.put("/{scan_id}/resume", response_model=ScanResponse)
def resume_scan(scan_id: str, db: Session = Depends(get_db),
                current_user: dict = Depends(require_permissions([Permission.SCAN_EXECUTE]))):
    """Resumes a paused scan by re-queueing tasks for any targets that are still PENDING."""
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan or scan.is_deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.PAUSED:
        raise HTTPException(status_code=400, detail=f"Cannot resume scan in state {scan.status.name}")
    # The perimeter may have changed since creation: re-check before re-queueing (R18)
    _validate_scan_targets(scan.target, scan.scan_type, current_user)

    scan.status = ScanStatus.IN_PROGRESS
    targets_to_requeue = []
    if scan.target_states:
        new_states = dict(scan.target_states)
        for t_ip, t_state in new_states.items():
            if t_state in ["PENDING", "IN_PROGRESS"]:
                new_states[t_ip] = "PENDING"
                targets_to_requeue.append(t_ip)
        scan.target_states = new_states
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(scan, "target_states")
    if not targets_to_requeue:
        # Every target finished while the scan was paused: it used to stay IN_PROGRESS forever
        from src.scans.application.services.progress import recompute_status
        recompute_status(scan)
    db.commit()

    db.add(AuditLog(user_id=_user_id(current_user), username=_username(current_user), action="RESUME",
                    resource_type="SCAN", resource_id=str(scan.id),
                    details={"status": "IN_PROGRESS", "requeued_targets": len(targets_to_requeue)}))
    db.commit()
    db.refresh(scan)

    if targets_to_requeue:
        _queue_scan(scan, targets_to_requeue if scan.scan_type != ScanType.DISCOVERY else split_targets(scan.target))
    return _to_response(scan)


@router.post("/{scan_id}/rerun", response_model=ScanResponse)
def rerun_scan(scan_id: str, db: Session = Depends(get_db),
               current_user: dict = Depends(require_permissions([Permission.SCAN_EXECUTE]))):
    """Runs a finished scan again on the same row (used to create a new scan each time).

    The targets restart from scratch; findings already stored are kept and updated by the new run
    (same title and port), so the history of each vulnerability is preserved.
    """
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan or scan.is_deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in (ScanStatus.IN_PROGRESS, ScanStatus.PENDING, ScanStatus.PAUSED):
        raise HTTPException(status_code=409, detail="Ce scan est déjà en cours : arrêtez-le avant de le relancer")
    # The perimeter may have changed since creation (R18)
    targets = _validate_scan_targets(scan.target, scan.scan_type, current_user)

    previous = {"status": scan.status.name, "progress": scan.progress}
    from sqlalchemy.orm.attributes import flag_modified
    scan.status = ScanStatus.IN_PROGRESS
    scan.progress = 0
    scan.target_states = {t: "PENDING" for t in targets}
    scan.target_meta = {}
    flag_modified(scan, "target_states")
    flag_modified(scan, "target_meta")
    db.add(AuditLog(user_id=_user_id(current_user), username=_username(current_user), action="RERUN",
                    resource_type="SCAN", resource_id=str(scan.id), details={"previous": previous}))
    db.commit()
    db.refresh(scan)

    _queue_scan(scan, targets)
    return _to_response(scan, db)


@router.put("/{scan_id}/stop", response_model=ScanResponse)
def stop_scan(scan_id: str, db: Session = Depends(get_db),
              current_user: dict = Depends(require_permissions([Permission.SCAN_EXECUTE]))):
    """Stops a running scan: revokes its Celery tasks, stops its OpenVAS tasks and kills the scanner
    processes; non-finished targets become INTERRUPTED (partial results kept)."""
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
    if not scan or scan.is_deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in (ScanStatus.IN_PROGRESS, ScanStatus.PENDING, ScanStatus.PAUSED):
        raise HTTPException(status_code=400, detail=f"Cannot stop scan in state {scan.status.name}")

    db.add(AuditLog(user_id=_user_id(current_user), username=_username(current_user), action="STOP",
                    resource_type="SCAN", resource_id=str(scan.id), details={"previous_status": scan.status.name}))
    db.commit()

    from src.scans.application.services.tasks import stop_scan_task
    stop_scan_task.delay(scan_id)
    db.refresh(scan)
    return _to_response(scan)
