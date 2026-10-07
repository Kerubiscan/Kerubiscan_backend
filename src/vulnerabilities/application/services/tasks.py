import logging
from typing import Dict, List
from sqlalchemy.orm import Session

from src.core.celery_app import celery_app
from src.core.database import SessionLocal
from src.scans.application.services import progress
from src.scans.application.services.progress import update_scan_progress
from src.scans.domain.entities import ScanEntity
from src.scans.domain.targets import parse_target, InvalidTargetError
from src.vulnerabilities.domain import severity as sev
from src.vulnerabilities.application.services.ingest import (  # noqa: F401  (calculate_contextual_risk re-exported)
    resolve_asset, update_asset_from_host, ingest_findings, calculate_contextual_risk,
)

logger = logging.getLogger(__name__)


def safe_float(val, default=0.0) -> float:
    try:
        return float(val) if val is not None and val != "" else default
    except (ValueError, TypeError):
        return default


def send_scan_summary_email(scan, asset, target_ip, new_vulns_to_insert, scanner_name):
    from src.notifications.application.services.smtp import send_alert_email
    admin_email = getattr(scan, 'notify_email', None) if scan else None
    if not admin_email: admin_email = "admin@KVS.local"

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in new_vulns_to_insert:
        name = v.severity.name if hasattr(v.severity, 'name') else str(v.severity).split('.')[-1]
        if name in counts: counts[name] += 1

    content = f"{counts['CRITICAL']} critical, {counts['HIGH']} high, {counts['MEDIUM']} medium and {counts['LOW']} low vulnerabilities were found."
    send_alert_email(to_email=admin_email, subject=f"Scan Completed: {asset.name} ({scanner_name})", content=content, is_html=False)


def _identity_for(target_raw: str, host_ip: str) -> str:
    """Asset identity of a scanned host: the domain for a domain scan, the host IP otherwise."""
    try:
        target = parse_target(target_raw)
    except InvalidTargetError:
        return host_ip or target_raw
    if target.kind == "cidr":
        return host_ip or target_raw
    return target.host


@celery_app.task
def parse_scan_report(report_xml: str, target_ip: str, scan_id: str = None, final_state: str = progress.COMPLETED,
                      detail: str = None):
    """Stores an OpenVAS report. `target_ip` is the target as typed by the user."""
    from src.vulnerabilities.application.services.openvas_report import normalize_openvas
    logger.info(f"Parsing OpenVAS report for {target_ip} (Scan {scan_id})")
    db: Session = SessionLocal()
    try:
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first() if scan_id else None
        hosts = normalize_openvas(report_xml)
        total = 0
        for host_ip, data in hosts.items():
            asset = resolve_asset(db, scan.company_id if scan else None, _identity_for(target_ip, host_ip),
                                  resolved_ip=host_ip, network_zone=scan.network_zone if scan else None)
            if data["os"]:
                asset.operating_system = data["os"]
            if data["ports"] and not asset.ports:
                asset.ports = ", ".join(data["ports"])
            result = ingest_findings(db, asset, "OPENVAS", data["findings"])
            total += result.total
            db.flush()
            try:
                send_scan_summary_email(scan, asset, target_ip, result.new, "OpenVAS")
            except Exception as e:
                logger.warning(f"Scan summary email failed: {e}")
        db.flush()
        if scan:
            from src.scans.application.services.scan_assets import count_scan_findings
            scan.vulnerabilities_found = count_scan_findings(db, scan)
        db.commit()
        logger.info(f"OpenVAS report for {target_ip}: {len(hosts)} host(s), {total} findings stored")
        if scan_id:
            update_scan_progress(scan_id, target_ip, final_state, detail=detail)
    except Exception as e:
        logger.exception(f"Error parsing OpenVAS report: {str(e)}")
        db.rollback()
        if scan_id:
            update_scan_progress(scan_id, target_ip, progress.FAILED, detail=f"Analyse du rapport OpenVAS impossible : {e}"[:300])
    finally:
        db.close()


# ---------------------------------------------------------------------------------------------
# Tasks below were used by the previous version, which parsed results in separate tasks.
# They are kept so that messages still queued during an upgrade are processed correctly.

def _legacy_to_finding(v: Dict) -> Dict:
    cvss = sev.to_cvss(v.get("cvss_score", v.get("cvss")))
    return {
        "title": v.get("title") or v.get("name") or v.get("id") or "Finding",
        "severity": sev.resolve(v.get("severity"), cvss).value,
        "cvss": cvss,
        "cve_id": v.get("cve_id"),
        "cve_ids": v.get("cve_ids") or [],
        "description": v.get("description") or v.get("output") or "",
        "remediation": v.get("remediation") or "",
        "port": v.get("port"),
        "service": v.get("service"),
        "evidence": [v["matched_at"]] if v.get("matched_at") else [],
    }


def _legacy_ingest(engine: str, findings: List[Dict], target_ip: str, scan_id: str, host: Dict = None):
    db: Session = SessionLocal()
    try:
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first() if scan_id else None
        asset = resolve_asset(db, scan.company_id if scan else None, _identity_for(target_ip, (host or {}).get("ip")),
                              resolved_ip=(host or {}).get("ip"), network_zone=scan.network_zone if scan else None)
        if host:
            update_asset_from_host(asset, host)
        ingest_findings(db, asset, engine, findings)
        db.flush()
        if scan:
            from src.scans.application.services.scan_assets import count_scan_findings
            scan.vulnerabilities_found = count_scan_findings(db, scan)
        db.commit()
        if scan_id:
            update_scan_progress(scan_id, target_ip, progress.COMPLETED)
    except Exception as e:
        logger.exception(f"Error parsing legacy {engine} report: {e}")
        db.rollback()
        if scan_id:
            update_scan_progress(scan_id, target_ip, progress.FAILED)
    finally:
        db.close()


@celery_app.task
def parse_nmap_report(host_data: dict, target_ip: str, scan_id: str = None):
    _legacy_ingest("NMAP", [_legacy_to_finding(v) for v in host_data.get("vulns", [])], target_ip, scan_id, host_data)


@celery_app.task
def parse_nuclei_report(vuln_data_list: list, target_ip: str, scan_id: str = None):
    from src.scans.adapters.outbound.nuclei_adapter import normalize_nuclei
    _legacy_ingest("NUCLEI", normalize_nuclei(vuln_data_list), target_ip, scan_id)


@celery_app.task
def parse_zap_report(vuln_data_list: list, target_ip: str, scan_id: str = None):
    _legacy_ingest("OWASP_ZAP", [_legacy_to_finding(v) for v in vuln_data_list], target_ip, scan_id)
