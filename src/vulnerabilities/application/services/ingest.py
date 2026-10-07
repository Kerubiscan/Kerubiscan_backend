"""Single path used by every engine to store assets and findings.

Normalised finding (dict) produced by the engines:
    title, severity (VulnSeverity value), cvss, cve_id, cve_ids, description, remediation,
    port, service, evidence (list of URLs / locations)
"""
import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy.sql import func
from src.assets.domain.entities import AssetEntity
from src.vulnerabilities.domain.entities import VulnerabilityEntity
from src.vulnerabilities.domain.models import VulnSeverity, VulnStatus

logger = logging.getLogger(__name__)

# Used when an engine gives no CVSS, so that every finding can be ranked by risk.
_SEVERITY_SCORE = {
    VulnSeverity.CRITICAL: 9.5, VulnSeverity.HIGH: 8.0, VulnSeverity.MEDIUM: 5.5,
    VulnSeverity.LOW: 2.0, VulnSeverity.INFO: 0.0,
}

MAX_EVIDENCE_LINES = 20


@dataclass
class IngestResult:
    new: List[VulnerabilityEntity]
    updated: int

    @property
    def total(self) -> int:
        return len(self.new) + self.updated


def calculate_contextual_risk(base_score: float, criticality) -> float:
    # Asset criticality: Low=0.5, Medium=0.75, High=1.0, Critical=1.25
    multiplier = 1.0
    crit_str = str(criticality.value) if hasattr(criticality, 'value') else str(criticality)
    if crit_str == "Low": multiplier = 0.5
    elif crit_str == "Medium": multiplier = 0.75
    elif crit_str == "High": multiplier = 1.0
    elif crit_str == "Critical": multiplier = 1.25
    return round((base_score or 0.0) * multiplier, 1)


def _active_assets(db: Session, company_id: Optional[str]):
    q = db.query(AssetEntity).filter(AssetEntity.is_deleted == False)  # noqa: E712
    if company_id:
        q = q.filter(AssetEntity.company_id == company_id)
    return q


def resolve_asset(db: Session, company_id: Optional[str], identity: str, resolved_ip: Optional[str] = None,
                  hostname: Optional[str] = None, network_zone: Optional[str] = None) -> AssetEntity:
    """Finds or creates the asset of a scanned host, scoped to the company and ignoring deleted assets.

    `identity` is what the user scanned: the domain for a domain scan (it is never replaced by the
    resolved IP any more, otherwise later scans lose the virtual host), the IP otherwise.
    """
    asset = _active_assets(db, company_id).filter(AssetEntity.ip_address == identity).first()
    if asset is None:
        # Assets created before this fix stored the domain in `name` and the resolved IP in `ip_address`
        asset = _active_assets(db, company_id).filter(AssetEntity.name == identity).first()
        if asset is not None and asset.ip_address != identity:
            logger.info(f"Asset {asset.id}: restoring scanned identity {identity} (was {asset.ip_address})")
            asset.ip_address = identity
    if asset is None:
        asset = AssetEntity(
            company_id=company_id,
            name=hostname or identity,
            ip_address=identity,
            asset_type="Unknown",
            network_zone=network_zone or "Internal",
            operating_system="Unknown",
        )
        db.add(asset)
        db.flush()
    if resolved_ip and resolved_ip != identity:
        asset.resolved_ip = resolved_ip
    return asset


def update_asset_from_host(asset: AssetEntity, host: Dict) -> None:
    if host.get("os") and host["os"] != "Unknown":
        asset.operating_system = host["os"]
    if host.get("ports"):
        asset.ports = host["ports"]
        flag_modified(asset, "ports")
    if host.get("services"):
        asset.services = host["services"]
        flag_modified(asset, "services")
    if host.get("mac_address"):
        asset.mac_address = host["mac_address"]
    raw = {k: v for k, v in host.items() if k != "vulns"}
    asset.last_scan_raw_output = json.dumps(raw, indent=2, default=str)


def _description(finding: Dict) -> str:
    parts = [finding.get("description") or ""]
    other_cves = [c for c in finding.get("cve_ids") or [] if c != finding.get("cve_id")]
    if other_cves:
        parts.append("Autres CVE : " + ", ".join(other_cves))
    evidence = finding.get("evidence") or []
    if evidence:
        lines = evidence[:MAX_EVIDENCE_LINES]
        more = len(evidence) - len(lines)
        parts.append("Emplacements :\n" + "\n".join(f"- {e}" for e in lines) + (f"\n- … et {more} autre(s)" if more > 0 else ""))
    return "\n\n".join(p for p in parts if p).strip()


def ingest_findings(db: Session, asset: AssetEntity, engine: str, findings: List[Dict]) -> IngestResult:
    """Stores findings for one asset and one engine.

    Deduplication key: (title, port). Two occurrences of the same issue on two ports are two
    findings; repeated scans update the existing finding instead of creating a duplicate.
    """
    existing = db.query(VulnerabilityEntity).filter(
        VulnerabilityEntity.asset_id == asset.id,
        VulnerabilityEntity.source_engine == engine,
    ).all()
    index = {(v.title, v.port): v for v in existing}

    new, updated = [], 0
    for f in findings:
        title = (f.get("title") or f"{engine} finding")[:250]
        port = f.get("port")
        severity = VulnSeverity(f.get("severity") or VulnSeverity.INFO.value)
        cvss = f.get("cvss")
        risk = calculate_contextual_risk(cvss if cvss is not None else _SEVERITY_SCORE[severity], asset.criticality)
        description = _description(f)

        vuln = index.get((title, port))
        if vuln is not None:
            vuln.last_seen_at = func.now()
            vuln.severity = severity
            vuln.cvss_base_score = cvss
            vuln.contextual_risk_score = risk
            vuln.description = description
            if f.get("remediation"):
                vuln.remediation = f["remediation"]
            if vuln.status == VulnStatus.FIXED:
                logger.warning(f"Regression detected for {title} on asset {asset.id}")
                vuln.status = VulnStatus.NEW
            updated += 1
            continue

        vuln = VulnerabilityEntity(
            asset_id=asset.id,
            cve_id=f.get("cve_id"),
            title=title,
            description=description,
            remediation=f.get("remediation") or None,
            cvss_base_score=cvss,
            contextual_risk_score=risk,
            severity=severity,
            port=port,
            service=f.get("service"),
            source_engine=engine,
            status=VulnStatus.NEW,
        )
        db.add(vuln)
        index[(title, port)] = vuln
        new.append(vuln)

    logger.info(f"{engine}: {len(new)} new and {updated} updated findings on asset {asset.id} ({asset.ip_address})")
    return IngestResult(new=new, updated=updated)
