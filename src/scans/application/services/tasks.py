import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from lxml import etree
from celery.exceptions import Retry
from sqlalchemy.orm import Session

from src.core.celery_app import celery_app
from src.core.database import SessionLocal
from src.scans.domain.entities import ScanEntity, ScanStatus, ScannerEngine
from src.scans.domain.targets import (
    ScanTarget, InvalidTargetError, parse_target, split_targets, build_url,
    web_urls_from_ports, open_ports, is_web_service,
)
from src.scans.adapters.outbound.base_adapter import ScanError, ScanTimeout
from src.scans.application.services import progress
from src.scans.application.services.progress import update_scan_progress  # noqa: F401  (re-exported)
from src.assets.domain.entities import AssetEntity

logger = logging.getLogger(__name__)

# Standard OpenVAS Default Scanner ID
DEFAULT_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
# Fast GVM "Host Discovery" Config ID (purely host up/down detection)
DISCOVERY_CONFIG_ID = "2d3f051c-55ba-11e3-bf43-406186ea4fc5"
# All TCP ports plus the UDP services that matter. A full UDP sweep (U:1-65535) made OpenVAS
# scans last for days and never complete.
DEFAULT_GVM_PORT_RANGE = "T:1-65535,U:53,67-69,123,137-138,161-162,500,514,520,623,1900,4500,5353"
OPENVAS_MAX_DURATION_S = 72 * 3600
WEB_PROBE_TIMEOUT_S = 15


# --------------------------------------------------------------------------- maintenance tasks

@celery_app.task(name="update_nuclei_templates")
def update_nuclei_templates():
    """Background task to update Nuclei templates daily to ensure the latest CVEs are covered."""
    logger.info("Running daily Nuclei templates update...")
    import subprocess
    try:
        result = subprocess.run(["/usr/local/bin/nuclei", "-ut"], capture_output=True, text=True, check=True)
        logger.info(f"Nuclei templates updated successfully: {result.stdout}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to update Nuclei templates: {e.stderr}")
    except Exception as e:
        logger.error(f"Error during Nuclei template update: {str(e)}")


@celery_app.task(name="update_nmap_scripts")
def update_nmap_scripts():
    """Background task to update the Nmap vulners script."""
    logger.info("Running Nmap scripts update...")
    import subprocess
    try:
        subprocess.run(
            ["wget", "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse", "-O", "/usr/share/nmap/scripts/vulners.nse"],
            capture_output=True, text=True, check=True
        )
        subprocess.run(["nmap", "--script-updatedb"], capture_output=True, text=True, check=True)
        logger.info("Nmap scripts updated successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to update Nmap scripts: {e.stderr}")
    except Exception as e:
        logger.error(f"Error during Nmap scripts update: {str(e)}")


@celery_app.task(name="update_zap_addons")
def update_zap_addons():
    """Background task to update ZAP add-ons."""
    logger.info("Running ZAP add-ons update...")
    import subprocess
    try:
        result = subprocess.run(["/opt/zaproxy/zap.sh", "-cmd", "-addonupdate"], capture_output=True, text=True, check=True)
        logger.info(f"ZAP add-ons updated successfully: {result.stdout}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to update ZAP add-ons: {e.stderr}")
    except Exception as e:
        logger.error(f"Error during ZAP add-ons update: {str(e)}")


def _audit(db: Session, action: str, scan_id: str, details: dict):
    from src.audit.domain.models import AuditLog
    db.add(AuditLog(user_id="system", username="celery_worker", action=action, resource_type="SCAN",
                    resource_id=str(scan_id), details=details))


def _profile_for(targets: List[ScanTarget]) -> str:
    """Aggressive timing only on internal networks; public targets get the 'internet' profile."""
    return "lan" if targets and all(t.is_private for t in targets) else "internet"


# --------------------------------------------------------------------------- discovery

@celery_app.task(bind=True, name="run_discovery_scan")
def run_discovery_scan(self, scan_id: str, target: str, network_zone: str, company_id: str):
    logger.info(f"Starting discovery scan {scan_id} on target {target}")
    db: Session = SessionLocal()
    scan_engine = ScannerEngine.NMAP
    try:
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        if not scan:
            return
        if scan.status == ScanStatus.PAUSED:
            logger.info(f"Scan {scan_id} is PAUSED. Aborting discovery task.")
            return True
        scan.status = ScanStatus.IN_PROGRESS
        scan_engine = scan.scanner_engine
        db.commit()
    finally:
        db.close()

    try:
        parsed = [parse_target(t) for t in split_targets(target)]
    except InvalidTargetError as e:
        logger.error(f"Discovery scan {scan_id}: {e}")
        _finish_discovery(scan_id, ScanStatus.FAILED, {"error": str(e)})
        return False

    if scan_engine == ScannerEngine.NMAP:
        return _run_nmap_discovery(scan_id, parsed, network_zone, company_id)

    from src.scans.adapters.outbound.gvm_adapter import GVMAdapter
    adapter = GVMAdapter()
    if not adapter.connect():
        logger.error("Failed to connect to GVM")
        if self.request.retries < 10:
            raise self.retry(countdown=60, max_retries=10)
        _finish_discovery(scan_id, ScanStatus.FAILED, {"error": "OpenVAS injoignable"})
        return False

    try:
        target_id = adapter.create_target(f"Discovery_Target_{scan_id}", [t.host for t in parsed])
        task_id = adapter.create_task(name=f"Discovery_Task_{scan_id}", target_id=target_id,
                                      scanner_id=DEFAULT_SCANNER_ID, config_id=DISCOVERY_CONFIG_ID)
        report_id = adapter.start_task(task_id)
        poll_discovery_scan_status.apply_async(args=[scan_id, task_id, report_id, network_zone, company_id], countdown=60)
        return True
    except Exception as e:
        logger.error(f"Discovery scan initialization failed: {str(e)}")
        _finish_discovery(scan_id, ScanStatus.FAILED, {"error": str(e)})
        return False
    finally:
        adapter.disconnect()


def _finish_discovery(scan_id: str, status: ScanStatus, details: dict):
    db = SessionLocal()
    try:
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        if scan:
            scan.status = status
            scan.progress = 100
            _audit(db, "SCAN_COMPLETED" if status == ScanStatus.COMPLETED else "SCAN_FAILED", scan_id,
                   {"status": status.name, **details})
            db.commit()
    finally:
        db.close()


def _upsert_discovered_asset(db: Session, company_id: str, network_zone: str, host: Dict) -> AssetEntity:
    asset = db.query(AssetEntity).filter(
        AssetEntity.ip_address == host["ip"],
        AssetEntity.company_id == company_id,
        AssetEntity.is_deleted == False  # noqa: E712
    ).first()
    if not asset:
        asset = AssetEntity(company_id=company_id, name=host.get("hostname") or host["ip"], ip_address=host["ip"],
                            asset_type="Unknown", network_zone=network_zone, operating_system="Unknown")
        db.add(asset)
    if host.get("hostname"):
        asset.name = host["hostname"]
    if host.get("mac_address"):
        asset.mac_address = host["mac_address"]
    if host.get("os") and host["os"] != "Unknown":
        asset.operating_system = host["os"]
    if host.get("ports"):
        asset.ports = host["ports"]
    if host.get("services"):
        asset.services = host["services"]
    return asset


def _run_nmap_discovery(scan_id: str, targets: List[ScanTarget], network_zone: str, company_id: str):
    from src.scans.adapters.outbound.nmap_adapter import NmapAdapter
    profile = _profile_for(targets)
    try:
        hosts = NmapAdapter.run_discovery_scan(",".join(t.host for t in targets), profile=profile)
    except Exception as e:
        logger.error(f"Nmap discovery failed: {e}")
        _finish_discovery(scan_id, ScanStatus.FAILED, {"error": str(e)})
        return False

    db = SessionLocal()
    try:
        for host in hosts:
            _upsert_discovered_asset(db, company_id, network_zone, host)
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        if scan:
            scan.progress = 50
        db.commit()

        failures = []
        for index, host in enumerate(hosts, start=1):
            logger.info(f"Discovery: detailed scan of host {index}/{len(hosts)} ({host['ip']})")
            try:
                detailed = NmapAdapter.run_detailed_discovery_scan(host["ip"], profile=profile)
                if detailed:
                    _upsert_discovered_asset(db, company_id, network_zone, detailed[0])
            except Exception as e:
                # One unreachable host must not lose the whole inventory
                logger.error(f"Discovery: detailed scan failed for {host['ip']}: {e}")
                failures.append(host["ip"])
            scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
            if scan:
                scan.progress = 50 + int(50 * (index / len(hosts)))
            db.commit()
    finally:
        db.close()

    status = ScanStatus.FAILED if hosts and len(failures) == len(hosts) else ScanStatus.COMPLETED
    _finish_discovery(scan_id, status, {"hosts_found": len(hosts), "detailed_failures": failures})
    logger.info(f"Nmap discovery scan {scan_id} finished: {len(hosts)} hosts, {len(failures)} detailed scan failures")
    return status == ScanStatus.COMPLETED


@celery_app.task(bind=True, max_retries=None)
def poll_discovery_scan_status(self, scan_id: str, task_id: str, report_id: str, network_zone: str, company_id: str):
    from src.scans.adapters.outbound.gvm_adapter import GVMAdapter
    adapter = GVMAdapter()
    if not adapter.connect():
        raise self.retry(countdown=60)

    try:
        status, progress_value = adapter.get_task_status_and_progress(task_id)
        db = SessionLocal()
        try:
            scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
            if scan:
                scan.progress = max(progress_value, 0)
                db.commit()
        finally:
            db.close()

        if status == "Done":
            parse_discovery_report.delay(adapter.get_report(report_id), scan_id, network_zone, company_id)
            return True
        if status in ["Stopped", "Interrupted"]:
            _finish_discovery(scan_id, ScanStatus.FAILED, {"error": f"OpenVAS task {status}"})
            return False
        raise self.retry(countdown=10)
    except Retry:
        raise
    except Exception as e:
        logger.error(f"Discovery polling failed: {str(e)}")
        raise self.retry(countdown=60)
    finally:
        adapter.disconnect()


@celery_app.task
def parse_discovery_report(report_xml: str, scan_id: str, network_zone: str, company_id: str):
    logger.info(f"Parsing discovery report for Scan {scan_id}")
    db: Session = SessionLocal()
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True)
        root = etree.fromstring(report_xml.encode('utf-8'), parser=parser)
        hosts_added = 0
        for host in root.xpath("//report/report/host"):
            ip_elem = host.find('ip')
            if ip_elem is None or not ip_elem.text:
                continue
            ip_address = ip_elem.text.strip()
            hostname_details = host.xpath(".//detail[name='hostname']/value/text()")
            os_details = host.xpath(".//detail[name='Best OS']/value/text()") or host.xpath(".//detail[name='OS']/value/text()")
            _upsert_discovered_asset(db, company_id, network_zone, {
                "ip": ip_address,
                "hostname": hostname_details[0].strip() if hostname_details else None,
                "os": os_details[0].strip() if os_details else None,
            })
            hosts_added += 1
        db.commit()
        _finish_discovery(scan_id, ScanStatus.COMPLETED, {"hosts_found": hosts_added})
        logger.info(f"Discovery scan {scan_id} completed. {hosts_added} hosts.")
    except Exception as e:
        logger.error(f"Error parsing discovery report: {str(e)}")
        db.rollback()
        _finish_discovery(scan_id, ScanStatus.FAILED, {"error": str(e)})
    finally:
        db.close()


# --------------------------------------------------------------------------- vulnerability scans

@dataclass
class ScanContext:
    scan_id: str
    company_id: str
    network_zone: Optional[str]
    engine: ScannerEngine
    port_range: Optional[str]
    credentials: Dict = field(default_factory=dict)
    profile: str = "internet"


def _select_policy(db: Session, scan: ScanEntity):
    from src.policies.domain.entities import PolicyEntity
    if scan.policy_id:
        return db.query(PolicyEntity).filter(PolicyEntity.id == scan.policy_id).first()
    # A company policy is applied implicitly only when it is unambiguous
    policies = db.query(PolicyEntity).filter(PolicyEntity.company_id == scan.company_id).limit(2).all()
    if len(policies) == 1:
        logger.info(f"Scan {scan.id}: applying the company's only policy '{policies[0].name}'")
        return policies[0]
    if len(policies) > 1:
        logger.warning(f"Scan {scan.id}: several company policies and none selected; using engine defaults")
    return None


def _load_credentials(db: Session, scan: ScanEntity, target: ScanTarget) -> Dict:
    from src.secrets.domain.entities import CredentialEntity
    credential = None
    if scan.credential_id:
        credential = db.query(CredentialEntity).filter(CredentialEntity.id == scan.credential_id).first()
    else:
        asset = db.query(AssetEntity).filter(
            AssetEntity.company_id == scan.company_id,
            AssetEntity.is_deleted == False,  # noqa: E712
            (AssetEntity.ip_address == target.host) | (AssetEntity.name == target.host),
        ).first()
        if asset:
            credential = db.query(CredentialEntity).filter(CredentialEntity.asset_id == asset.id).first()
    if not credential:
        return {}

    try:
        from src.secrets.adapters.outbound.vault import VaultAdapter
        secret = VaultAdapter().get_secret(credential.vault_path)
    except Exception as e:
        logger.error(f"Scan {scan.id}: cannot read credential '{credential.name}' from Vault: {e}")
        return {}
    if not secret:
        logger.error(f"Scan {scan.id}: credential '{credential.name}' is empty in Vault "
                     f"(Vault in dev mode loses its secrets on restart): scan runs unauthenticated")
        return {}
    # The type is stored in PostgreSQL only; the engines need it to pick the authentication method.
    return {**secret, "credential_type": credential.credential_type}


def _load_context(scan_id: str, target_raw: str, target: ScanTarget) -> Optional[ScanContext]:
    from sqlalchemy.orm.attributes import flag_modified
    db: Session = SessionLocal()
    try:
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        if not scan or scan.is_deleted:
            logger.info(f"Scan {scan_id} not found or deleted, skipping {target_raw}")
            return None

        states = dict(scan.target_states or {})
        if scan.status == ScanStatus.PAUSED:
            logger.info(f"Scan {scan_id} is PAUSED. Aborting task for {target_raw}.")
            states[target_raw] = progress.PENDING
            scan.target_states = states
            flag_modified(scan, "target_states")
            db.commit()
            return None

        states[target_raw] = progress.IN_PROGRESS
        scan.target_states = states
        flag_modified(scan, "target_states")
        scan.status = ScanStatus.IN_PROGRESS

        policy = _select_policy(db, scan)
        ctx = ScanContext(
            scan_id=scan_id,
            company_id=scan.company_id,
            network_zone=scan.network_zone,
            engine=scan.scanner_engine,
            port_range=policy.port_scanning_range if policy and policy.port_scanning_range else None,
            credentials=_load_credentials(db, scan, target),
            profile=_profile_for([target]),
        )
        db.commit()
        logger.info(f"Scan {scan_id} on {target_raw}: engine={ctx.engine.name} profile={ctx.profile} "
                    f"ports={ctx.port_range or 'all'} authenticated={'yes (' + str(ctx.credentials.get('credential_type')) + ')' if ctx.credentials else 'no'}")
        return ctx
    finally:
        db.close()


def _resolve_dns(host: str) -> Optional[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return None
    return infos[0][4][0] if infos else None


def _probe_web(host: str, path: str = "") -> List[str]:
    """Fallback when the port scan sees nothing (WAF/CDN dropping SYN probes): try HTTPS then HTTP."""
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    for scheme in ("https", "http"):
        url = build_url(scheme, host, None, path)
        try:
            requests.get(url, timeout=WEB_PROBE_TIMEOUT_S, verify=False, allow_redirects=False)
            logger.info(f"Web probe: {url} answers")
            return [url]
        except Exception as e:
            logger.info(f"Web probe: {url} unreachable ({type(e).__name__})")
    return []


def _identity(target: ScanTarget, host: Optional[Dict]) -> str:
    """What the asset is keyed on and what web engines must call: the domain for a domain scan."""
    if target.kind == "cidr" and host:
        return host["ip"]
    return target.host


def _save_host(ctx: ScanContext, target: ScanTarget, host: Optional[Dict], resolved_ip: Optional[str] = None) -> str:
    from src.vulnerabilities.application.services.ingest import resolve_asset, update_asset_from_host
    db = SessionLocal()
    try:
        asset = resolve_asset(db, ctx.company_id, _identity(target, host),
                              resolved_ip=(host or {}).get("ip") or resolved_ip,
                              hostname=(host or {}).get("hostname"), network_zone=ctx.network_zone)
        if host:
            update_asset_from_host(asset, host)
        db.commit()
        return asset.id
    finally:
        db.close()


def _store(ctx: ScanContext, asset_id: str, engine: str, findings: List[Dict]) -> int:
    from src.vulnerabilities.application.services.ingest import ingest_findings
    db = SessionLocal()
    try:
        asset = db.query(AssetEntity).filter(AssetEntity.id == asset_id).first()
        result = ingest_findings(db, asset, engine, findings)
        scan = db.query(ScanEntity).filter(ScanEntity.id == ctx.scan_id).first()
        if scan:
            scan.vulnerabilities_found = (scan.vulnerabilities_found or 0) + result.total
        db.commit()
        try:
            from src.vulnerabilities.application.services.tasks import send_scan_summary_email
            send_scan_summary_email(scan, asset, asset.ip_address, result.new, engine)
        except Exception as e:
            logger.warning(f"Scan summary email failed: {e}")
        return result.total
    finally:
        db.close()


def _aggregate(states: List[str]) -> str:
    for state in (progress.COMPLETED, progress.NO_WEB_SERVICE, progress.NO_OPEN_PORTS, progress.TIMEOUT):
        if state in states:
            return state
    return progress.HOST_UNREACHABLE


def _no_input_state(host: Optional[Dict], had_open_ports: bool) -> str:
    if host is None:
        return progress.HOST_UNREACHABLE
    if had_open_ports:
        return progress.NO_WEB_SERVICE
    return progress.TIMEOUT if host.get("timed_out") else progress.NO_OPEN_PORTS


def _phase1(ctx: ScanContext, target: ScanTarget, tolerate_failure: bool) -> List[Dict]:
    """Ports, services and OS discovery shared by every engine except OpenVAS."""
    from src.scans.adapters.outbound.nmap_adapter import NmapAdapter
    try:
        hosts = NmapAdapter.run_detailed_discovery_scan(target.host, ports=ctx.port_range,
                                                        credentials=ctx.credentials, profile=ctx.profile)
    except ScanError as e:
        if not tolerate_failure:
            raise
        logger.warning(f"Phase 1 (Nmap) failed on {target.host}, continuing with web probing: {e}")
        return []
    for host in hosts:
        n_open = len(open_ports(host.get("ports")))
        logger.info(f"Phase 1 on {target.host}: host {host['ip']} has {n_open} open port(s)"
                    + (" — Nmap host timeout reached, results incomplete" if host.get("timed_out") else ""))
    return hosts


def _run_nmap(ctx: ScanContext, target: ScanTarget) -> str:
    from src.scans.adapters.outbound.nmap_adapter import NmapAdapter
    hosts = _phase1(ctx, target, tolerate_failure=False)
    if not hosts:
        return progress.HOST_UNREACHABLE
    states = []
    for host in hosts:
        asset_id = _save_host(ctx, target, host)
        tcp_ports = [str(p["port"]) for p in open_ports(host["ports"]) if (p.get("protocol") or "tcp") == "tcp"]
        if not tcp_ports:
            states.append(_no_input_state(host, False))
            continue
        scan_host = _identity(target, host)
        logger.info(f"Phase 2: Nmap vulnerability scripts on {scan_host} ports {','.join(tcp_ports)}")
        vuln_hosts = NmapAdapter.run_vulnerability_scan(scan_host, ports=",".join(tcp_ports),
                                                        credentials=ctx.credentials, profile=ctx.profile)
        findings = [f for vh in vuln_hosts for f in vh.get("vulns", [])]
        _store(ctx, asset_id, "NMAP", findings)
        states.append(progress.COMPLETED)
    return _aggregate(states)


def _web_work(ctx: ScanContext, target: ScanTarget, include_network: bool) -> List[Tuple[str, List[str], Optional[Dict], bool]]:
    """Builds, per host, the inputs of the web engines: (asset_id, inputs, host, had_open_ports)."""
    if target.is_url:
        # The user pointed at a precise application: scan exactly that URL (no 65 535-port sweep).
        asset_id = _save_host(ctx, target, None, resolved_ip=_resolve_dns(target.host) if target.is_hostname else None)
        return [(asset_id, [target.url], None, True)]

    hosts = _phase1(ctx, target, tolerate_failure=target.kind != "cidr")
    work = []
    if not hosts and target.kind != "cidr":
        hosts = [None]
    for host in hosts:
        label = _identity(target, host)
        ports = open_ports(host.get("ports")) if host else []
        web_urls = web_urls_from_ports(label, ports)
        if not web_urls and target.kind != "cidr":
            # Port scan saw no web service (WAF/CDN dropping probes, timeout, unidentified service)
            web_urls = _probe_web(label)
        inputs = list(web_urls)
        if include_network:
            netloc = f"[{label}]" if ":" in label else label
            inputs += [f"{netloc}:{p['port']}" for p in ports
                       if not is_web_service(p.get("service"), p.get("tunnel"), p.get("port"))]
        asset_id = _save_host(ctx, target, host, resolved_ip=None if host else _resolve_dns(target.host))
        work.append((asset_id, list(dict.fromkeys(inputs)), host, bool(ports)))
    return work


def _run_nuclei(ctx: ScanContext, target: ScanTarget) -> str:
    from src.scans.adapters.outbound.nuclei_adapter import NucleiAdapter, normalize_nuclei
    states = []
    for asset_id, inputs, host, had_ports in _web_work(ctx, target, include_network=True):
        if not inputs:
            states.append(_no_input_state(host, had_ports))
            continue
        logger.info(f"Phase 2: Nuclei on {inputs}")
        raw = NucleiAdapter.run_scan(inputs, credentials=ctx.credentials, profile=ctx.profile)
        _store(ctx, asset_id, "NUCLEI", normalize_nuclei(raw))
        states.append(progress.COMPLETED)
    return _aggregate(states)


def _run_zap(ctx: ScanContext, target: ScanTarget) -> str:
    from src.scans.adapters.outbound.zap_adapter import ZAPAdapter, normalize_zap
    states = []
    for asset_id, inputs, host, had_ports in _web_work(ctx, target, include_network=False):
        if not inputs:
            states.append(_no_input_state(host, had_ports))
            continue
        logger.info(f"Phase 2: OWASP ZAP on {inputs}")
        alerts = ZAPAdapter.run_scan(inputs, credentials=ctx.credentials)
        _store(ctx, asset_id, "OWASP_ZAP", normalize_zap(alerts))
        states.append(progress.COMPLETED)
    return _aggregate(states)


ENGINE_RUNNERS = {
    ScannerEngine.NMAP: _run_nmap,
    ScannerEngine.NUCLEI: _run_nuclei,
    ScannerEngine.OWASP_ZAP: _run_zap,
}


@celery_app.task(bind=True, max_retries=1, name="run_vulnerability_scan")
def run_vulnerability_scan(self, scan_id: str, asset_ip: str, asset_name: str, config_id: str):
    """Scans one target of a scan. `asset_ip` is the target as typed by the user (IP, CIDR, domain or URL)."""
    target_raw = asset_ip
    logger.info(f"Starting vulnerability scan {scan_id} on {target_raw}")
    try:
        target = parse_target(target_raw)
    except InvalidTargetError as e:
        logger.error(f"Scan {scan_id}: {e}")
        update_scan_progress(scan_id, target_raw, progress.INVALID_TARGET)
        return False

    ctx = _load_context(scan_id, target_raw, target)
    if ctx is None:
        return True

    if target.is_hostname and not _resolve_dns(target.host):
        logger.error(f"Scan {scan_id}: DNS resolution failed for {target.host}")
        update_scan_progress(scan_id, target_raw, progress.HOST_UNREACHABLE)
        return False

    if ctx.engine == ScannerEngine.OPENVAS:
        return _start_openvas(self, ctx, target, target_raw, asset_name, config_id)

    runner = ENGINE_RUNNERS.get(ctx.engine)
    if runner is None:
        logger.error(f"Scan {scan_id}: unsupported engine {ctx.engine}")
        update_scan_progress(scan_id, target_raw, progress.FAILED)
        return False

    try:
        state = runner(ctx, target)
    except Retry:
        raise
    except ScanTimeout as e:
        logger.error(f"{ctx.engine.name} scan timed out for {target_raw}: {e}")
        update_scan_progress(scan_id, target_raw, progress.TIMEOUT)
        return False
    except Exception as e:
        logger.exception(f"{ctx.engine.name} scan failed for {target_raw}: {e}")
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e, countdown=120)
        update_scan_progress(scan_id, target_raw, progress.FAILED)
        return False

    logger.info(f"{ctx.engine.name} scan of {target_raw} finished: {state}")
    update_scan_progress(scan_id, target_raw, state)
    return state in progress.SUCCESS_STATES


def _gvm_port_range(port_range: Optional[str]) -> str:
    if not port_range:
        return DEFAULT_GVM_PORT_RANGE
    included = [p.strip() for p in port_range.split(",") if p.strip() and not p.strip().startswith("!")]
    return f"T:{','.join(included)}" if included else DEFAULT_GVM_PORT_RANGE


def _start_openvas(task, ctx: ScanContext, target: ScanTarget, target_raw: str, asset_name: str, config_id: str):
    from src.scans.adapters.outbound.gvm_adapter import GVMAdapter
    adapter = GVMAdapter()
    if not adapter.connect():
        logger.error("Failed to connect to GVM")
        if task.request.retries < 10:
            raise task.retry(countdown=60, max_retries=10)
        update_scan_progress(ctx.scan_id, target_raw, progress.FAILED)
        return False
    try:
        if ctx.credentials:
            logger.warning(f"OpenVAS: credentials are not passed to GVM yet, {target_raw} is scanned unauthenticated")
        target_id = adapter.create_target(f"Target_{asset_name}_{ctx.scan_id}", [target.host],
                                          port_range=_gvm_port_range(ctx.port_range))
        task_id = adapter.create_task(f"Task_{asset_name}_{ctx.scan_id}", target_id, DEFAULT_SCANNER_ID, config_id)
        report_id = adapter.start_task(task_id)
        poll_scan_status.apply_async(args=[ctx.scan_id, task_id, report_id, target_raw],
                                     kwargs={"started_at": time.time()}, countdown=60)
        return True
    except Exception as e:
        logger.error(f"OpenVAS scan initialization failed for {target_raw}: {e}")
        update_scan_progress(ctx.scan_id, target_raw, progress.FAILED)
        return False
    finally:
        adapter.disconnect()


@celery_app.task(bind=True, max_retries=None)
def poll_scan_status(self, scan_id: str, task_id: str, report_id: str, asset_ip: str, started_at: float = None):
    from src.scans.adapters.outbound.gvm_adapter import GVMAdapter
    adapter = GVMAdapter()
    if not adapter.connect():
        raise self.retry(countdown=60)

    try:
        status, progress_value = adapter.get_task_status_and_progress(task_id)
        logger.info(f"OpenVAS task {task_id} ({asset_ip}): {status} {progress_value}%")

        if status == "Done":
            parse_report(adapter, report_id, asset_ip, scan_id, progress.COMPLETED)
            return True
        if status in ("Stopped", "Interrupted"):
            parse_report(adapter, report_id, asset_ip, scan_id, progress.INTERRUPTED)
            return False
        if started_at and time.time() - started_at > OPENVAS_MAX_DURATION_S:
            logger.error(f"OpenVAS task {task_id} exceeded {OPENVAS_MAX_DURATION_S // 3600} h, stopping it")
            try:
                adapter.gmp.stop_task(task_id=task_id)
            except Exception as e:
                logger.warning(f"Could not stop OpenVAS task {task_id}: {e}")
            parse_report(adapter, report_id, asset_ip, scan_id, progress.TIMEOUT)
            return False
        raise self.retry(countdown=30)
    except Retry:
        raise
    except Exception as e:
        logger.error(f"Polling failed: {str(e)}")
        raise self.retry(countdown=60)
    finally:
        adapter.disconnect()


def parse_report(adapter, report_id: str, asset_ip: str, scan_id: str, final_state: str):
    report_xml = adapter.get_report(report_id)
    from src.vulnerabilities.application.services.tasks import parse_scan_report
    parse_scan_report.delay(report_xml, asset_ip, scan_id, final_state)


# --------------------------------------------------------------------------- AI

@celery_app.task(name="generate_ai_summary_task", bind=True, max_retries=3, ignore_result=False)
def generate_ai_summary_task(self, vuln_data: list, language: str = "French", extra_instructions: str = "", provider: str = None):
    import asyncio
    from src.ai.application.services.nlp import generate_executive_summary

    logger.info(f"Task {self.request.id}: Starting AI summary generation...")
    try:
        summary = asyncio.run(generate_executive_summary(vuln_data, language=language, extra_instructions=extra_instructions, provider=provider))
        logger.info(f"Task {self.request.id}: AI summary generation completed successfully.")
        return summary
    except Exception as e:
        logger.error(f"Task {self.request.id}: AI summary generation failed: {str(e)}")
        raise self.retry(exc=e, countdown=30)


@celery_app.task(name="generate_ai_remediation_task", bind=True, max_retries=3, ignore_result=False)
def generate_ai_remediation_task(self, vuln_name: str, vuln_desc: str, language: str = "French", provider: str = None):
    import asyncio
    from src.ai.application.services.nlp import generate_vulnerability_remediation

    logger.info(f"Task {self.request.id}: Starting AI remediation generation for '{vuln_name}'...")
    try:
        remediation = asyncio.run(generate_vulnerability_remediation(vuln_name, vuln_desc, language=language, provider=provider))
        logger.info(f"Task {self.request.id}: AI remediation generation completed successfully.")
        return remediation
    except Exception as e:
        logger.error(f"Task {self.request.id}: AI remediation generation failed: {str(e)}")
        raise self.retry(exc=e, countdown=30)
