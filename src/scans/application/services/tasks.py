from src.core.celery_app import celery_app
from src.scans.adapters.outbound.gvm_adapter import GVMAdapter
import logging
from lxml import etree
from celery.exceptions import Retry
from sqlalchemy.orm import Session
from src.core.database import SessionLocal
from src.scans.domain.entities import ScanEntity, ScanStatus, ScannerEngine
from src.assets.domain.entities import AssetEntity
from src.companies.domain.entities import CompanyEntity

logger = logging.getLogger(__name__)

# Standard OpenVAS Default Scanner ID
DEFAULT_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"

@celery_app.task(name="update_nuclei_templates")
def update_nuclei_templates():
    """Background task to update Nuclei templates daily to ensure the latest CVEs are covered."""
    logger.info("Running daily Nuclei templates update...")
    import subprocess
    try:
        result = subprocess.run(
            ["/usr/local/bin/nuclei", "-ut"],
            capture_output=True, text=True, check=True
        )
        logger.info(f"Nuclei templates updated successfully: {result.stdout}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to update Nuclei templates: {e.stderr}")
    except Exception as e:
        logger.error(f"Error during Nuclei template update: {str(e)}")

@celery_app.task(name="update_nmap_scripts")
def update_nmap_scripts():
    """Background task to update Nmap vulners and vulscan databases."""
    logger.info("Running Nmap scripts update...")
    import subprocess
    try:
        # Update vulners
        subprocess.run(
            ["wget", "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse", "-O", "/usr/share/nmap/scripts/vulners.nse"],
            capture_output=True, text=True, check=True
        )
        # Update vulscan
        subprocess.run(
            ["git", "-C", "/usr/share/nmap/scripts/vulscan", "pull"],
            capture_output=True, text=True, check=True
        )
        # Update nmap script DB
        subprocess.run(
            ["nmap", "--script-updatedb"],
            capture_output=True, text=True, check=True
        )
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
        result = subprocess.run(
            ["/opt/zaproxy/zap.sh", "-cmd", "-addonupdate"],
            capture_output=True, text=True, check=True
        )
        logger.info(f"ZAP add-ons updated successfully: {result.stdout}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to update ZAP add-ons: {e.stderr}")
    except Exception as e:
        logger.error(f"Error during ZAP add-ons update: {str(e)}")

def update_scan_progress(scan_id: str, ip: str, target_status: str):
    db: Session = SessionLocal()
    try:
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        if scan and scan.target_states:
            states = dict(scan.target_states)
            states[ip] = target_status
            scan.target_states = states
            
            total = len(states)
            completed = sum(1 for s in states.values() if s in ["COMPLETED", "FAILED"])
            scan.progress = int((completed / total) * 100) if total > 0 else 100
            
            if completed == total:
                scan.status = ScanStatus.COMPLETED
                from src.audit.domain.models import AuditLog
                db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_COMPLETED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "COMPLETED"}))
            db.commit()
    finally:
        db.close()

# Fast GVM "Host Discovery" Config ID (purely host up/down detection)
DISCOVERY_CONFIG_ID = "2d3f051c-55ba-11e3-bf43-406186ea4fc5"

@celery_app.task(bind=True, name="run_discovery_scan")
def run_discovery_scan(self, scan_id: str, target: str, network_zone: str, company_id: str):
    logger.info(f"Starting OpenVAS discovery scan {scan_id} on target {target}")
    db: Session = SessionLocal()
    from src.scans.domain.entities import ScannerEngine
    scan_engine = ScannerEngine.NMAP # default
    try:
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        if not scan:
            return
            
        scan.status = ScanStatus.IN_PROGRESS
        scan_engine = scan.scanner_engine
        db.commit()
    finally:
        db.close()
    
    if scan_engine == ScannerEngine.NMAP:
        try:
            from src.scans.adapters.outbound.nmap_adapter import NmapAdapter
            logger.info(f"Phase 1: Fast ping sweep on {target}")
            hosts = NmapAdapter.run_discovery_scan(target)
            
            db = SessionLocal()
            try:
                # Phase 1: Save basic hosts
                discovered_ips = []
                for host_data in hosts:
                    ip = host_data["ip"]
                    discovered_ips.append(ip)
                    existing_asset = db.query(AssetEntity).filter(
                        AssetEntity.ip_address == ip, 
                        AssetEntity.company_id == company_id,
                        AssetEntity.is_deleted == False
                    ).first()
                    
                    if not existing_asset:
                        new_asset = AssetEntity(
                            company_id=company_id,
                            name=host_data["hostname"] or ip,
                            ip_address=ip,
                            asset_type="Unknown",
                            network_zone=network_zone,
                            mac_address=host_data.get("mac_address"),
                            operating_system=host_data["os"],
                            ports=host_data["ports"]
                        )
                        db.add(new_asset)
                
                scan_update = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
                if scan_update:
                    scan_update.progress = 50
                db.commit()
                
                if discovered_ips:
                    logger.info(f"Phase 2: Detailed scan on {len(discovered_ips)} discovered hosts one-by-one")
                    total_hosts = len(discovered_ips)
                    
                    for index, ip in enumerate(discovered_ips, start=1):
                        logger.info(f"Phase 2: Scanning host {index}/{total_hosts} ({ip})")
                        detailed_hosts = NmapAdapter.run_detailed_discovery_scan(ip)
                        
                        if detailed_hosts:
                            d_host = detailed_hosts[0]
                            asset_to_update = db.query(AssetEntity).filter(
                                AssetEntity.ip_address == d_host["ip"],
                                AssetEntity.company_id == company_id,
                                AssetEntity.is_deleted == False
                            ).first()
                            
                            if asset_to_update:
                                if d_host.get("hostname"):
                                    asset_to_update.name = d_host["hostname"]
                                if d_host.get("mac_address"):
                                    asset_to_update.mac_address = d_host["mac_address"]
                                if d_host.get("os") and d_host.get("os") != "Unknown":
                                    asset_to_update.operating_system = d_host["os"]
                                if d_host.get("ports"):
                                    asset_to_update.ports = d_host["ports"]
                        
                        # Update scan progress
                        scan_update = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
                        if scan_update:
                            scan_update.progress = 50 + int(50 * (index / total_hosts))
                        db.commit()
                                
                scan_update = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
                if scan_update:
                    scan_update.status = ScanStatus.COMPLETED
                    from src.audit.domain.models import AuditLog
                    db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_COMPLETED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "COMPLETED"}))
                    scan_update.progress = 100
                db.commit()
                logger.info(f"Nmap discovery scan {scan_id} completed successfully.")
                return True
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Nmap discovery failed: {str(e)}")
            db = SessionLocal()
            try:
                scan_fail = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
                if scan_fail:
                    scan_fail.status = ScanStatus.FAILED
                    from src.audit.domain.models import AuditLog
                    db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_FAILED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "FAILED"}))
                    db.commit()
            finally:
                db.close()
            raise e
            
    # Default to OpenVAS
    adapter = GVMAdapter()
    if not adapter.connect():
        logger.error("Failed to connect to GVM")
        self.retry(countdown=60)
        return
        
    try:
        # Create a target for the discovery scan (e.g., using a CIDR block)
        target_id = adapter.create_target(f"Discovery_Target_{scan_id}", [target])
        
        # Create task using the Discovery config
        task_id = adapter.create_task(
            name=f"Discovery_Task_{scan_id}", 
            target_id=target_id, 
            scanner_id=DEFAULT_SCANNER_ID, 
            config_id=DISCOVERY_CONFIG_ID
        )
        report_id = adapter.start_task(task_id)
        
        adapter.disconnect()
        
        # Poll the status asynchronously
        poll_discovery_scan_status.apply_async(args=[scan_id, task_id, report_id, network_zone, company_id], countdown=60)
        return True
        
    except Exception as e:
        logger.error(f"Discovery scan initialization failed: {str(e)}")
        adapter.disconnect()
        
        db = SessionLocal()
        try:
            scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                from src.audit.domain.models import AuditLog
                db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_FAILED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "FAILED"}))
                db.commit()
        finally:
            db.close()
        raise e

@celery_app.task(bind=True, max_retries=None)
def poll_discovery_scan_status(self, scan_id: str, task_id: str, report_id: str, network_zone: str, company_id: str):
    adapter = GVMAdapter()
    if not adapter.connect():
        self.retry(countdown=60)
        return
        
    try:
        status, progress = adapter.get_task_status_and_progress(task_id)
        
        db = SessionLocal()
        try:
            scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
            if scan:
                scan.progress = progress
                db.commit()
        finally:
            db.close()

        if status == "Done":
            report_xml = adapter.get_report(report_id)
            adapter.disconnect()
            
            # Send to discovery parser
            parse_discovery_report.delay(report_xml, scan_id, network_zone, company_id)
            return True
            
        elif status in ["Stopped", "Interrupted"]:
            adapter.disconnect()
            
            db = SessionLocal()
            try:
                scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.FAILED
                    from src.audit.domain.models import AuditLog
                    db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_FAILED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "FAILED"}))
                    db.commit()
            finally:
                db.close()
            return False
            
        else:
            adapter.disconnect()
            self.retry(countdown=10)
            
    except Exception as e:
        if isinstance(e, Retry):
            raise
        logger.error(f"Discovery polling failed: {str(e)}")
        adapter.disconnect()
        self.retry(countdown=60)

@celery_app.task
def parse_discovery_report(report_xml: str, scan_id: str, network_zone: str, company_id: str):
    logger.info(f"Parsing discovery report for Scan {scan_id}")
    db: Session = SessionLocal()
    
    try:
        root = etree.fromstring(report_xml.encode('utf-8'))
        hosts_added = 0
        
        # Use XPath to find all <host> elements within the report
        hosts = root.xpath("//report/report/host")
        
        for host in hosts:
            ip_elem = host.find('ip')
            if ip_elem is not None and ip_elem.text:
                ip_address = ip_elem.text.strip()
                
                # Attempt to get hostname from details
                hostname = f"Discovered Host ({ip_address})"
                
                # Sometimes GVM provides hostname in a detail tag
                hostname_details = host.xpath(".//detail[name='hostname']/value/text()")
                if hostname_details:
                    hostname = hostname_details[0].strip()
                    
                # Extract OS
                os_val = "Unknown"
                os_details = host.xpath(".//detail[name='Best OS']/value/text()")
                if not os_details:
                    os_details = host.xpath(".//detail[name='OS']/value/text()")
                if os_details:
                    os_val = os_details[0].strip()

                # Extract Ports
                host_ports = []
                results_for_host = root.xpath(f"//result[host='{ip_address}']")
                for r in results_for_host:
                    port_elem = r.find('port')
                    if port_elem is not None and port_elem.text:
                        p_text = port_elem.text.strip()
                        if p_text != "general/tcp" and p_text != "general/udp" and p_text not in host_ports:
                            host_ports.append(p_text)
                
                ports_str = ", ".join(host_ports) if host_ports else None
                    
                new_asset = AssetEntity(
                    company_id=company_id,
                    name=hostname,
                    ip_address=ip_address,
                    asset_type="Unknown",
                    network_zone=network_zone,
                    operating_system=os_val,
                    ports=ports_str
                )
                db.add(new_asset)
                hosts_added += 1
                    
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.COMPLETED
            from src.audit.domain.models import AuditLog
            db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_COMPLETED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "COMPLETED"}))
            scan.progress = 100
        db.commit()
        
        logger.info(f"Discovery scan {scan_id} completed. Added {hosts_added} hosts.")
        
    except Exception as e:
        logger.error(f"Error parsing discovery report: {str(e)}")
        db.rollback()
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            from src.audit.domain.models import AuditLog
            db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_FAILED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "FAILED"}))
            db.commit()
    finally:
                    db.close()


@celery_app.task(bind=True, max_retries=3, name="run_vulnerability_scan")
def run_vulnerability_scan(self, scan_id: str, asset_ip: str, asset_name: str, config_id: str):
    logger.info(f"Starting vulnerability scan for scan_id: {scan_id}, target: {asset_ip}")
    db: Session = SessionLocal()
    scan_engine = ScannerEngine.OPENVAS
    policy = None
    credential = None
    vault_secret = {}
    
    try:
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        if scan:
            if not scan.target_states:
                scan.target_states = {}
            
            # Make a copy of target_states, update the current IP, and reassign so SQLAlchemy detects the change
            current_states = dict(scan.target_states)
            current_states[asset_ip] = "IN_PROGRESS"
            scan.target_states = current_states
            
            if scan.status != ScanStatus.IN_PROGRESS:
                scan.status = ScanStatus.IN_PROGRESS
            scan_engine = scan.scanner_engine
            
            from src.policies.domain.entities import PolicyEntity
            from src.secrets.domain.entities import CredentialEntity
            from src.assets.domain.entities import AssetEntity
            from src.secrets.adapters.outbound.vault import VaultAdapter

            # 1. Fetch policy (explicit policy_id OR automatic lookup for company_id)
            if scan.policy_id:
                policy = db.query(PolicyEntity).filter(PolicyEntity.id == scan.policy_id).first()
            elif scan.company_id:
                policy = db.query(PolicyEntity).filter(PolicyEntity.company_id == scan.company_id).first()
                
            # 2. Fetch credential (explicit credential_id OR automatic lookup for asset/company_id)
            if scan.credential_id:
                credential = db.query(CredentialEntity).filter(CredentialEntity.id == scan.credential_id).first()
            elif scan.company_id:
                asset = db.query(AssetEntity).filter(
                    AssetEntity.ip_address == asset_ip,
                    AssetEntity.company_id == scan.company_id,
                    AssetEntity.is_deleted == False
                ).first()
                if asset:
                    credential = db.query(CredentialEntity).filter(CredentialEntity.asset_id == asset.id).first()
                    
            if credential:
                try:
                    vault = VaultAdapter()
                    vault_secret = vault.get_secret(credential.vault_path)
                except Exception as ve:
                    logger.warning(f"Could not fetch secret from Vault at {credential.vault_path}: {ve}")
                    vault_secret = {}
            
            db.commit()
    finally:
        db.close()

    port_range = policy.port_scanning_range if policy and policy.port_scanning_range else None

    if scan_engine == ScannerEngine.NMAP:
        try:
            from src.scans.adapters.outbound.nmap_adapter import NmapAdapter
            import json
            
            # --- PHASE 1: Ports, Services, OS ---
            logger.info(f"Phase 1: Running detailed discovery on {asset_ip}")
            discovery_hosts = NmapAdapter.run_detailed_discovery_scan(asset_ip, ports=port_range, credentials=vault_secret)
            
            open_ports_list = []
            
            # Save Phase 1 results directly to DB without triggering COMPLETED status
            db = SessionLocal()
            try:
                if discovery_hosts:
                    for host_data in discovery_hosts:
                        host_ip = host_data.get("ip", asset_ip)
                        
                        if host_data.get("ports"):
                            port_list = host_data["ports"]
                            if isinstance(port_list, str):
                                port_list = [p.strip() for p in port_list.split(",") if p.strip()]
                            for p in port_list:
                                port_num = p.split('/')[0]
                                open_ports_list.append(port_num)
                                
                        asset = db.query(AssetEntity).filter(AssetEntity.ip_address == asset_ip).first()
                        if not asset:
                            asset = db.query(AssetEntity).filter(AssetEntity.name == asset_ip).first()
                        if not asset:
                            asset = db.query(AssetEntity).filter(AssetEntity.ip_address == host_ip).first()
                            
                        if asset:
                            if host_data.get("os") and host_data["os"] != "Unknown":
                                asset.operating_system = host_data["os"]
                            if host_data.get("ports"):
                                asset.ports = host_data["ports"]
                            if host_data.get("services"):
                                asset.services = host_data["services"]
                            if host_data.get("mac_address"):
                                asset.mac_address = host_data["mac_address"]
                            
                            # Update IP address if the original asset was a domain name and we resolved an IP
                            if host_ip != asset_ip and host_data.get("ip"):
                                # Ensure we don't overwrite the original name if it's the domain
                                if asset.name == asset.ip_address:
                                    asset.name = asset_ip
                                asset.ip_address = host_ip

                            asset.last_scan_raw_output = json.dumps(host_data, indent=2)
                    db.commit()
            finally:
                db.close()
                
            # If no open ports were found, there's no need to run vulnerability scripts
            if not open_ports_list:
                logger.info(f"No open ports found on {asset_ip}. Skipping Phase 2 vulnerability scripts.")
                from src.vulnerabilities.application.services.tasks import update_scan_progress
                update_scan_progress(scan_id, asset_ip, "COMPLETED")
                return True
                
            open_ports_str = ",".join(set(open_ports_list))
            
            # --- PHASE 2: Vulnerability Scripts ---
            logger.info(f"Phase 2: Running vulnerability scripts on open ports {open_ports_str} for {asset_ip}")
            vuln_hosts = NmapAdapter.run_vulnerability_scan(asset_ip, ports=open_ports_str, credentials=vault_secret)
            logger.info(f"Nmap vulnerability scan completed. Hosts found: {len(vuln_hosts)}")
            
            # Save Phase 2 results and mark COMPLETED
            if vuln_hosts:
                from src.vulnerabilities.application.services.tasks import parse_nmap_report
                for host_data in vuln_hosts:
                    parse_nmap_report.delay(host_data, host_data.get("ip", asset_ip), scan_id)
            else:
                from src.vulnerabilities.application.services.tasks import update_scan_progress
                update_scan_progress(scan_id, asset_ip, "COMPLETED")
                
            return True
        except Exception as e:
            logger.error(f"Nmap scan failed: {str(e)}")
            db = SessionLocal()
            try:
                scan_fail = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
                if scan_fail:
                    scan_fail.status = ScanStatus.FAILED
                    from src.audit.domain.models import AuditLog
                    db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_FAILED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "FAILED"}))
                    db.commit()
            finally:
                db.close()
            raise e

    if scan_engine == ScannerEngine.NUCLEI:
        try:
            from src.scans.adapters.outbound.nmap_adapter import NmapAdapter
            import json
            
            # --- PHASE 1: Ports, Services, OS ---
            logger.info(f"Phase 1: Running Nmap detailed discovery on {asset_ip} for Nuclei")
            discovery_hosts = NmapAdapter.run_detailed_discovery_scan(asset_ip, ports=port_range, credentials=vault_secret)
            
            nuclei_targets = []
            
            # Save Phase 1 results directly to DB
            db = SessionLocal()
            try:
                if discovery_hosts:
                    for host_data in discovery_hosts:
                        host_ip = host_data.get("ip", asset_ip)
                        
                        if host_data.get("ports"):
                            port_list = host_data["ports"]
                            if isinstance(port_list, str):
                                port_list = [p.strip() for p in port_list.split(",") if p.strip()]
                            # Map ports to Nuclei URIs
                            for p in port_list:
                                port_id = p.split('/')[0]
                                service_name = "unknown"
                                if "(" in p and ")" in p:
                                    service_name = p.split('(')[1].split(')')[0].lower()
                                
                                if "http" in service_name and "ssl" not in service_name and "https" not in service_name:
                                    nuclei_targets.append(f"http://{host_ip}:{port_id}")
                                elif "https" in service_name or "ssl" in service_name:
                                    nuclei_targets.append(f"https://{host_ip}:{port_id}")
                                else:
                                    nuclei_targets.append(f"{host_ip}:{port_id}")
                                    
                        asset = db.query(AssetEntity).filter(AssetEntity.ip_address == asset_ip).first()
                        if not asset:
                            asset = db.query(AssetEntity).filter(AssetEntity.name == asset_ip).first()
                        if not asset:
                            asset = db.query(AssetEntity).filter(AssetEntity.ip_address == host_ip).first()
                            
                        if asset:
                            if host_data.get("os") and host_data["os"] != "Unknown":
                                asset.operating_system = host_data["os"]
                            if host_data.get("ports"):
                                asset.ports = host_data["ports"]
                            if host_data.get("services"):
                                asset.services = host_data["services"]
                            if host_data.get("mac_address"):
                                asset.mac_address = host_data["mac_address"]
                                
                            # Update IP address if the original asset was a domain name and we resolved an IP
                            if host_ip != asset_ip and host_data.get("ip"):
                                # Ensure we don't overwrite the original name if it's the domain
                                if asset.name == asset.ip_address:
                                    asset.name = asset_ip
                                asset.ip_address = host_ip
                                
                            asset.last_scan_raw_output = json.dumps(host_data, indent=2)
                    db.commit()
            finally:
                db.close()
                
            if not nuclei_targets:
                logger.info(f"No open ports found on {asset_ip}. Skipping Phase 2 Nuclei scripts.")
                from src.vulnerabilities.application.services.tasks import update_scan_progress
                update_scan_progress(scan_id, asset_ip, "COMPLETED")
                return True
                
            # --- PHASE 2: Nuclei Vulnerability Scan ---
            logger.info(f"Phase 2: Running Nuclei on mapped targets: {nuclei_targets}")
            from src.scans.adapters.outbound.nuclei_adapter import NucleiAdapter
            vulns = NucleiAdapter.run_scan(target=nuclei_targets, ports=None, credentials=vault_secret)
            
            # Nuclei runs synchronously, pass to parser.
            from src.vulnerabilities.application.services.tasks import parse_nuclei_report
            parse_nuclei_report.delay(vulns, asset_ip, scan_id)
            return True
        except Exception as e:
            logger.error(f"Nuclei scan failed: {str(e)}")
            db = SessionLocal()
            try:
                scan_fail = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
                if scan_fail:
                    scan_fail.status = ScanStatus.FAILED
                    from src.audit.domain.models import AuditLog
                    db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_FAILED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "FAILED"}))
                    db.commit()
            finally:
                db.close()
            raise e

    if scan_engine == ScannerEngine.NESSUS:
        try:
            from src.scans.adapters.outbound.nessus_adapter import NessusAdapter
            adapter = NessusAdapter()
            vulns = adapter.run_scan(asset_ip)
            
            db = SessionLocal()
            try:
                scan_update = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
                if scan_update:
                    scan_update.status = ScanStatus.COMPLETED
                    from src.audit.domain.models import AuditLog
                    db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_COMPLETED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "COMPLETED"}))
                    scan_update.progress = 100
                db.commit()
            finally:
                db.close()
            
            logger.info("Nessus integration is currently in stub mode. Scan completed.")
            return True
        except Exception as e:
            logger.error(f"Nessus scan failed: {str(e)}")
            db = SessionLocal()
            try:
                scan_fail = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
                if scan_fail:
                    scan_fail.status = ScanStatus.FAILED
                    from src.audit.domain.models import AuditLog
                    db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_FAILED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "FAILED"}))
                    db.commit()
            finally:
                db.close()
            raise e

    if scan_engine == ScannerEngine.OWASP_ZAP:
        try:
            from src.scans.adapters.outbound.zap_adapter import ZAPAdapter
            from src.scans.adapters.outbound.nmap_adapter import NmapAdapter
            import json
            
            # --- PHASE 1: Ports, Services, OS, MAC ---
            logger.info(f"Phase 1: Running Nmap detailed discovery on {asset_ip} for ZAP")
            discovery_hosts = NmapAdapter.run_detailed_discovery_scan(asset_ip, ports=port_range, credentials=vault_secret)
            
            open_ports_list = []
            
            # Save Phase 1 results directly to DB
            db = SessionLocal()
            try:
                if discovery_hosts:
                    for host_data in discovery_hosts:
                        host_ip = host_data.get("ip", asset_ip)
                        
                        if host_data.get("ports"):
                            port_list = host_data["ports"]
                            if isinstance(port_list, str):
                                port_list = [p.strip() for p in port_list.split(",") if p.strip()]
                            for p in port_list:
                                port_num = p.split('/')[0]
                                open_ports_list.append(port_num)
                                
                        asset = db.query(AssetEntity).filter(AssetEntity.ip_address == asset_ip).first()
                        if not asset:
                            asset = db.query(AssetEntity).filter(AssetEntity.name == asset_ip).first()
                        if not asset:
                            asset = db.query(AssetEntity).filter(AssetEntity.ip_address == host_ip).first()
                            
                        if asset:
                            if host_data.get("os") and host_data["os"] != "Unknown":
                                asset.operating_system = host_data["os"]
                            if host_data.get("ports"):
                                asset.ports = host_data["ports"]
                            if host_data.get("services"):
                                asset.services = host_data["services"]
                            if host_data.get("mac_address"):
                                asset.mac_address = host_data["mac_address"]
                                
                            # Update IP address if the original asset was a domain name and we resolved an IP
                            if host_ip != asset_ip and host_data.get("ip"):
                                # Ensure we don't overwrite the original name if it's the domain
                                if asset.name == asset.ip_address:
                                    asset.name = asset_ip
                                asset.ip_address = host_ip
                                
                            asset.last_scan_raw_output = json.dumps(host_data, indent=2)
                    db.commit()
            finally:
                db.close()
                
            if not open_ports_list:
                logger.info(f"No open ports found on {asset_ip}. Skipping Phase 2 ZAP scan.")
                from src.vulnerabilities.application.services.tasks import update_scan_progress
                update_scan_progress(scan_id, asset_ip, "COMPLETED")
                return True
                
            # --- PHASE 2: OWASP ZAP Vulnerability Scan ---
            logger.info(f"Phase 2: Running OWASP ZAP on {asset_ip}")
            vulns = ZAPAdapter.run_scan(asset_ip, credentials=vault_secret)
            from src.vulnerabilities.application.services.tasks import parse_zap_report
            parse_zap_report.delay(vulns, asset_ip, scan_id)
            return True
        except Exception as e:
            logger.error(f"OWASP ZAP scan failed: {str(e)}")
            db = SessionLocal()
            try:
                scan_fail = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
                if scan_fail:
                    scan_fail.status = ScanStatus.FAILED
                    from src.audit.domain.models import AuditLog
                    db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_FAILED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "FAILED"}))
                    db.commit()
            finally:
                db.close()
            raise e

    adapter = GVMAdapter()
    if not adapter.connect():
        logger.error("Failed to connect to GVM")
        self.retry(countdown=60)
        return
        
    try:
        gvm_port_range = "T:1-65535,U:1-65535"
        if port_range:
            # Clean port range for GVM format, e.g. "1-65535,!7000" or "80,443"
            clean_ports = port_range.split("!")[0].rstrip(",")
            if clean_ports:
                gvm_port_range = f"T:{clean_ports}"
                
        target_id = adapter.create_target(f"Target_{asset_name}_{scan_id}", [asset_ip], port_range=gvm_port_range)
        task_id = adapter.create_task(f"Task_{asset_name}_{scan_id}", target_id, DEFAULT_SCANNER_ID, config_id)
        report_id = adapter.start_task(task_id)
        
        adapter.disconnect()
        
        poll_scan_status.apply_async(args=[scan_id, task_id, report_id, asset_ip], countdown=60)
        return True
    except Exception as e:
        logger.error(f"Scan initialization failed: {str(e)}")
        adapter.disconnect()
        
        db = SessionLocal()
        try:
            scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                from src.audit.domain.models import AuditLog
                db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_FAILED", resource_type="SCAN", resource_id=str(scan_id), details={"status": "FAILED"}))
                db.commit()
        finally:
            db.close()
        raise e

@celery_app.task(bind=True, max_retries=None)
def poll_scan_status(self, scan_id: str, task_id: str, report_id: str, asset_ip: str):
    adapter = GVMAdapter()
    if not adapter.connect():
        self.retry(countdown=60)
        return
        
    try:
        status, progress = adapter.get_task_status_and_progress(task_id)
        
        db = SessionLocal()
        try:
            scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
            if scan:
                scan.progress = progress
                db.commit()
        finally:
            db.close()

        if status in ["Done", "Stopped", "Interrupted"]:
            report_xml = adapter.get_report(report_id)
            adapter.disconnect()
            
            # Mark scan complete
            db = SessionLocal()
            try:
                scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
                if scan:
                    # If it was stopped/interrupted, we might want to mark it as PARTIAL or just COMPLETED. We'll use COMPLETED to see results.
                    # For OpenVAS, we will let the parser handle it per IP since OpenVAS scans all IPs at once.
                    scan.status = ScanStatus.IN_PROGRESS
                    db.commit()
            finally:
                db.close()
            
            # Send to vulnerability parser to extract whatever it found
            from src.vulnerabilities.application.services.tasks import parse_scan_report
            parse_scan_report.delay(report_xml, asset_ip, scan_id)
            return True

        else:
            adapter.disconnect()
            self.retry(countdown=10)
            
    except Exception as e:
        if isinstance(e, Retry):
            raise
        logger.error(f"Polling failed: {str(e)}")
        adapter.disconnect()
        self.retry(countdown=60)

@celery_app.task(name="generate_ai_summary_task", bind=True, max_retries=3)
def generate_ai_summary_task(self, vuln_data: list, language: str = "French", extra_instructions: str = ""):
    import asyncio
    from src.ai.application.services.nlp import generate_executive_summary
    
    logger.info(f"Task {self.request.id}: Starting AI summary generation...")
    try:
        # Run the async summary generation synchronously
        summary = asyncio.run(generate_executive_summary(vuln_data, language=language, extra_instructions=extra_instructions))
        logger.info(f"Task {self.request.id}: AI summary generation completed successfully.")
        return summary
    except Exception as e:
        logger.error(f"Task {self.request.id}: AI summary generation failed: {str(e)}")
        raise self.retry(exc=e, countdown=30)
