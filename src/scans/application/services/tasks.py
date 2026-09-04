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
                    logger.info(f"Phase 2: Detailed scan on {len(discovered_ips)} discovered hosts")
                    detailed_target = ",".join(discovered_ips)
                    detailed_hosts = NmapAdapter.run_detailed_discovery_scan(detailed_target)
                    
                    for d_host in detailed_hosts:
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
            db.commit()
    finally:
        db.close()

    if scan_engine == ScannerEngine.NMAP:
        try:
            from src.scans.adapters.outbound.nmap_adapter import NmapAdapter
            hosts = NmapAdapter.run_vulnerability_scan(asset_ip)
            logger.info(f"Nmap vulnerability scan completed. Hosts found: {len(hosts)}")
            
            # Nmap runs synchronously, so we pass to parser. 
            # We don't mark as COMPLETED here, the parser will do it.
            if hosts:
                from src.vulnerabilities.application.services.tasks import parse_nmap_report
                for host_data in hosts:
                    # Queue task to parse report for each host and mark it as COMPLETED
                    parse_nmap_report.delay(host_data, host_data.get("ip", asset_ip), scan_id)
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
            from src.scans.adapters.outbound.nuclei_adapter import NucleiAdapter
            vulns = NucleiAdapter.run_scan(asset_ip)
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

    adapter = GVMAdapter()
    if not adapter.connect():
        logger.error("Failed to connect to GVM")
        self.retry(countdown=60)
        return
        
    try:
        target_id = adapter.create_target(f"Target_{asset_name}_{scan_id}", [asset_ip])
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
