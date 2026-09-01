from src.core.celery_app import celery_app
from lxml import etree
import logging
from sqlalchemy.sql import func
from src.core.database import SessionLocal
from src.vulnerabilities.domain.entities import VulnerabilityEntity
from src.vulnerabilities.domain.models import VulnSeverity, VulnStatus
from src.assets.domain.entities import AssetEntity
from src.scans.domain.entities import ScanEntity
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

def map_threat_to_severity(threat: str) -> VulnSeverity:
    if not threat: return VulnSeverity.INFO
    threat = threat.lower()
    if threat == "critical": return VulnSeverity.CRITICAL
    if threat == "high": return VulnSeverity.HIGH
    if threat == "medium": return VulnSeverity.MEDIUM
    if threat == "low": return VulnSeverity.LOW
    return VulnSeverity.INFO

def calculate_contextual_risk(base_score: float, criticality) -> float:
    # Asset criticality: Low=0.5, Medium=0.75, High=1.0, Critical=1.25
    multiplier = 1.0
    crit_str = str(criticality.value) if hasattr(criticality, 'value') else str(criticality)
    
    if crit_str == "Low": multiplier = 0.5
    elif crit_str == "Medium": multiplier = 0.75
    elif crit_str == "High": multiplier = 1.0
    elif crit_str == "Critical": multiplier = 1.25
    
    return round(base_score * multiplier, 1)

@celery_app.task
def parse_scan_report(report_xml: str, target_ip: str, scan_id: int = None):
    logger.info(f"Parsing scan report for {target_ip} (Scan {scan_id})")
    db: Session = SessionLocal()
    
    new_alerts = []
    
    try:
        # Find the asset
        asset = db.query(AssetEntity).filter(AssetEntity.ip_address == target_ip).first()
        if not asset:
            logger.info(f"Asset with IP {target_ip} not found. Creating it automatically.")
            scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
            if not scan:
                logger.error(f"Scan {scan_id} not found. Cannot create asset.")
                return
            
            asset = AssetEntity(
                company_id=scan.company_id,
                name=f"Auto-added Host ({target_ip})",
                ip_address=target_ip,
                asset_type="Unknown",
                network_zone=scan.network_zone or "Internal",
                operating_system="Unknown"
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)
            
        root = etree.fromstring(report_xml.encode('utf-8'))
        
        # Extract OS and Ports to enrich the Asset
        host_elements = root.xpath(f"//report/report/host[ip='{target_ip}']")
        if host_elements:
            host_elem = host_elements[0]
            os_details = host_elem.xpath(".//detail[name='Best OS']/value/text()")
            if not os_details:
                os_details = host_elem.xpath(".//detail[name='OS']/value/text()")
            if os_details and os_details[0].strip():
                asset.operating_system = os_details[0].strip()
                
        host_ports = []
        results_for_host = root.xpath(f"//result[host='{target_ip}']")
        for r in results_for_host:
            port_elem = r.find('port')
            if port_elem is not None and port_elem.text:
                p_text = port_elem.text.strip()
                if p_text != "general/tcp" and p_text != "general/udp" and p_text not in host_ports:
                    host_ports.append(p_text)
                    
        if host_ports:
            asset.ports = ", ".join(host_ports)
            
        asset.last_scan_raw_output = report_xml
            
        db.commit()
        
        # Extract results
        results = root.xpath("//report/report/results/result")
        logger.info(f"Found {len(results)} raw results in report.")
        
        for result in results:
            threat = result.findtext("threat")
            if threat in ["Log", "False Positive"]:
                continue # Skip pure logs
                
            nvt = result.find("nvt")
            if nvt is None: continue
            
            cve_id = nvt.findtext("cve")
            if cve_id == "NOCVE": cve_id = None
            
            title = nvt.findtext("name")
            if not title: continue
            
            cvss_str = nvt.findtext("cvss_base")
            cvss_base_score = float(cvss_str) if cvss_str else 0.0
            
            description = result.findtext("description")
            remediation = nvt.findtext("solution")
            
            severity = map_threat_to_severity(threat)
            contextual_risk = calculate_contextual_risk(cvss_base_score, asset.criticality)
            
            # AI Prioritization for High/Critical
            if cvss_base_score >= 7.0:
                try:
                    from src.ai.application.services.nlp import refine_risk_score_sync
                    ai_multiplier = refine_risk_score_sync(title, description)
                    if ai_multiplier > 1.0:
                        logger.info(f"AI bumped risk score for {title} by {ai_multiplier}x")
                        contextual_risk = round(contextual_risk * ai_multiplier, 1)
                except Exception as e:
                    logger.error(f"Failed to apply AI multiplier: {str(e)}")
            
            # Deduplication: CVE + Asset
            existing_vuln = None
            if cve_id:
                existing_vuln = db.query(VulnerabilityEntity).filter(
                    VulnerabilityEntity.asset_id == asset.id,
                    VulnerabilityEntity.cve_id == cve_id
                ).first()
            else:
                # Fallback to Title + Asset deduplication for non-CVE findings
                existing_vuln = db.query(VulnerabilityEntity).filter(
                    VulnerabilityEntity.asset_id == asset.id,
                    VulnerabilityEntity.title == title[:250]
                ).first()
                
            if existing_vuln:
                # Update last seen and check for regression
                existing_vuln.last_seen_at = func.now()
                if existing_vuln.status == VulnStatus.FIXED:
                    # Regression detected
                    logger.warning(f"Regression detected for {title} on {target_ip}")
                    existing_vuln.status = VulnStatus.NEW
                    if severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH]:
                        new_alerts.append(f"[{severity.name}] {title[:250]}")
                db.commit()
            else:
                # Create new vulnerability
                new_vuln = VulnerabilityEntity(
                    asset_id=asset.id,
                    cve_id=cve_id,
                    title=title[:250],
                    description=description,
                    remediation=remediation,
                    cvss_base_score=cvss_base_score,
                    contextual_risk_score=contextual_risk,
                    severity=severity,
                    status=VulnStatus.NEW
                )
                db.add(new_vuln)
                db.commit()
                if severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH]:
                    new_alerts.append(f"[{severity.name}] {title[:250]}")
                
        logger.info("Finished parsing report.")
        
        # Send Email Alerts
        from src.notifications.application.services.smtp import send_alert_email
        admin_email = "admin@kerubiscan.local" # Or fetch from a config
        
        # 1. Email for finished scan
        send_alert_email(
            to_email=admin_email,
            subject=f"Scan Completed: {target_ip}",
            content=f"The vulnerability scan for asset {asset.name} ({target_ip}) has completed successfully.\nTotal results processed: {len(results)}."
        )
        
        # 2. Email for critical/high alerts
        if new_alerts:
            logger.info(f"Sending alerts for {len(new_alerts)} vulnerabilities.")
            vuln_list = "\n".join([f"- {v}" for v in new_alerts])
            send_alert_email(
                to_email=admin_email,
                subject=f"HIGH/CRITICAL Vulnerabilities Detected on {asset.name}",
                content=f"The following HIGH and CRITICAL vulnerabilities were newly discovered or regressed on {asset.name} ({target_ip}):\n\n{vuln_list}\n\nPlease investigate immediately."
            )
        
    except Exception as e:
        logger.error(f"Error parsing report: {str(e)}")
        db.rollback()
    finally:
        db.close()


@celery_app.task
def parse_nmap_report(host_data: dict, target_ip: str, scan_id: int = None):
    logger.info(f"Parsing Nmap report for {target_ip} (Scan {scan_id})")
    db: Session = SessionLocal()
    new_alerts = []
    try:
        asset = db.query(AssetEntity).filter(AssetEntity.ip_address == target_ip).first()
        if not asset:
            logger.info(f"Asset with IP {target_ip} not found. Creating it automatically.")
            scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
            if not scan:
                logger.error(f"Scan {scan_id} not found. Cannot create asset.")
                return
            
            asset = AssetEntity(
                company_id=scan.company_id,
                name=f"Auto-added Host ({target_ip})",
                ip_address=target_ip,
                asset_type="Unknown",
                network_zone=scan.network_zone or "Internal",
                operating_system="Unknown"
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)

        if host_data.get("os") and host_data["os"] != "Unknown":
            asset.operating_system = host_data["os"]
        if host_data.get("ports"):
            asset.ports = host_data["ports"]
            
        import json
        asset.last_scan_raw_output = json.dumps(host_data, indent=2)
            
        db.commit()

        vulns = host_data.get("vulns", [])
        for v in vulns:
            title = v.get("id", "Nmap Vuln")
            output = v.get("output", "")
            
            # Simple Nmap deduction
            severity = VulnSeverity.INFO
            if "VULNERABLE" in output or "State: VULNERABLE" in output:
                severity = VulnSeverity.HIGH
            
            existing_vuln = db.query(VulnerabilityEntity).filter(
                VulnerabilityEntity.asset_id == asset.id,
                VulnerabilityEntity.title == title[:250]
            ).first()
            
            if existing_vuln:
                existing_vuln.last_seen_at = func.now()
                if existing_vuln.status == VulnStatus.FIXED:
                    existing_vuln.status = VulnStatus.NEW
                    if severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH]:
                        new_alerts.append(f"[{severity.name}] {title[:250]}")
                db.commit()
            else:
                new_vuln = VulnerabilityEntity(
                    asset_id=asset.id,
                    title=title[:250],
                    description=output,
                    severity=severity,
                    source_engine="NMAP",
                    status=VulnStatus.NEW
                )
                db.add(new_vuln)
                db.commit()
                if severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH]:
                    new_alerts.append(f"[{severity.name}] {title[:250]}")

        logger.info(f"Finished parsing Nmap report. Found {len(vulns)} scripts output.")

        # Send Email Alerts
        from src.notifications.application.services.smtp import send_alert_email
        admin_email = "admin@kerubiscan.local" # Or fetch from a config
        
        # 1. Email for finished scan
        send_alert_email(
            to_email=admin_email,
            subject=f"Nmap Scan Completed: {target_ip}",
            content=f"The Nmap scan for asset {asset.name} ({target_ip}) has completed successfully.\nTotal scripts processed: {len(vulns)}."
        )
        
        # 2. Email for critical/high alerts
        if new_alerts:
            logger.info(f"Sending alerts for {len(new_alerts)} Nmap vulnerabilities.")
            vuln_list = "\n".join([f"- {v}" for v in new_alerts])
            send_alert_email(
                to_email=admin_email,
                subject=f"HIGH/CRITICAL Vulnerabilities Detected by Nmap on {asset.name}",
                content=f"The following HIGH and CRITICAL vulnerabilities were newly discovered or regressed on {asset.name} ({target_ip}):\n\n{vuln_list}\n\nPlease investigate immediately."
            )

    except Exception as e:
        logger.error(f"Error parsing Nmap report: {str(e)}")
        db.rollback()
    finally:
        db.close()


@celery_app.task
def parse_nuclei_report(vuln_data_list: list, target_ip: str, scan_id: int = None):
    logger.info(f"Parsing Nuclei report for {target_ip} (Scan {scan_id})")
    db: Session = SessionLocal()
    new_alerts = []
    try:
        asset = db.query(AssetEntity).filter(AssetEntity.ip_address == target_ip).first()
        if not asset:
            logger.info(f"Asset with IP {target_ip} not found. Creating it automatically.")
            scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
            if not scan:
                logger.error(f"Scan {scan_id} not found. Cannot create asset.")
                return
            
            asset = AssetEntity(
                company_id=scan.company_id,
                name=f"Auto-added Host ({target_ip})",
                ip_address=target_ip,
                asset_type="Unknown",
                network_zone=scan.network_zone or "Internal",
                operating_system="Unknown"
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)

        import json
        asset.last_scan_raw_output = json.dumps(vuln_data_list, indent=2)
        db.commit()

        for v in vuln_data_list:
            title = v.get("name", "Nuclei Vuln")
            cve_id = v.get("cve_id")
            
            # Map severity
            sev_str = v.get("severity", "info").lower()
            severity = VulnSeverity.INFO
            if sev_str == "critical": severity = VulnSeverity.CRITICAL
            elif sev_str == "high": severity = VulnSeverity.HIGH
            elif sev_str == "medium": severity = VulnSeverity.MEDIUM
            elif sev_str == "low": severity = VulnSeverity.LOW

            description = v.get("description", "")
            if v.get("matched_at"):
                description += f"\nMatched at: {v.get('matched_at')}"
            if v.get("extracted_results"):
                description += f"\nExtracted: {', '.join(v.get('extracted_results'))}"
                
            remediation = v.get("remediation", "")
            cvss_score = float(v.get("cvss_score", 0.0))
            
            contextual_risk = calculate_contextual_risk(cvss_score, asset.criticality)

            existing_vuln = db.query(VulnerabilityEntity).filter(
                VulnerabilityEntity.asset_id == asset.id,
                VulnerabilityEntity.title == title[:250]
            ).first()
            
            if existing_vuln:
                existing_vuln.last_seen_at = func.now()
                if existing_vuln.status == VulnStatus.FIXED:
                    existing_vuln.status = VulnStatus.NEW
                    if severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH]:
                        new_alerts.append(f"[{severity.name}] {title[:250]}")
                db.commit()
            else:
                new_vuln = VulnerabilityEntity(
                    asset_id=asset.id,
                    cve_id=cve_id,
                    title=title[:250],
                    description=description,
                    remediation=remediation,
                    cvss_base_score=cvss_score,
                    contextual_risk_score=contextual_risk,
                    severity=severity,
                    source_engine="NUCLEI",
                    status=VulnStatus.NEW
                )
                db.add(new_vuln)
                db.commit()
                if severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH]:
                    new_alerts.append(f"[{severity.name}] {title[:250]}")

        logger.info(f"Finished parsing Nuclei report. Processed {len(vuln_data_list)} findings.")

        # Send Email Alerts
        from src.notifications.application.services.smtp import send_alert_email
        admin_email = "admin@kerubiscan.local" # Or fetch from a config
        
        # 1. Email for finished scan
        send_alert_email(
            to_email=admin_email,
            subject=f"Nuclei Scan Completed: {target_ip}",
            content=f"The Nuclei scan for asset {asset.name} ({target_ip}) has completed successfully.\nTotal findings processed: {len(vuln_data_list)}."
        )
        
        # 2. Email for critical/high alerts
        if new_alerts:
            logger.info(f"Sending alerts for {len(new_alerts)} Nuclei vulnerabilities.")
            vuln_list = "\n".join([f"- {v}" for v in new_alerts])
            send_alert_email(
                to_email=admin_email,
                subject=f"HIGH/CRITICAL Vulnerabilities Detected by Nuclei on {asset.name}",
                content=f"The following HIGH and CRITICAL vulnerabilities were newly discovered or regressed on {asset.name} ({target_ip}):\n\n{vuln_list}\n\nPlease investigate immediately."
            )

    except Exception as e:
        logger.error(f"Error parsing Nuclei report: {str(e)}")
        db.rollback()
    finally:
        db.close()
