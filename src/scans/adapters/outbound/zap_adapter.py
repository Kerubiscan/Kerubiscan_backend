import subprocess
import logging
import json
import os
from typing import List, Dict

logger = logging.getLogger(__name__)

class ZAPAdapter:
    @staticmethod
    def run_scan(target: str) -> List[Dict]:
        """Runs an OWASP ZAP active scan and returns structured JSON data."""
        logger.info(f"Running OWASP ZAP full scan on {target}")
        
        output_file = f"/tmp/zap_{target.replace('.', '_').replace('/', '_').replace(':', '_')}.json"
        
        try:
            # ZAP expects a URL.
            formatted_target = target
            if not target.startswith("http://") and not target.startswith("https://"):
                formatted_target = f"http://{target}"
            logger.info(f"ZAP target formatted to: {formatted_target}")

            # -cmd: Run inline without GUI or daemon
            # -quickurl: Spider and Active Scan the target
            # -quickout: Save the results to this file
            # -quickprogress: Print progress
            if os.path.exists(output_file):
                os.remove(output_file)

            result = subprocess.run(
                ["/usr/local/bin/zap", "-cmd", "-quickurl", formatted_target, "-quickout", output_file, "-quickprogress"], 
                capture_output=True, 
                text=True, 
                check=False,
                timeout=7200 # ZAP Active scans can take a long time
            )
            
            logger.info(f"ZAP scan stdout: {result.stdout}")
            if result.stderr:
                logger.warning(f"ZAP output/errors: {result.stderr}")
                
            return ZAPAdapter._parse_zap_json(output_file)
        except subprocess.TimeoutExpired:
            logger.error(f"ZAP scan timed out for {target}")
            raise Exception(f"ZAP scan timed out on {target}")
        except Exception as e:
            logger.error(f"ZAP scan failed: {str(e)}")
            raise Exception(f"ZAP scan failed: {str(e)}")
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    @staticmethod
    def _parse_zap_json(filepath: str) -> List[Dict]:
        """Parses ZAP JSON output."""
        vulns = []
        if not os.path.exists(filepath):
            logger.warning(f"ZAP output file {filepath} not found.")
            return vulns
            
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                
                # ZAP JSON structure is usually:
                # {"site": [{"@name": "http://192.168.100.80", "alerts": [{"alert": "...", "riskdesc": "High", "desc": "...", "solution": "..."}]}]}
                sites = data.get("site", [])
                if isinstance(sites, dict):
                    sites = [sites]
                    
                for site in sites:
                    alerts = site.get("alerts", [])
                    if isinstance(alerts, dict):
                        alerts = [alerts]
                        
                    for alert in alerts:
                        risk_desc = alert.get("riskdesc", "Informational")
                        # Map riskdesc like 'High (Medium)' to just 'High'
                        severity = risk_desc.split(' ')[0].lower()
                        if severity == "informational":
                            severity = "info"
                            
                        vuln = {
                            "id": alert.get("pluginid", "zap-unknown"),
                            "name": alert.get("alert", "ZAP Finding"),
                            "severity": severity,
                            "description": alert.get("desc", ""),
                            "remediation": alert.get("solution", ""),
                            "cvss_score": 0.0, # ZAP usually doesn't provide CVSS in quickout
                            "cve_id": None,
                            "matched_at": alert.get("instances", [{}])[0].get("uri", "") if alert.get("instances") else "",
                            "extracted_results": [f"Evidence: {alert.get('instances', [{}])[0].get('evidence', '')}"] if alert.get('instances') else []
                        }
                        vulns.append(vuln)
                        
        except Exception as e:
            logger.error(f"Failed to parse ZAP JSON: {str(e)}")
            
        logger.info(f"ZAP parsed result:\n{json.dumps(vulns, indent=2)}")
        return vulns
