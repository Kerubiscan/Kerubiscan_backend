import subprocess
import logging
import json
import os
from typing import List, Dict

logger = logging.getLogger(__name__)

class ZAPAdapter:
    @staticmethod
    def run_scan(target: str, credentials: Dict = None) -> List[Dict]:
        """Runs an OWASP ZAP active scan and returns structured JSON data."""
        logger.info(f"Running OWASP ZAP full scan on {target}")
        
        output_file = f"/tmp/zap_{target.replace('.', '_').replace('/', '_').replace(':', '_')}.json"
        
        try:
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # ZAP expects a URL.
            formatted_target = target
            if not target.startswith("http://") and not target.startswith("https://"):
                logger.info(f"Probing {target} to determine correct HTTP/HTTPS prefix...")
                use_https = False
                
                # Fast Probe: Try HTTPS first
                try:
                    requests.get(f"https://{target}", timeout=3, verify=False)
                    use_https = True
                    logger.info(f"Fast Probe: HTTPS connection successful for {target}")
                except requests.RequestException:
                    # If HTTPS fails, try HTTP
                    try:
                        requests.get(f"http://{target}", timeout=3)
                        use_https = False
                        logger.info(f"Fast Probe: HTTP connection successful for {target}")
                    except requests.RequestException:
                        # If both fail, default to http but log warning
                        logger.warning(f"Fast Probe: Both HTTP and HTTPS failed for {target}. Defaulting to HTTP.")
                        use_https = False
                        
                formatted_target = f"https://{target}" if use_https else f"http://{target}"
                
            logger.info(f"ZAP target formatted to: {formatted_target}")
            # -cmd: Run inline without GUI or daemon
            # -quickurl: Spider and Active Scan the target
            # -quickout: Save the results to this file
            # -quickprogress: Print progress
            if os.path.exists(output_file):
                os.remove(output_file)
                
            cmd = ["/usr/local/bin/zap", "-cmd", "-quickurl", formatted_target, "-quickout", output_file, "-quickprogress"]
            
            if credentials and credentials.get("credential_type") == "HTTP":
                import base64
                user = credentials.get("username", "")
                pwd = credentials.get("password", "")
                if user or pwd:
                    auth_str = f"{user}:{pwd}"
                    b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
                    
                    # Inject Authorization header using ZAP Replacer
                    cmd.extend([
                        "-config", "replacer.full_list(0).description=auth1",
                        "-config", "replacer.full_list(0).enabled=true",
                        "-config", "replacer.full_list(0).matchtype=REQ_HEADER",
                        "-config", "replacer.full_list(0).matchstr=Authorization",
                        "-config", "replacer.full_list(0).regex=false",
                        "-config", f"replacer.full_list(0).replacement=Basic {b64_auth}"
                    ])
                    logger.info("Injected HTTP Basic Auth into ZAP Replacer config.")

            result = subprocess.run(
                cmd, 
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
