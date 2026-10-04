import os
import json
import shutil
import signal
import socket
import subprocess
import tempfile
import logging
import re
import time
import requests
import secrets
import urllib3
from html import unescape
from typing import List, Dict

logger = logging.getLogger(__name__)

class ScanError(RuntimeError):
    pass

_TAG = re.compile(r"<[^>]+>")
def _clean(html: str) -> str:
    """Removes HTML tags and unescapes entities from ZAP descriptions."""
    return unescape(_TAG.sub("", html or "")).strip()

class ZAPAdapter:
    @staticmethod
    def run_scan(targets: str, credentials: Dict = None) -> List[Dict]:
        """
        Runs OWASP ZAP active scans efficiently on multiple targets.
        Uses a single background daemon and the REST API to handle multiple targets simultaneously.
        """
        target_list = [t.strip() for t in targets.split(",") if t.strip()]
        if not target_list:
            return []
            
        logger.info(f"Running OWASP ZAP scan on {len(target_list)} targets: {target_list}")
        
        zap_home_dir = None
        proc = None
        api_key = secrets.token_hex(16)
        
        try:
            # Ensure requests to localhost do not use proxy
            os.environ["NO_PROXY"] = "127.0.0.1,localhost"
            os.environ["no_proxy"] = "127.0.0.1,localhost"
            
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            zap_home_dir = tempfile.mkdtemp(prefix="zap_home_")
            
            # Find a free port safely
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', 0))
                free_port = s.getsockname()[1]
                
            cmd = [
                "/usr/local/bin/zap", 
                "-daemon", 
                "-host", "127.0.0.1",
                "-dir", zap_home_dir, 
                "-port", str(free_port),
                "-config", f"api.key={api_key}"
            ]
            
            # Inject Credentials if provided
            if credentials and credentials.get("credential_type") == "HTTP":
                import base64
                user = credentials.get("username", "")
                pwd = credentials.get("password", "")
                if user or pwd:
                    auth_str = f"{user}:{pwd}"
                    b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
                    cmd.extend([
                        "-config", "replacer.full_list(0).description=auth1",
                        "-config", "replacer.full_list(0).enabled=true",
                        "-config", "replacer.full_list(0).matchtype=REQ_HEADER",
                        "-config", "replacer.full_list(0).matchstr=Authorization",
                        "-config", "replacer.full_list(0).regex=false",
                        "-config", f"replacer.full_list(0).replacement=Basic {b64_auth}"
                    ])
            else:
                if credentials:
                    logger.warning(f"ZAP Adapter: Unsupported credential_type '{credentials.get('credential_type')}'. Ignoring.")
            
            logger.info("Starting ZAP Daemon...")
            
            # Use start_new_session to ensure we can kill the entire process group (java + wrapper)
            # Restrict JVM memory to 512MB to prevent starving Celery/RabbitMQ under load
            env = os.environ.copy()
            env["_JAVA_OPTIONS"] = "-Xmx512m -Xms256m"
            
            proc = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True, 
                env=env,
                start_new_session=True
            )
            
            zap_url = f"http://127.0.0.1:{free_port}"
            zap_ready = False
            
            # Wait for ZAP API to boot (Up to 120 seconds for heavy environments)
            for _ in range(120):
                try:
                    resp = requests.get(zap_url, timeout=2)
                    if resp.status_code == 200:
                        zap_ready = True
                        break
                except Exception:
                    time.sleep(1)
                    
            if not zap_ready:
                # Let's get stderr for debugging if it crashes
                stderr_out = proc.stderr.read() if proc.stderr else "No stderr"
                logger.error(f"ZAP Boot Failed. Stderr: {stderr_out}")
                raise ScanError("ZAP Daemon failed to start within 120 seconds.")
                
            logger.info("ZAP Daemon is ready. Preparing targets...")
            
            formatted_targets = []
            for target in target_list:
                formatted = target
                if not formatted.startswith("http"):
                    try:
                        requests.get(f"https://{formatted}", timeout=3, verify=False)
                        formatted = f"https://{formatted}"
                    except Exception:
                        formatted = f"http://{formatted}"
                formatted_targets.append(formatted)
            
            # Step 1: Spider all targets
            for target in formatted_targets:
                logger.info(f"Accessing and Spidering {target}...")
                requests.get(f"{zap_url}/JSON/core/action/accessUrl/", params={"apikey": api_key, "url": target})
                
                spider_resp = requests.get(f"{zap_url}/JSON/spider/action/scan/", params={"apikey": api_key, "url": target})
                scan_id = spider_resp.json().get("scan")
                
                if scan_id:
                    # Wait for this spider to finish (Max 5 minutes)
                    spider_start_time = time.time()
                    while True:
                        if time.time() - spider_start_time > 300:
                            logger.warning(f"ZAP Spider timeout reached for {target}")
                            break
                        stat_resp = requests.get(f"{zap_url}/JSON/spider/view/status/", params={"apikey": api_key, "scanId": scan_id})
                        if str(stat_resp.json().get("status")) == "100":
                            break
                        time.sleep(2)
                        
            # Step 2: Trigger Active Scans for all targets (Concurrent in ZAP)
            scan_ids = []
            for target in formatted_targets:
                logger.info(f"Starting Active Scan for {target}...")
                ascan_resp = requests.get(f"{zap_url}/JSON/ascan/action/scan/", params={"apikey": api_key, "url": target})
                scan_ids.append(ascan_resp.json().get("scan"))
                
            # Step 3: Poll Active Scan status until all are 100% (Max 30 minutes)
            for scan_id in scan_ids:
                if not scan_id: 
                    continue
                ascan_start_time = time.time()
                while True:
                    if time.time() - ascan_start_time > 1800:
                        logger.warning(f"ZAP Active Scan timeout reached for scan ID {scan_id}")
                        break
                    stat_resp = requests.get(f"{zap_url}/JSON/ascan/view/status/", params={"apikey": api_key, "scanId": scan_id})
                    if str(stat_resp.json().get("status")) == "100":
                        break
                    time.sleep(10) # Poll every 10 seconds for heavy active scans
                    
            logger.info("All ZAP scans completed. Fetching aggregated alerts...")
            alerts_resp = requests.get(f"{zap_url}/JSON/core/view/alerts/", params={"apikey": api_key})
            raw_alerts = alerts_resp.json().get("alerts", [])
            
            # Step 4: Gracefully shutdown the Daemon
            requests.get(f"{zap_url}/JSON/core/action/shutdown/", params={"apikey": api_key})
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
            
            return ZAPAdapter._parse_zap_alerts(raw_alerts)
            
        except Exception as e:
            # Emergency cleanup of the background JVM
            if proc and proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
            raise ScanError(f"ZAP scan failed: {str(e)}") from e
            
        finally:
            if zap_home_dir and os.path.exists(zap_home_dir):
                shutil.rmtree(zap_home_dir, ignore_errors=True)

    @staticmethod
    def _parse_zap_alerts(alerts: List[Dict]) -> List[Dict]:
        """Parses and normalizes the JSON alerts from the ZAP REST API."""
        vulns = []
        for alert in alerts:
            # Map risk codes to severity securely
            risk_desc = str(alert.get("risk", alert.get("riskcode", "0")))
            severity = {"3": "high", "2": "medium", "1": "low", "0": "info"}.get(risk_desc, "info")
            
            # Fallback if the API returns text instead of code
            if not risk_desc.isdigit():
                severity = risk_desc.split(' ')[0].lower()
                if severity == "informational": 
                    severity = "info"
                
            vuln = {
                "id": f"zap-{alert.get('pluginId', alert.get('pluginid', 'unknown'))}",
                "name": alert.get("alert", alert.get("name", "ZAP Finding")),
                "severity": severity,
                "confidence": alert.get("confidence"),
                "description": _clean(alert.get("description", alert.get("desc", ""))),
                "remediation": _clean(alert.get("solution", "")),
                "cvss_score": None, # ZAP doesn't return CVSS
                "cve_id": None,
                "cwe_id": alert.get("cweid"),
                "matched_at": alert.get("url", alert.get("uri", "")),
                "extracted_results": [f"Evidence: {alert['evidence']}"] if alert.get("evidence") else []
            }
            vulns.append(vuln)
            
        logger.info(f"ZAP successfully parsed {len(vulns)} aggregated findings.")
        return vulns
