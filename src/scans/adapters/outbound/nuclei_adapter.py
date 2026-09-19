import subprocess
import logging
import json
import os
from typing import List, Dict

logger = logging.getLogger(__name__)

class NucleiAdapter:
    @staticmethod
    def run_scan(target: str | List[str], ports: str = None, credentials: Dict = None) -> List[Dict]:
        """Runs a Nuclei vulnerability scan and returns structured JSON data."""
        targets = [target] if isinstance(target, str) else target
        target_name = targets[0].replace('.', '_').replace(':', '_').replace('/', '_')
        logger.info(f"Running Nuclei scan on {targets} with ports {ports}")
        
        output_file = f"/tmp/nuclei_{target_name}.json"
        
        try:
            # -duc: Disable update check
            # We removed -as (Automatic Scan) so Nuclei runs ALL default templates 
            # (cves, vulnerabilities, exposures, misconfiguration, etc.) as requested.
            cmd = ["/usr/local/bin/nuclei", "-duc", "-je", output_file, "-nc"]
            
            if credentials and credentials.get("credential_type") == "HTTP":
                import base64
                user = credentials.get("username", "")
                pwd = credentials.get("password", "")
                if user or pwd:
                    auth_str = f"{user}:{pwd}"
                    b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
                    cmd.extend(["-H", f"Authorization: Basic {b64_auth}"])
                    logger.info("Injected HTTP Basic Auth into Nuclei headers.")
            
            # Format targets with ports if ports are provided
            # IMPORTANT: In Nuclei, '-p' is the short flag for '--proxy'!
            # To scan specific ports, targets must be passed as 'host:port' with '-u'.
            scan_targets = []
            for t in targets:
                scan_targets.append(t)
                if ports:
                    for p in ports.split(','):
                        p_clean = p.strip()
                        if p_clean.isdigit():
                            scan_targets.append(f"{t}:{p_clean}")
                            
            for st in list(dict.fromkeys(scan_targets)):
                cmd.extend(["-u", st])
                
            # Completely strip all proxy environment variables to prevent Nuclei proxy errors
            env = os.environ.copy()
            for proxy_var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"]:
                env.pop(proxy_var, None)
                
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=False,
                stdin=subprocess.DEVNULL,
                env=env,
                timeout=86400
            )
            
            # Log any errors Nuclei spits out
            if result.stderr:
                logger.warning(f"Nuclei output/errors: {result.stderr}")
                
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    logger.info(f"Nuclei raw output for {target}:\n{f.read()}")
                    
            # Nuclei might return non-zero if vulnerabilities are found, so we don't strict check=True
            return NucleiAdapter._parse_nuclei_json(output_file)
        except subprocess.TimeoutExpired:
            logger.error(f"Nuclei scan timed out for {target}")
            raise Exception(f"Nuclei scan timed out on {target}")
        except Exception as e:
            logger.error(f"Nuclei scan failed: {str(e)}")
            raise Exception(f"Nuclei scan failed: {str(e)}")
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    @staticmethod
    def _parse_nuclei_json(filepath: str) -> List[Dict]:
        """Parses Nuclei JSON output."""
        vulns = []
        if not os.path.exists(filepath):
            return vulns
            
        try:
            with open(filepath, 'r') as f:
                # Nuclei JSON export might be a JSON array or JSON lines. 
                # Modern Nuclei -je creates a JSON array.
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        lines = data
                    else:
                        lines = [data]
                except json.JSONDecodeError:
                    # Fallback to JSON Lines
                    f.seek(0)
                    lines = [json.loads(line) for line in f if line.strip()]
                    
                for entry in lines:
                    info = entry.get("info", {})
                    
                    vulns.append({
                        "id": entry.get("template-id", "unknown"),
                        "name": info.get("name", "Nuclei Finding"),
                        "severity": info.get("severity", "info"),
                        "description": info.get("description", ""),
                        "remediation": info.get("remediation", ""),
                        "cvss_score": info.get("classification", {}).get("cvss-score", 0.0),
                        "cve_id": info.get("classification", {}).get("cve-id", [None])[0] if info.get("classification", {}).get("cve-id") else None,
                        "matched_at": entry.get("matched-at", ""),
                        "extracted_results": entry.get("extracted-results", [])
                    })
        except Exception as e:
            logger.error(f"Failed to parse Nuclei JSON: {str(e)}")
            
        logger.info(f"Nuclei parsed result:\n{json.dumps(vulns, indent=2)}")
        return vulns
