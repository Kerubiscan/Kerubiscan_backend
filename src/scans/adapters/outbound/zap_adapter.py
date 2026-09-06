import subprocess
import logging
import json
import os
from typing import List, Dict

logger = logging.getLogger(__name__)

class ZAPAdapter:
    @staticmethod
    def run_scan(target: str) -> List[Dict]:
        """Runs an OWASP ZAP baseline scan and returns structured JSON data."""
        logger.info(f"Running ZAP Baseline scan on {target}")
        
        safe_name = target.replace('://', '_').replace('.', '_').replace('/', '_').replace(':', '_')
        output_filename = f"zap_{safe_name}.json"
        output_file = f"/tmp/{output_filename}"
        
        try:
            formatted_target = target
            if not target.startswith("http://") and not target.startswith("https://"):
                formatted_target = f"http://{target}"
                logger.info(f"ZAP target formatted to: {formatted_target}")

            # Run zap-baseline.py (Assuming it's available in the worker's path or Docker image)
            # -t: target URL
            # -J: output JSON file name (by default it saves to CWD)
            result = subprocess.run(
                ["zap-baseline.py", "-t", formatted_target, "-J", output_filename], 
                capture_output=True, 
                text=True, 
                check=False,
                cwd="/tmp",
                stdin=subprocess.DEVNULL,
                timeout=86400
            )
            
            if result.stderr:
                logger.warning(f"ZAP output/errors: {result.stderr[:1000]}...")
                
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    # ZAP JSON can be large, we'll log the first 2000 chars
                    raw_data = f.read()
                    logger.info(f"ZAP raw output for {target}:\n{raw_data[:2000]}...")
                    
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
            return vulns
            
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                
            sites = data.get("site", [])
            for site in sites:
                alerts = site.get("alerts", [])
                for alert in alerts:
                    # ZAP risk is usually like "High (Medium)" or "Low"
                    risk_desc = alert.get("riskdesc", "Info")
                    severity_str = risk_desc.split(" ")[0].lower()
                    
                    vulns.append({
                        "id": alert.get("pluginid", "unknown"),
                        "name": alert.get("name", "ZAP Finding"),
                        "severity": severity_str,
                        "description": alert.get("desc", ""),
                        "remediation": alert.get("solution", ""),
                        "cvss_score": 0.0, # ZAP baseline JSON rarely includes direct CVSS
                        "cve_id": None,
                        "reference": alert.get("reference", ""),
                        "instances": alert.get("instances", [])
                    })
            
            logger.info(f"ZAP parsed result:\n{json.dumps(vulns, indent=2)}")
        except Exception as e:
            logger.error(f"Failed to parse ZAP JSON: {str(e)}")
            
        return vulns
