import subprocess
import logging
import json
import os
from typing import List, Dict

logger = logging.getLogger(__name__)

class NucleiAdapter:
    @staticmethod
    def run_scan(target: str) -> List[Dict]:
        """Runs a Nuclei vulnerability scan and returns structured JSON data."""
        logger.info(f"Running Nuclei scan on {target}")
        
        output_file = f"/tmp/nuclei_{target.replace('.', '_')}.json"
        
        try:
            # Nuclei expects a URL for web templates. Add http:// if it's just a domain.
            formatted_target = target
            if not target.startswith("http://") and not target.startswith("https://"):
                formatted_target = f"http://{target}"
                logger.info(f"Nuclei target formatted to: {formatted_target}")

            # -ut: Update Templates automatically
            # Removed -silent so we can capture errors in stderr
            result = subprocess.run(["nuclei", "-ut", "-u", formatted_target, "-je", output_file, "-nc"], 
                           capture_output=True, text=True, check=False)
            
            # Log any errors Nuclei spits out
            if result.stderr:
                logger.warning(f"Nuclei output/errors: {result.stderr}")
                
            # Nuclei might return non-zero if vulnerabilities are found, so we don't strict check=True
            return NucleiAdapter._parse_nuclei_json(output_file)
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
            
        return vulns
