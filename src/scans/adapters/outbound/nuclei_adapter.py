import os
import json
import shutil
import tempfile
import logging
import base64
from typing import List, Dict, Optional, Union
from src.scans.adapters.outbound.base_adapter import BaseScannerAdapter, ScanError

logger = logging.getLogger(__name__)

class NucleiAdapter(BaseScannerAdapter):
    @staticmethod
    def run_scan(target: Union[str, List[str]], ports: Optional[str] = None, credentials: Optional[Dict] = None) -> List[Dict]:
        """Runs a Nuclei vulnerability scan and returns structured JSON data."""
        targets = [target] if isinstance(target, str) else list(target)
        if not targets:
            raise ValueError("No target provided")
            
        logger.info(f"Running Nuclei scan on {targets} with ports {ports}")
        
        workdir = tempfile.mkdtemp(prefix="nuclei_")
        targets_file = os.path.join(workdir, "targets.txt")
        out_file = os.path.join(workdir, "results.jsonl")
        err_file = os.path.join(workdir, "stderr.log")
        
        try:
            scan_targets = []
            for t in targets:
                scan_targets.append(t)
                if ports:
                    for p in ports.split(','):
                        p_clean = p.strip()
                        if p_clean.isdigit():
                            scan_targets.append(f"{t}:{p_clean}")
                            
            with open(targets_file, "w", encoding="utf-8") as f:
                f.write("\n".join(dict.fromkeys(scan_targets)))

            # -duc: disable updates, -nc: no color, -jle: JSONL export
            cmd = ["/usr/local/bin/nuclei", "-duc", "-nc", "-l", targets_file, "-jle", out_file]
            
            if credentials and credentials.get("credential_type") == "HTTP":
                user = credentials.get("username", "")
                pwd = credentials.get("password", "")
                if user or pwd:
                    auth_str = f"{user}:{pwd}"
                    b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
                    cmd.extend(["-H", f"Authorization: Basic {b64_auth}"])
                    logger.info("Injected HTTP Basic Auth into Nuclei headers.")
                    
            env = os.environ.copy()
            for proxy_var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"]:
                env.pop(proxy_var, None)
                
            returncode, stderr_tail = NucleiAdapter.run_process(
                cmd=cmd,
                timeout=86400,
                err_file_path=err_file,
                env=env
            )
            
            if returncode != 0:
                raise ScanError(f"Nuclei exited with code {returncode}: {stderr_tail}")
                
            if not os.path.exists(out_file):
                return []
                
            return NucleiAdapter._parse_nuclei_jsonl(out_file)
            
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def _parse_nuclei_jsonl(path: str) -> List[Dict]:
        """Parses Nuclei JSONL output."""
        vulns = []
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    raise ScanError(f"Invalid Nuclei JSON at line {n}") from e

                info = entry.get("info") or {}
                cls = info.get("classification") or {}
                cves = cls.get("cve-id") or []
                if isinstance(cves, str):
                    cves = [cves]
                cves = [c.upper() for c in cves]

                vuln = {
                    "id": f"nuclei-{entry.get('template-id', 'unknown')}",
                    "name": info.get("name", "Nuclei Finding"),
                    "severity": (info.get("severity") or "info").lower(),
                    "description": info.get("description", ""),
                    "remediation": info.get("remediation", ""),
                    "cvss_score": cls.get("cvss-score"),
                    "cve_id": cves[0] if cves else None,
                    "cve_ids": cves,
                    "host": entry.get("host"),
                    "ip": entry.get("ip"),
                    "matcher_name": entry.get("matcher-name"),
                    "matched_at": entry.get("matched-at", ""),
                    "extracted_results": entry.get("extracted-results") or [],
                }
                vulns.append(vuln)
                
        logger.info(f"Nuclei parsed {len(vulns)} results.")
        return vulns
