import os
import json
import glob
import shutil
import tempfile
import logging
import base64
import subprocess
from typing import List, Dict, Optional, Union
from urllib.parse import urlsplit
from src.scans.adapters.outbound.base_adapter import BaseScannerAdapter, ScanError
from src.vulnerabilities.domain import severity as sev

logger = logging.getLogger(__name__)

NUCLEI_BIN = "/usr/local/bin/nuclei"

# Per profile request settings. Nuclei defaults (150 req/s, 10 s timeout, 1 retry) get public
# sites behind a WAF/CDN to block the scanner, which then looks like "no vulnerability".
PROFILES = {
    "lan": ["-rl", "150", "-timeout", "10", "-retries", "1"],
    "internet": ["-rl", "30", "-c", "10", "-timeout", "20", "-retries", "2"],
}

MIN_TEMPLATES = 100


def _templates_dir() -> str:
    if os.environ.get("NUCLEI_TEMPLATES_DIR"):
        return os.environ["NUCLEI_TEMPLATES_DIR"]
    # Nuclei records its templates location in its config file
    config = os.path.expanduser("~/.config/nuclei/.templates-config.json")
    try:
        with open(config, encoding="utf-8") as f:
            configured = json.load(f).get("nuclei-templates-directory")
        if configured:
            return configured
    except (OSError, ValueError):
        pass
    return os.path.expanduser("~/nuclei-templates")


def _count_templates(path: str) -> int:
    if not os.path.isdir(path):
        return 0
    return len(glob.glob(os.path.join(path, "**", "*.yaml"), recursive=True))


def ensure_templates() -> int:
    """Nuclei silently finds nothing without templates (the image build ignores download errors)."""
    path = _templates_dir()
    count = _count_templates(path)
    if count >= MIN_TEMPLATES:
        return count
    logger.warning(f"Nuclei templates missing or incomplete in {path} ({count}); downloading them now")
    try:
        subprocess.run([NUCLEI_BIN, "-ut"], capture_output=True, text=True, timeout=900)
    except Exception as e:
        logger.error(f"Nuclei template download failed: {e}")
    count = _count_templates(path)
    if count < MIN_TEMPLATES:
        raise ScanError(f"Templates Nuclei absents ({count} trouvés dans {path}) : scan impossible")
    return count


class NucleiAdapter(BaseScannerAdapter):
    @staticmethod
    def run_scan(target: Union[str, List[str]], ports: Optional[str] = None, credentials: Optional[Dict] = None,
                 profile: str = "lan") -> List[Dict]:
        """Runs a Nuclei scan and returns the raw JSON findings."""
        targets = [target] if isinstance(target, str) else list(target)
        targets = [t for t in targets if t]
        if not targets:
            raise ValueError("No target provided")

        templates = ensure_templates()
        logger.info(f"Running Nuclei ({templates} templates, profile={profile}) on {targets}")

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
                        if p.strip().isdigit():
                            scan_targets.append(f"{t}:{p.strip()}")
            with open(targets_file, "w", encoding="utf-8") as f:
                f.write("\n".join(dict.fromkeys(scan_targets)))

            # -duc: no update check during the scan (templates are checked above), -nc: no color, -jle: JSONL export
            cmd = [NUCLEI_BIN, "-duc", "-nc", "-l", targets_file, "-jle", out_file, *PROFILES.get(profile, PROFILES["lan"])]

            c_type = (credentials or {}).get("credential_type", "")
            if credentials and str(c_type).upper() in ("HTTP", "HTTP_BASIC"):
                user = credentials.get("username", "")
                pwd = credentials.get("password", "")
                if user or pwd:
                    b64_auth = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("utf-8")
                    cmd.extend(["-H", f"Authorization: Basic {b64_auth}"])
                    logger.info("Nuclei: authenticated scan enabled (HTTP Basic)")
            elif credentials:
                logger.warning(f"Nuclei: credential of type {c_type or 'UNKNOWN'} not usable by Nuclei, scan runs unauthenticated")

            env = os.environ.copy()
            for proxy_var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"]:
                env.pop(proxy_var, None)

            returncode, stderr_tail = NucleiAdapter.run_process(cmd=cmd, timeout=86400, err_file_path=err_file, env=env)
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

                vulns.append({
                    "id": f"nuclei-{entry.get('template-id', 'unknown')}",
                    "template_id": entry.get("template-id", "unknown"),
                    "name": info.get("name", "Nuclei Finding"),
                    "severity": (info.get("severity") or "info").lower(),
                    "description": info.get("description", ""),
                    "remediation": info.get("remediation", ""),
                    "cvss_score": cls.get("cvss-score"),
                    "cve_id": cves[0] if cves else None,
                    "cve_ids": cves,
                    "host": entry.get("host"),
                    "ip": entry.get("ip"),
                    "port": entry.get("port"),
                    "matcher_name": entry.get("matcher-name"),
                    "matched_at": entry.get("matched-at", ""),
                    "extracted_results": entry.get("extracted-results") or [],
                })

        logger.info(f"Nuclei parsed {len(vulns)} results.")
        return vulns


def _port_of(location: str, fallback=None) -> Optional[int]:
    if not location:
        return fallback
    try:
        if "://" in location:
            parts = urlsplit(location)
            return parts.port or {"http": 80, "https": 443}.get(parts.scheme, fallback)
        tail = location.rsplit(":", 1)
        if len(tail) == 2 and tail[1].isdigit():
            return int(tail[1])
    except ValueError:
        pass
    return fallback


def normalize_nuclei(raw: List[Dict]) -> List[Dict]:
    """One finding per (template, matcher, port); all matched locations are kept as evidence."""
    grouped: Dict[tuple, Dict] = {}
    for v in raw:
        title = v.get("name") or "Nuclei Finding"
        if v.get("matcher_name"):
            title = f"{title} : {v['matcher_name']}"
        location = v.get("matched_at") or v.get("host") or ""
        try:
            port_hint = int(v.get("port")) if v.get("port") else None
        except (TypeError, ValueError):
            port_hint = None
        port = _port_of(location, port_hint)
        cvss = sev.to_cvss(v.get("cvss_score"))
        key = (v.get("template_id") or v.get("id"), v.get("matcher_name"), port)
        f = grouped.get(key)
        if f is None:
            f = grouped[key] = {
                "rule_id": f"nuclei:{v.get('template_id') or v.get('id')}:{v.get('matcher_name') or ''}",
                "title": title[:250],
                "severity": sev.resolve(v.get("severity"), cvss).value,
                "cvss": cvss,
                "cve_id": v.get("cve_id"),
                "cve_ids": v.get("cve_ids") or [],
                "description": v.get("description") or "",
                "remediation": v.get("remediation") or "",
                "port": port,
                "service": urlsplit(location).scheme if "://" in location else None,
                "evidence": [],
            }
        if location and location not in f["evidence"]:
            f["evidence"].append(location)
        for extracted in v.get("extracted_results") or []:
            item = f"Extrait : {extracted}"
            if item not in f["evidence"]:
                f["evidence"].append(item)
    return list(grouped.values())
