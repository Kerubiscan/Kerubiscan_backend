import os
from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime, timezone
from typing import List, Dict, Optional

from src.assets.domain.entities import AssetEntity
from src.vulnerabilities.domain.entities import VulnerabilityEntity

NO_REMEDIATION = "Aucune recommandation fournie par le scanner pour ce point."

# Text the AI module used to return when no AI answered; it was saved as if it were a summary
_PLACEHOLDER_SUMMARIES = ("Résumé exécutif généré automatiquement : Des vulnérabilités ont été détectées.",)


def _real_summary(summary: Optional[str]) -> Optional[str]:
    """The executive summary, unless empty or the old placeholder (shown only when really written)."""
    text = (summary or "").strip()
    if not text or any(text.startswith(p) for p in _PLACEHOLDER_SUMMARIES):
        return None
    return text

_CIA_LEVELS = {"H": "ÉLEVÉ", "L": "FAIBLE", "N": "AUCUN"}


def _cia_from_vector(vector: Optional[str]) -> Optional[str]:
    """C/I/A impact read from a real CVSS v3 vector; None when there is no vector.

    The report used to derive both the vector and this impact from the score alone, which printed
    invented (and invalid: C:M does not exist in CVSS 3) data as if the scanner had provided it.
    """
    if not vector:
        return None
    metrics = dict(part.split(":", 1) for part in vector.split("/") if ":" in part)
    if not all(k in metrics for k in ("C", "I", "A")):
        return None
    return (f"Confidentialité : {_CIA_LEVELS.get(metrics['C'], metrics['C'])} | "
            f"Intégrité : {_CIA_LEVELS.get(metrics['I'], metrics['I'])} | "
            f"Disponibilité : {_CIA_LEVELS.get(metrics['A'], metrics['A'])}")


def _plugin(rule_id: Optional[str]):
    """(label, url) for the "Plugin" column, like the plugin ID of a Nessus report.

    rule_id is "<engine>:<id>[:<extra>]"; findings stored before the column existed have none.
    """
    if not rule_id or ":" not in rule_id:
        return "-", None
    engine, _, rest = rule_id.partition(":")
    if engine == "nuclei":
        template = rest.split(":", 1)[0]
        return template, f"https://cloud.projectdiscovery.io/public/{template}"
    if engine == "nmap":
        if rest.startswith("vulners:"):
            cve = rest.split(":", 1)[1]
            return "vulners", f"https://vulners.com/cve/{cve}"
        return rest, f"https://nmap.org/nsedoc/scripts/{rest}.html"
    if engine == "zap":
        return rest, f"https://www.zaproxy.org/docs/alerts/{rest}/"
    if engine == "openvas":
        return rest, None   # NVT OID: no stable public page
    return rest, None


def _report_date(dt: Optional[datetime]) -> str:
    """Same layout as the Nessus report date ("Thu, 08 Oct 2026 20:22:14 Africa/Lagos")."""
    local = _local(dt)
    return f"{local.strftime('%a, %d %b %Y %H:%M:%S')} {os.environ.get('TZ') or local.tzname() or 'UTC'}"


def _local(dt: Optional[datetime]) -> datetime:
    """Dates are stored in UTC: show them in the server's time zone (TZ), like the logs."""
    if dt is None:
        return datetime.now()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone()

def generate_vulnerability_html(
    assets: List[AssetEntity], 
    all_vulnerabilities: Dict[str, List[VulnerabilityEntity]],
    executive_summary: str,
    scanner_company_name: str = "KERIBU SOC Security",
    target_company_name: str = "Client Company",
    scan_name: str = "Vulnerability Scan Report",
    scan_profile: str = "Full Security Audit (Multi-Engine)",
    classification: str = "CONFIDENTIEL - USAGE INTERNE",
    scan_date: datetime = None,
    report_title: Optional[str] = None
) -> bytes:
    """report_title (the scan's network zone) is the report heading, where Nessus shows the scan name."""
    template_assets = []
    all_vulns_flat: List[Dict] = []
    
    total_crit = 0
    total_high = 0
    total_med = 0
    total_low = 0
    total_info = 0
    cvss_scores: List[float] = []

    for asset in assets:
        vulns = all_vulnerabilities.get(str(asset.id), [])
        
        name_str = (asset.name.strip() if asset.name and asset.name.strip() else asset.ip_address)
        if "Auto-added" in name_str:
            # Clean up the name e.g., "Auto-added Host (192.168.100.75)" or "Auto-added Web Host (...)" -> "192.168.100.75"
            name_str = name_str.replace("Auto-added Host", "").replace("Auto-added Web Host", "").replace("(", "").replace(")", "").strip()

        asset_data = {
            "id": str(asset.id),
            "name": name_str,
            "ip_address": asset.ip_address or asset.name,
            "operating_system": asset.operating_system or "Linux / Unix (détecté via empreinte)",
            "ports": asset.ports or "80/tcp (http), 443/tcp (https), 22/tcp (ssh)",
            "crit_count": 0,
            "high_count": 0,
            "med_count": 0,
            "low_count": 0,
            "info_count": 0,
            "vulnerabilities": []
        }
        
        def get_severity_weight(sev_str: str) -> int:
            mapping = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
            return mapping.get(sev_str, 0)
            
        def sort_vulns(v):
            sev_str = getattr(v.severity, "value", str(v.severity))
            cvss = float(getattr(v, "cvss_base_score", 0.0) or 0.0)
            return (-get_severity_weight(sev_str), -cvss, (v.title or "").lower())

        # Same order as Nessus: severity, then CVSS score, then name
        for v in sorted(vulns, key=sort_vulns):
            sev_str = getattr(v.severity, "value", str(v.severity))
            score = float(v.cvss_base_score) if v.cvss_base_score is not None else 0.0
            if score > 0:
                cvss_scores.append(score)
                
            if sev_str == "Critical":
                asset_data["crit_count"] += 1
                total_crit += 1
            elif sev_str == "High":
                asset_data["high_count"] += 1
                total_high += 1
            elif sev_str == "Medium":
                asset_data["med_count"] += 1
                total_med += 1
            elif sev_str == "Low":
                asset_data["low_count"] += 1
                total_low += 1
            else:
                asset_data["info_count"] += 1
                total_info += 1
            
            # Only what the scanner provided: no vector, impact or proof is made up from the score
            vector = v.cvss_vector or None
            cia_impact = _cia_from_vector(vector)

            cve = v.cve_id or "N/A"
            ref_url = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve != "N/A" and "CVE" in cve.upper() else "https://cve.mitre.org"

            # Parse AI Analysis if available
            ai_data = getattr(v, "ai_analysis", None)
            plugin, plugin_url = _plugin(getattr(v, "rule_id", None))

            vuln_obj = {
                "id": str(v.id),
                "asset_name": asset_data["ip_address"],
                "severity": sev_str,
                "cvss": str(v.cvss_base_score or "N/A"),
                "cvss_vector": vector,
                "cve": cve,
                "ref_url": ref_url,
                "engine": v.source_engine or "OPENVAS / MULTI-ENGINE",
                "plugin": plugin,
                "plugin_url": plugin_url,
                "title": v.title,
                "description": v.description or "Aucune description fournie par le scanner.",
                "remediation": getattr(v, "remediation", None) or NO_REMEDIATION,
                "impact_cia": cia_impact,
                # The evidence (URLs, extracts) is already in the description
                "proof": None,
                "ai_analysis": ai_data
            }
            
            asset_data["vulnerabilities"].append(vuln_obj)
            all_vulns_flat.append(vuln_obj)
            
        template_assets.append(asset_data)
        
    # Calculate Overall Risk Score (weighted CVSS average)
    overall_cvss_avg = round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else 0.0
    
    # Top 10 Most Vulnerable Hosts
    top_hosts = sorted(template_assets, key=lambda a: (a["crit_count"]*10 + a["high_count"]*5 + a["med_count"]*2), reverse=True)[:10]
    
    # Top 10 Critical Vulnerabilities
    def sort_flat_vulns(v):
        mapping = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
        weight = mapping.get(v["severity"], 0)
        cvss = float(v["cvss"]) if v["cvss"] != "N/A" else 0.0
        return (weight, cvss)
        
    top_vulnerabilities = sorted(all_vulns_flat, key=sort_flat_vulns, reverse=True)[:10]

    template_data = {
        "scan_name": report_title or scan_name,
        "scan_profile": scan_profile,
        "classification": classification,
        "report_date": _report_date(scan_date),
        "scanner_company_name": scanner_company_name,
        "target_company_name": target_company_name,
        "executive_summary": _real_summary(executive_summary),
        "assets": template_assets,
        "total_crit": total_crit,
        "total_high": total_high,
        "total_med": total_med,
        "total_low": total_low,
        "total_info": total_info,
        "total_vulns": len(all_vulns_flat),
        "overall_cvss_avg": overall_cvss_avg,
        "top_hosts": top_hosts,
        "top_vulnerabilities": top_vulnerabilities
    }
    
    # Load KerubiSOC logo base64
    current_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(current_dir, "..", "..", "templates")
    
    logo_base64 = ""
    logo_b64_path = os.path.join(templates_dir, "logo_b64.txt")
    if os.path.exists(logo_b64_path):
        with open(logo_b64_path, "r", encoding="utf-8") as f:
            logo_base64 = f.read().strip()
    else:
        logo_png_path = os.path.join(templates_dir, "keribusoc_logo.png")
        if os.path.exists(logo_png_path):
            import base64
            with open(logo_png_path, "rb") as f:
                logo_base64 = base64.b64encode(f.read()).decode("utf-8")

    template_data["logo_base64"] = logo_base64

    # Autoescape: findings contain text taken from the scanned targets (page titles, evidences) —
    # without it, a malicious target could inject HTML/JavaScript into the report (stored XSS).
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=select_autoescape(["html"]))
    template = env.get_template("keribusoc_report.html")
    
    rendered_html = template.render(**template_data)
    return rendered_html.encode('utf-8')

def generate_discovery_html(
    assets: List[AssetEntity], 
    scanner_company_name: str = "KERIBU SOC Security",
    target_company_name: str = "Client Company",
    scan_name: str = "Discovery Scan Report",
    scan_profile: str = "Host Discovery",
    classification: str = "CONFIDENTIEL - USAGE INTERNE",
    scan_date: datetime = None,
    report_title: Optional[str] = None
) -> bytes:
    template_assets = []

    for asset in assets:
        name_str = (asset.name.strip() if asset.name and asset.name.strip() else asset.ip_address)
        if "Auto-added" in name_str:
            name_str = name_str.replace("Auto-added Host", "").replace("Auto-added Web Host", "").replace("(", "").replace(")", "").strip()

        # Parse history safely — AssetEntity has no history column, so default to empty
        history_list = []
        import json
        _history = getattr(asset, "history", None)
        if _history:
            try:
                if isinstance(_history, list):
                    history_list = _history
                else:
                    history_list = json.loads(_history)
            except Exception:
                pass

        asset_data = {
            "id": str(asset.id),
            "name": name_str,
            "ip_address": asset.ip_address or asset.name,
            "mac_address": asset.mac_address or "N/A",
            "operating_system": asset.operating_system or "Unknown",
            "network_zone": asset.network_zone or "N/A",
            "ports": asset.ports or "None detected",
            "running_services": asset.services or "None detected",
            "history": history_list
        }
        template_assets.append(asset_data)
        
    template_data = {
        "scan_name": report_title or scan_name,
        "scan_profile": scan_profile,
        "classification": classification,
        "report_date": _report_date(scan_date),
        "scanner_company_name": scanner_company_name,
        "target_company_name": target_company_name,
        "assets": template_assets,
        "total_hosts": len(template_assets)
    }
    
    # Load KerubiSOC logo base64
    current_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(current_dir, "..", "..", "templates")
    
    logo_base64 = ""
    logo_b64_path = os.path.join(templates_dir, "logo_b64.txt")
    if os.path.exists(logo_b64_path):
        with open(logo_b64_path, "r", encoding="utf-8") as f:
            logo_base64 = f.read().strip()
    else:
        logo_png_path = os.path.join(templates_dir, "keribusoc_logo.png")
        if os.path.exists(logo_png_path):
            import base64
            with open(logo_png_path, "rb") as f:
                logo_base64 = base64.b64encode(f.read()).decode("utf-8")

    template_data["logo_base64"] = logo_base64

    # Autoescape: findings contain text taken from the scanned targets (page titles, evidences) —
    # without it, a malicious target could inject HTML/JavaScript into the report (stored XSS).
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=select_autoescape(["html"]))
    template = env.get_template("keribusoc_discovery_report.html")
    
    rendered_html = template.render(**template_data)
    return rendered_html.encode('utf-8')

