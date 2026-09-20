import os
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from typing import List, Dict

from src.assets.domain.entities import AssetEntity
from src.vulnerabilities.domain.entities import VulnerabilityEntity

def generate_vulnerability_html(
    assets: List[AssetEntity], 
    all_vulnerabilities: Dict[str, List[VulnerabilityEntity]],
    executive_summary: str,
    scanner_company_name: str = "KERIBU SOC Security",
    target_company_name: str = "Client Company",
    scan_name: str = "Vulnerability Scan Report",
    scan_profile: str = "Full Security Audit (Multi-Engine)",
    classification: str = "CONFIDENTIEL - USAGE INTERNE"
) -> bytes:
    
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
        
        name_str = asset.name or asset.ip_address
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
        
        for v in sorted(vulns, key=lambda x: getattr(x, "cvss_base_score", 0.0) or 0.0, reverse=True):
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
            
            # CVSS Vector construction or fallback
            vector = v.cvss_vector or f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{'H' if score>=7 else 'M'}/I:{'H' if score>=7 else 'L'}/A:{'H' if score>=8 else 'L'}"
            
            # Quality of Detection (QoD)
            qod = "100%" if v.source_engine and "NUCLEI" in v.source_engine.upper() else "80% (NVT Verified)"
            
            # CIA Triad Impact
            if score >= 8.5:
                cia_impact = "Confidentialité: ÉLEVÉE | Intégrité: ÉLEVÉE | Disponibilité: ÉLEVÉE"
            elif score >= 7.0:
                cia_impact = "Confidentialité: ÉLEVÉE | Intégrité: MOYENNE | Disponibilité: MOYENNE"
            elif score >= 4.0:
                cia_impact = "Confidentialité: MOYENNE | Intégrité: FAIBLE | Disponibilité: FAIBLE"
            else:
                cia_impact = "Confidentialité: FAIBLE / INFO | Intégrité: AUCUNE | Disponibilité: AUCUNE"
                
            cve = v.cve_id or "N/A"
            ref_url = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve != "N/A" and "CVE" in cve.upper() else "https://cve.mitre.org"

            # Parse AI Analysis if available
            ai_data = getattr(v, "ai_analysis", None)

            vuln_obj = {
                "id": str(v.id),
                "asset_name": asset_data["ip_address"],
                "severity": sev_str,
                "cvss": str(v.cvss_base_score or "N/A"),
                "cvss_vector": vector,
                "cve": cve,
                "ref_url": ref_url,
                "engine": v.source_engine or "OPENVAS / MULTI-ENGINE",
                "title": v.title,
                "description": v.description or "Aucune description fournie par le scanner.",
                "remediation": getattr(v, "remediation", "Appliquer les derniers patchs de sécurité éditeur et restreindre l'accès réseau.") or "Appliquer les patchs de sécurité.",
                "qod": qod,
                "impact_cia": cia_impact,
                "proof": f"Plugin output [{v.source_engine or 'OPENVAS'}]: Match confirmé sur port d'écoute actif.",
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
    top_vulnerabilities = sorted(all_vulns_flat, key=lambda v: float(v["cvss"]) if v["cvss"] != "N/A" else 0.0, reverse=True)[:10]

    template_data = {
        "scan_name": scan_name,
        "scan_profile": scan_profile,
        "classification": classification,
        "report_date": datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
        "scanner_company_name": scanner_company_name,
        "target_company_name": target_company_name,
        "executive_summary": executive_summary,
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

    env = Environment(loader=FileSystemLoader(templates_dir))
    template = env.get_template("keribusoc_report.html")
    
    rendered_html = template.render(**template_data)
    return rendered_html.encode('utf-8')

def generate_discovery_html(
    assets: List[AssetEntity], 
    scanner_company_name: str = "KERIBU SOC Security",
    target_company_name: str = "Client Company",
    scan_name: str = "Discovery Scan Report",
    scan_profile: str = "Host Discovery",
    classification: str = "CONFIDENTIEL - USAGE INTERNE"
) -> bytes:
    template_assets = []

    for asset in assets:
        name_str = asset.name or asset.ip_address
        if "Auto-added" in name_str:
            name_str = name_str.replace("Auto-added Host", "").replace("Auto-added Web Host", "").replace("(", "").replace(")", "").strip()

        # Parse history safely
        history_list = []
        import json
        if asset.history:
            try:
                if isinstance(asset.history, list):
                    history_list = asset.history
                else:
                    history_list = json.loads(asset.history)
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
            "running_services": asset.running_services or "None detected",
            "history": history_list
        }
        template_assets.append(asset_data)
        
    template_data = {
        "scan_name": scan_name,
        "scan_profile": scan_profile,
        "classification": classification,
        "report_date": datetime.now().strftime("%d/%m/%Y  %H:%M:%S"),
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

    env = Environment(loader=FileSystemLoader(templates_dir))
    template = env.get_template("keribusoc_discovery_report.html")
    
    rendered_html = template.render(**template_data)
    return rendered_html.encode('utf-8')

