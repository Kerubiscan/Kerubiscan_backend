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
    scanner_company_name: str = "Kerubiscan Security",
    target_company_name: str = "Client Company",
    scan_name: str = "Vulnerability Scan Report"
) -> bytes:
    
    # 1. Prepare data for Jinja2
    template_assets = []
    
    for asset in assets:
        vulns = all_vulnerabilities.get(str(asset.id), [])
        
        asset_data = {
            "id": str(asset.id),
            "ip_address": asset.ip_address or asset.name,
            "crit_count": 0,
            "high_count": 0,
            "med_count": 0,
            "low_count": 0,
            "info_count": 0,
            "vulnerabilities": []
        }
        
        for v in sorted(vulns, key=lambda x: getattr(x, "cvss_base_score", 0.0) or 0.0, reverse=True):
            sev_str = getattr(v.severity, "value", str(v.severity))
            if sev_str == "Critical": asset_data["crit_count"] += 1
            elif sev_str == "High": asset_data["high_count"] += 1
            elif sev_str == "Medium": asset_data["med_count"] += 1
            elif sev_str == "Low": asset_data["low_count"] += 1
            else: asset_data["info_count"] += 1
            
            asset_data["vulnerabilities"].append({
                "id": str(v.id),
                "severity": sev_str,
                "cvss": str(v.cvss_base_score or "N/A"),
                "cve": v.cve_id or "N/A",
                "engine": v.source_engine or "Unknown",
                "title": v.title,
                "description": v.description or "No description provided.",
                "remediation": getattr(v, "remediation", "No remediation provided.") or "No remediation provided."
            })
            
        template_assets.append(asset_data)
        
    template_data = {
        "scan_name": scan_name,
        "report_date": datetime.now().strftime("%a, %d %b %Y %H:%M:%S"),
        "scanner_company_name": scanner_company_name,
        "target_company_name": target_company_name,
        "executive_summary": executive_summary,
        "assets": template_assets
    }
    
    # 2. Render Jinja2 Template
    current_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(current_dir, "..", "..", "templates")
    
    env = Environment(loader=FileSystemLoader(templates_dir))
    template = env.get_template("nessus_report.html")
    
    rendered_html = template.render(**template_data)
    
    return rendered_html.encode('utf-8')
