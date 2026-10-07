"""Normalisation of OpenVAS / GVM XML reports into the common finding format."""
import logging
from typing import Dict, Optional
from lxml import etree
from src.vulnerabilities.domain import severity as sev

logger = logging.getLogger(__name__)


def _text(elem, path: str) -> Optional[str]:
    value = elem.findtext(path) if elem is not None else None
    return value.strip() if value else None


def normalize_openvas(report_xml: str) -> Dict[str, Dict]:
    """Returns {host_ip: {"os", "ports", "findings"}} from a GVM report (one entry per scanned host)."""
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True)
    root = etree.fromstring(report_xml.encode("utf-8"), parser=parser)

    hosts: Dict[str, Dict] = {}

    def host_entry(ip: str) -> Dict:
        return hosts.setdefault(ip, {"os": None, "ports": [], "findings": {}})

    for host in root.xpath("//report/report/host") or root.xpath("//report/host"):
        ip = _text(host, "ip")
        if not ip:
            continue
        entry = host_entry(ip)
        os_details = host.xpath(".//detail[name='best_os_txt']/value/text()") or \
            host.xpath(".//detail[name='Best OS']/value/text()") or host.xpath(".//detail[name='OS']/value/text()")
        if os_details:
            entry["os"] = os_details[0].strip()

    results = root.xpath("//report/report/results/result") or root.xpath("//report/results/result")
    for result in results:
        ip = _text(result, "host") or "unknown"
        entry = host_entry(ip)

        port_str = _text(result, "port") or ""
        port, service = None, None
        if "/" in port_str:
            num, _, proto = port_str.partition("/")
            if num.isdigit():
                port = int(num)
                service = proto or None
                if port_str not in entry["ports"]:
                    entry["ports"].append(port_str)

        threat = _text(result, "threat")
        if threat in ("Log", "False Positive", "Debug"):
            continue
        nvt = result.find("nvt")
        if nvt is None:
            continue
        title = (_text(nvt, "name") or _text(result, "name") or "")[:250]
        if not title:
            continue

        cvss = sev.to_cvss(_text(result, "severity")) or sev.to_cvss(_text(nvt, "cvss_base"))
        cves = [c.upper() for c in nvt.xpath(".//ref[@type='cve']/@id")]
        legacy_cve = _text(nvt, "cve")
        if legacy_cve and legacy_cve != "NOCVE":
            cves = [c.strip().upper() for c in legacy_cve.split(",")] + cves
        cves = list(dict.fromkeys(cves))

        key = (title, port)
        if key in entry["findings"]:
            continue
        entry["findings"][key] = {
            "rule_id": f"openvas:{nvt.get('oid')}",
            "title": title,
            "severity": sev.resolve(threat, cvss).value,
            "cvss": cvss,
            "cve_id": cves[0] if cves else None,
            "cve_ids": cves,
            "description": _text(result, "description") or _text(nvt, "summary") or "",
            "remediation": _text(nvt, "solution") or "",
            "port": port,
            "service": service,
            "evidence": [],
        }

    for entry in hosts.values():
        entry["findings"] = list(entry["findings"].values())
    return hosts
