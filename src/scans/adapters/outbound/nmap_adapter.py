import os
import re
import shutil
import tempfile
import ipaddress
import logging
from lxml import etree
from typing import Callable, List, Dict, Optional
from src.scans.adapters.outbound.base_adapter import BaseScannerAdapter, ScanError
from src.vulnerabilities.domain import severity as sev
from src.vulnerabilities.domain.models import VulnSeverity

logger = logging.getLogger(__name__)

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_PORT_TOKEN = re.compile(r"^\d{1,5}(-\d{1,5})?$")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_VULNERS_LINE = re.compile(r"\b(CVE-\d{4}-\d{4,})\b(?:\s+(\d{1,2}(?:\.\d)?))?")
_RISK_FACTOR = re.compile(r"Risk factor:\s*(\w+)", re.IGNORECASE)
_NOT_VULNERABLE = ("NOT VULNERABLE", "State: NOT VULNERABLE")
# Outputs of 'vuln' scripts that tested and found nothing (real Nmap outputs)
_NOTHING_FOUND = re.compile(r"Couldn't find|Could not find|\bNo\b[\w\s-]{0,40}\bfound\b|\bnot vulnerable\b", re.IGNORECASE)
_POSSIBLE = re.compile(r"Found the following (possible|potential)\s+([^:\n]+)", re.IGNORECASE)
# Informational scripts: their data is already stored with the ports/services, not a vulnerability
_INFORMATIONAL_SCRIPTS = {"http-server-header", "http-title", "fingerprint-strings"}

# Timing profiles. "lan" keeps the historical aggressive settings for internal networks;
# "internet" is slower but does not lose ports on high latency links or behind rate limiting WAF/CDN.
PROFILES = {
    "lan": {"timing": "-T4", "max_retries": "2", "host_timeout": "30m"},
    "internet": {"timing": "-T3", "max_retries": "4", "host_timeout": "180m"},
}

# The whole 'vuln' category is run so that web vulnerabilities are actually tested (team choice in
# 5bae702), except scripts that are also in the 'dos' category: they can crash the scanned service.
# vulscan was removed from the default set: it matches on product names only and produced hundreds
# of false positives per host.
DEFAULT_VULN_SCRIPTS = "(vuln and not dos),vulners"

# Phase 1 + phase 2 must fit in the Celery soft time limit (23 h) of a scan task
PHASE1_TIMEOUT_S = 8 * 3600
PHASE2_TIMEOUT_S = 12 * 3600


def _validate_targets(raw: str) -> List[str]:
    out = []
    for t in (x.strip() for x in raw.split(",")):
        if not t or t.startswith("-"):
            raise ValueError(f"Invalid target: {t!r}")
        try:
            ipaddress.ip_network(t, strict=False)      # IP or CIDR
        except ValueError:
            if not _HOST_RE.match(t):                  # hostname
                raise ValueError(f"Invalid target: {t!r}")
        out.append(t)
    return out


def _is_ipv6(targets: List[str]) -> bool:
    for t in targets:
        try:
            if ipaddress.ip_network(t, strict=False).version == 6:
                return True
        except ValueError:
            pass
    return False


def _build_port_args(ports: Optional[str]) -> List[str]:
    if not ports:
        return ["-p-"]
    tokens = [t.strip() for t in ports.split(",") if t.strip()]
    inc = [t for t in tokens if not t.startswith("!")]
    exc = [t[1:] for t in tokens if t.startswith("!")]
    for t in inc + exc:
        if not _PORT_TOKEN.match(t):
            raise ValueError(f"Invalid port spec: {t!r}")
    args = ["-p", ",".join(inc)] if inc else ["-p-"]
    if exc:
        args += ["--exclude-ports", ",".join(exc)]
    return args


# Nmap reports a percentage per phase ("SYN Stealth Scan Timing: About 42.10% done"): each phase
# is given its share of the whole run, in the order Nmap runs them.
_NMAP_STATS = re.compile(r"^([A-Za-z][A-Za-z /-]*?) Timing: About ([0-9.]+)% done", re.MULTILINE)
_NMAP_PHASES = [  # (words of the phase name, start, end) as fractions of the whole run
    (("ping", "arp", "dns"), 0.00, 0.05),
    (("syn", "connect", "udp", "ack", "window", "fin", "null", "xmas"), 0.05, 0.50),
    (("service",), 0.50, 0.75),
    (("os",), 0.75, 0.80),
    (("nse", "script"), 0.80, 1.00),
]


def nmap_fraction(output: str) -> Optional[float]:
    """Progress of the whole Nmap run (0 to 1) from its latest statistics line, None if none yet."""
    matches = _NMAP_STATS.findall(output or "")
    if not matches:
        return None
    phase, percent = matches[-1]
    words = phase.lower().split()
    for keys, start, end in _NMAP_PHASES:
        if any(k in words for k in keys):
            return start + (end - start) * min(float(percent), 100.0) / 100
    return None


def _report_nmap_progress(output: str, on_progress: Callable[[float], None]) -> None:
    fraction = nmap_fraction(output)
    if fraction is not None:
        on_progress(fraction)


def _profile_args(profile: str) -> List[str]:
    p = PROFILES.get(profile, PROFILES["lan"])
    return [p["timing"], "--max-retries", p["max_retries"], "--host-timeout", p["host_timeout"]]


class NmapAdapter(BaseScannerAdapter):
    @staticmethod
    def _build_nmap_auth_args(credentials: Optional[Dict] = None, workdir: Optional[str] = None) -> List[str]:
        if not credentials or not workdir:
            return []

        args = []
        c_type = (credentials.get("credential_type") or "").upper()
        user = credentials.get("username", "")
        pwd = credentials.get("password", "")
        domain = credentials.get("domain", "")

        if c_type == "SMB" and user:
            args.append(f"smbusername={user}")
            if pwd: args.append(f"smbpassword={pwd}")
            if domain: args.append(f"smbdomain={domain}")
        elif c_type == "SSH" and user:
            args.append(f"ssh.username={user}")
            if pwd: args.append(f"ssh.password={pwd}")
        elif c_type in ("HTTP", "HTTP_BASIC") and user:
            args.append(f"http.user={user}")
            if pwd: args.append(f"http.password={pwd}")
        elif c_type == "DATABASE" and user:
            args.append(f"mysqluser={user}")
            if pwd: args.append(f"mysqlpass={pwd}")

        if args:
            args_file_path = os.path.join(workdir, "script_args.txt")
            with open(args_file_path, "w") as f:
                f.write(",".join(args))
            os.chmod(args_file_path, 0o600)
            logger.info(f"Nmap: authenticated scan enabled ({c_type})")
            return ["--script-args-file", args_file_path]
        logger.warning(f"Nmap: credential of type {c_type or 'UNKNOWN'} not usable by Nmap, scan runs unauthenticated")
        return []

    @staticmethod
    def _run(cmd_head: List[str], target: str, timeout: int, credentials: Optional[Dict] = None,
             on_progress: Optional[Callable[[float], None]] = None) -> List[Dict]:
        workdir = tempfile.mkdtemp(prefix="nmap_")
        out_xml = os.path.join(workdir, "output.xml")
        err_file = os.path.join(workdir, "stderr.log")
        try:
            targets = _validate_targets(target)
            cmd = list(cmd_head)
            if _is_ipv6(targets):
                cmd.append("-6")
            cmd.extend(NmapAdapter._build_nmap_auth_args(credentials, workdir))
            if on_progress:
                # Nmap prints "<phase> Timing: About 42.10% done" every 5 s
                cmd.extend(["--stats-every", "5s"])
            cmd.extend(["-oX", out_xml, "--", *targets])
            logger.info(f"Executing Nmap command: {' '.join(c for c in cmd if not c.startswith(workdir))}")

            env = os.environ.copy()
            env["NMAP_PRIVILEGED"] = "1"
            returncode, stderr = NmapAdapter.run_process(
                cmd, timeout, err_file, env,
                on_output=(lambda text: _report_nmap_progress(text, on_progress)) if on_progress else None)
            if returncode != 0:
                raise ScanError(f"Nmap failed with code {returncode}: {stderr}")
            with open(out_xml, "r", encoding="utf-8") as f:
                return NmapAdapter._parse_nmap_xml(f.read())
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def run_discovery_scan(target: str, profile: str = "lan") -> List[Dict]:
        """Host discovery. TCP SYN/ACK probes complement ICMP so hosts that drop ping are still found."""
        logger.info(f"Running Nmap discovery scan on {target}")
        cmd = ["nmap", "-sn", "-PE", "-PS21,22,25,80,443,445,3389,8080", "-PA80,443", *_profile_args(profile)]
        return NmapAdapter._run(cmd, target, 3600)

    @staticmethod
    def run_detailed_discovery_scan(target: str, ports: Optional[str] = None, credentials: Optional[Dict] = None,
                                    profile: str = "lan", on_progress: Optional[Callable[[float], None]] = None) -> List[Dict]:
        logger.info(f"Running Nmap detailed discovery on {target} (profile={profile})")
        cmd = ["nmap", "-sS", "-sV", "-O", "-Pn", *_profile_args(profile), *_build_port_args(ports),
               "--script", "nbstat,smb-os-discovery"]
        return NmapAdapter._run(cmd, target, PHASE1_TIMEOUT_S, credentials, on_progress)

    @staticmethod
    def run_vulnerability_scan(target: str, ports: Optional[str] = None, credentials: Optional[Dict] = None,
                               profile: str = "lan", scripts: str = DEFAULT_VULN_SCRIPTS,
                               on_progress: Optional[Callable[[float], None]] = None) -> List[Dict]:
        logger.info(f"Running Nmap vulnerability scan on {target} (profile={profile})")
        cmd = ["nmap", "-sS", "-sV", "-Pn", *_profile_args(profile), *_build_port_args(ports), "--script", scripts]
        return NmapAdapter._run(cmd, target, PHASE2_TIMEOUT_S, credentials, on_progress)

    # ------------------------------------------------------------------ parsing

    @staticmethod
    def _parse_vulnerable_blocks(script_id: str, output: str, port: Optional[int], service: Optional[str]) -> List[Dict]:
        """Parse the standard NSE 'vulns' library output (State: VULNERABLE blocks)."""
        findings = []
        blocks = re.split(r"(?m)^\s*VULNERABLE:\s*$", output)
        for block in blocks[1:]:
            if any(marker in block for marker in _NOT_VULNERABLE):
                continue
            lines = [l.strip() for l in block.strip().splitlines() if l.strip()]
            title = lines[0] if lines else f"Nmap {script_id}"
            cves = sorted({c.upper() for c in _CVE_RE.findall(block)})
            risk = _RISK_FACTOR.search(block)
            severity = sev.resolve(risk.group(1) if risk else None, None, default=VulnSeverity.MEDIUM)
            findings.append({
                "rule_id": f"nmap:{script_id}",
                "title": f"{title[:200]} ({script_id})",
                "severity": severity.value,
                "cvss": None,
                "cve_id": cves[0] if cves else None,
                "cve_ids": cves,
                "description": f"Script Nmap {script_id} :\nVULNERABLE:\n{block.strip()}",
                "remediation": "",
                "port": port,
                "service": service,
                "evidence": [],
            })
        return findings

    @staticmethod
    def _parse_vulners(output: str, port: Optional[int], service: Optional[str], product_label: str) -> List[Dict]:
        findings = {}
        for line in output.splitlines():
            m = _VULNERS_LINE.search(line)
            if not m:
                continue
            cve_id = m.group(1).upper()
            cvss = sev.to_cvss(m.group(2))
            exploit = "*EXPLOIT*" in line
            previous = findings.get(cve_id)
            if previous and (previous["cvss"] or 0) >= (cvss or 0) and not exploit:
                continue
            desc = (f"{cve_id} détecté par correspondance de version sur {product_label} (port {port}).\n"
                    f"Score CVSS : {cvss if cvss is not None else 'inconnu'}\n"
                    f"Référence : https://vulners.com/cve/{cve_id}")
            if exploit or (previous and previous.get("exploit")):
                desc += "\nUn exploit public est référencé pour cette vulnérabilité."
            findings[cve_id] = {
                "rule_id": f"nmap:vulners:{cve_id}",
                "title": f"{cve_id} – {product_label}",
                "severity": sev.resolve(None, cvss, default=VulnSeverity.MEDIUM).value,
                "cvss": cvss,
                "cve_id": cve_id,
                "cve_ids": [cve_id],
                "description": desc,
                "remediation": f"Mettre à jour {product_label} vers une version corrigée.",
                "port": port,
                "service": service,
                "evidence": [line.strip()],
                "exploit": exploit or bool(previous and previous.get("exploit")),
            }
        return list(findings.values())

    @staticmethod
    def _parse_script(script_id: str, output: str, port: Optional[int], service: Optional[str], product_label: str) -> List[Dict]:
        if not output or len(output.strip()) < 5 or "ERROR:" in output:
            if output and "ERROR:" in output:
                logger.warning(f"Nmap script {script_id} failed on port {port}: {output.strip()[:300]}")
            return []
        if script_id == "vulners":
            return NmapAdapter._parse_vulners(output, port, service, product_label)
        if script_id == "vulscan" or script_id in _INFORMATIONAL_SCRIPTS:
            return []
        if re.search(r"(?m)^\s*VULNERABLE:\s*$", output):
            return NmapAdapter._parse_vulnerable_blocks(script_id, output, port, service)
        if any(marker in output for marker in _NOT_VULNERABLE):
            return []
        cves = sorted({c.upper() for c in _CVE_RE.findall(output)})
        possible = _POSSIBLE.search(output)
        if possible:
            # e.g. http-csrf "Found the following possible CSRF vulnerabilities": to be confirmed manually
            what = possible.group(2).strip().rstrip(".")
            return [{
                "rule_id": f"nmap:{script_id}",
                "title": f"Possible {what} ({script_id})",
                "severity": (VulnSeverity.MEDIUM if "xss" in script_id.lower() else VulnSeverity.LOW).value,
                "cvss": None,
                "cve_id": cves[0] if cves else None,
                "cve_ids": cves,
                "description": f"Script Nmap {script_id} (à confirmer manuellement) :\n{output.strip()}",
                "remediation": "",
                "port": port,
                "service": service,
                "evidence": [],
            }]
        if not cves and _NOTHING_FOUND.search(output):
            return []
        return [{
            "rule_id": f"nmap:{script_id}",
            "title": f"Résultat du script Nmap {script_id}",
            "severity": (VulnSeverity.MEDIUM if cves else VulnSeverity.INFO).value,
            "cvss": None,
            "cve_id": cves[0] if cves else None,
            "cve_ids": cves,
            "description": f"Script Nmap {script_id} :\n{output.strip()}",
            "remediation": "",
            "port": port,
            "service": service,
            "evidence": [],
        }]

    @staticmethod
    def _parse_nmap_xml(xml_output: str) -> List[Dict]:
        if not xml_output or not xml_output.strip():
            raise ScanError("Nmap generated empty output.")

        hosts_data = []
        try:
            parser = etree.XMLParser(resolve_entities=False, no_network=True)
            root = etree.fromstring(xml_output.encode('utf-8'), parser=parser)
        except Exception as e:
            raise ScanError(f"Failed to parse Nmap XML: {e}") from e

        runstats = root.find("runstats/finished")
        if runstats is not None and runstats.get("exit") != "success":
            logger.warning(f"Nmap XML indicates scan did not exit successfully: {runstats.get('errormsg')}")

        for host in root.xpath("//host"):
            try:
                status = host.find("status")
                state = status.get("state") if status is not None else "down"
                timed_out = host.get("timedout") == "true"

                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    addr_elem = host.find("address[@addrtype='ipv6']")
                ip = addr_elem.get("addr") if addr_elem is not None else None
                mac_elem = host.find("address[@addrtype='mac']")
                mac_address = mac_elem.get("addr") if mac_elem is not None else None
                if not ip:
                    continue

                user_hostname = host.find("hostnames/hostname[@type='user']")
                hostname_elem = user_hostname if user_hostname is not None else host.find("hostnames/hostname")
                hostname = hostname_elem.get("name") if hostname_elem is not None else None

                os_match = host.find("os/osmatch")
                os_name = os_match.get("name") if os_match is not None else "Unknown"
                os_accuracy = os_match.get("accuracy") if os_match is not None else "0"

                parsed_ports = []
                vulns = []
                for port in host.xpath("ports/port"):
                    port_id = port.get("portid")
                    port_num = int(port_id) if port_id and port_id.isdigit() else None
                    state_elem = port.find("state")
                    service = port.find("service")
                    get = (lambda k, d=None: service.get(k, d)) if service is not None else (lambda k, d=None: d)
                    conf = get("conf", "0")
                    entry = {
                        "port": port_num if port_num is not None else port_id,
                        "protocol": port.get("protocol"),
                        "state": state_elem.get("state") if state_elem is not None else "unknown",
                        "reason": state_elem.get("reason") if state_elem is not None else "unknown",
                        "service": get("name", "unknown"),
                        "product": get("product"),
                        "version": get("version"),
                        "extrainfo": get("extrainfo"),
                        "tunnel": get("tunnel"),
                        "method": get("method", "unknown"),
                        "confidence": int(conf) if conf.isdigit() else 0,
                        "cpe": [c.text for c in service.findall("cpe")] if service is not None else [],
                    }
                    parsed_ports.append(entry)

                    product_label = " ".join(x for x in (entry["product"], entry["version"]) if x) or entry["service"]
                    service_label = f"{'ssl/' if entry['tunnel'] == 'ssl' else ''}{entry['service']}"
                    for script in port.xpath("script"):
                        vulns.extend(NmapAdapter._parse_script(script.get("id"), script.get("output", ""),
                                                               port_num, service_label, product_label))

                for script in host.xpath("hostscript/script"):
                    script_id = script.get("id")
                    output_text = script.get("output", "")
                    if script_id in ("smb-os-discovery", "nbstat"):
                        if not hostname:
                            m = re.search(r"(?i)(?:Computer name|NetBIOS computer name|NetBIOS name):\s*([^\r\n,\\]+)", output_text)
                            if m:
                                hostname = m.group(1).strip()
                        continue
                    vulns.extend(NmapAdapter._parse_script(script_id, output_text, None, None, "hôte"))

                if state != "up" and not any(p["state"] == "open" for p in parsed_ports) and not timed_out:
                    continue

                unique = {}
                for v in vulns:
                    unique[(v["rule_id"], v["port"])] = v

                hosts_data.append({
                    "ip": ip,
                    "hostname": hostname,
                    "mac_address": mac_address,
                    "os": os_name,
                    "os_accuracy": int(os_accuracy) if os_accuracy.isdigit() else 0,
                    "ports": parsed_ports,
                    "services": parsed_ports,
                    "timed_out": timed_out,
                    "vulns": list(unique.values()),
                })
            except Exception as ex:
                logger.error(f"Error parsing Nmap host: {ex}")
                continue

        logger.debug(f"Nmap successfully parsed {len(hosts_data)} hosts.")
        return hosts_data
