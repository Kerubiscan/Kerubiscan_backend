import os
import re
import shutil
import tempfile
import ipaddress
import logging
from lxml import etree
from typing import List, Dict, Optional, Union
from src.scans.adapters.outbound.base_adapter import BaseScannerAdapter, ScanError

logger = logging.getLogger(__name__)

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_PORT_TOKEN = re.compile(r"^\d{1,5}(-\d{1,5})?$")

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

def _to_cvss(s) -> Optional[float]:
    try:
        v = float(s)
    except (TypeError, ValueError):
        return None
    return v if 0.0 <= v <= 10.0 else None

class NmapAdapter(BaseScannerAdapter):
    @staticmethod
    def _build_nmap_auth_args(credentials: Optional[Dict] = None, workdir: Optional[str] = None) -> List[str]:
        if not credentials or not workdir:
            return []
        
        args = []
        c_type = credentials.get("credential_type")
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
        elif c_type == "HTTP" and user:
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
            return ["--script-args-file", args_file_path]
        return []

    @staticmethod
    def run_discovery_scan(target: str) -> List[Dict]:
        """Runs an Nmap ping sweep."""
        logger.info(f"Running Nmap discovery scan on {target}")
        
        workdir = tempfile.mkdtemp(prefix="nmap_")
        out_xml = os.path.join(workdir, "output.xml")
        err_file = os.path.join(workdir, "stderr.log")
        
        try:
            cmd = ["nmap", "-sn", "-oX", out_xml, "--", *_validate_targets(target)]
            env = os.environ.copy()
            env["NMAP_PRIVILEGED"] = "1"
            
            returncode, stderr = NmapAdapter.run_process(cmd, 300, err_file, env)
            if returncode != 0:
                raise ScanError(f"Nmap discovery failed with code {returncode}: {stderr}")
            
            with open(out_xml, "r", encoding="utf-8") as f:
                return NmapAdapter._parse_nmap_xml(f.read())
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def run_detailed_discovery_scan(target: str, ports: Optional[str] = None, credentials: Optional[Dict] = None) -> List[Dict]:
        logger.info(f"Running Nmap detailed discovery on {target}")
        
        workdir = tempfile.mkdtemp(prefix="nmap_")
        out_xml = os.path.join(workdir, "output.xml")
        err_file = os.path.join(workdir, "stderr.log")
        
        try:
            cmd = ["nmap", "-sS", "-sV", "-O", "-Pn", "--max-retries", "2", "--host-timeout", "30m"]
            cmd.extend(_build_port_args(ports))
            cmd.extend(["-T4", "--script", "nbstat,smb-os-discovery"])
            cmd.extend(NmapAdapter._build_nmap_auth_args(credentials, workdir))
            cmd.extend(["-oX", out_xml, "--", *_validate_targets(target)])
            
            env = os.environ.copy()
            env["NMAP_PRIVILEGED"] = "1"
            
            returncode, stderr = NmapAdapter.run_process(cmd, 86400, err_file, env)
            if returncode != 0:
                raise ScanError(f"Nmap detailed scan failed with code {returncode}: {stderr}")
            
            with open(out_xml, "r", encoding="utf-8") as f:
                return NmapAdapter._parse_nmap_xml(f.read())
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def run_vulnerability_scan(target: str, ports: Optional[str] = None, credentials: Optional[Dict] = None) -> List[Dict]:
        logger.info(f"Running Nmap vulnerability scan on {target}")
        
        workdir = tempfile.mkdtemp(prefix="nmap_")
        out_xml = os.path.join(workdir, "output.xml")
        err_file = os.path.join(workdir, "stderr.log")
        
        try:
            cmd = ["nmap", "-sS", "-sV", "-Pn", "--max-retries", "2", "--host-timeout", "30m"]
            cmd.extend(_build_port_args(ports))
            # Use 'vuln' category fully to ensure web vulnerabilities are actually tested
            cmd.extend(["--script", "vuln,vulners,vulscan"])
            cmd.extend(NmapAdapter._build_nmap_auth_args(credentials, workdir))
            cmd.extend(["-oX", out_xml, "--", *_validate_targets(target)])
            
            logger.info(f"Executing Nmap command: {' '.join(cmd)}")
            
            env = os.environ.copy()
            env["NMAP_PRIVILEGED"] = "1"
            
            returncode, stderr = NmapAdapter.run_process(cmd, 86400, err_file, env)
            if returncode != 0:
                raise ScanError(f"Nmap vulnerability scan failed with code {returncode}: {stderr}")
            
            with open(out_xml, "r", encoding="utf-8") as f:
                return NmapAdapter._parse_nmap_xml(f.read())
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def _parse_nmap_xml(xml_output: str) -> List[Dict]:
        if not xml_output or not xml_output.strip():
            raise ScanError("Nmap generated empty output.")
            
        hosts_data = []
        try:
            parser = etree.XMLParser(resolve_entities=False, no_network=True)
            root = etree.fromstring(xml_output.encode('utf-8'), parser=parser)
            
            # Check exit success
            runstats = root.find("runstats/finished")
            if runstats is not None and runstats.get("exit") != "success":
                logger.warning(f"Nmap XML indicates scan did not exit successfully: {runstats.get('errormsg')}")
                
            for host in root.xpath("//host"):
                try:
                    status = host.find("status")
                    state = status.get("state") if status is not None else "down"
                    reason = status.get("reason") if status is not None else "unknown"
                    
                    addr_elem = host.find("address[@addrtype='ipv4']")
                    if addr_elem is None:
                        addr_elem = host.find("address")
                    ip = addr_elem.get("addr") if addr_elem is not None else None
                    
                    mac_elem = host.find("address[@addrtype='mac']")
                    mac_address = mac_elem.get("addr") if mac_elem is not None else None
                    
                    if not ip:
                        continue
                    
                    hostname_elem = host.find("hostnames/hostname")
                    hostname = hostname_elem.get("name") if hostname_elem is not None else None
                    
                    # OS Detection
                    os_match = host.find("os/osmatch")
                    os_name = os_match.get("name") if os_match is not None else "Unknown"
                    os_accuracy = os_match.get("accuracy") if os_match is not None else "0"
                    
                    parsed_ports = []
                    
                    for port in host.xpath("ports/port"):
                        port_id = port.get("portid")
                        protocol = port.get("protocol")
                        
                        state_elem = port.find("state")
                        port_state = state_elem.get("state") if state_elem is not None else "unknown"
                        port_reason = state_elem.get("reason") if state_elem is not None else "unknown"
                        
                        service = port.find("service")
                        service_name = service.get("name") if service is not None else "unknown"
                        
                        product = service.get("product") if service is not None else None
                        version = service.get("version") if service is not None else None
                        extrainfo = service.get("extrainfo") if service is not None else None
                        tunnel = service.get("tunnel") if service is not None else None
                        method = service.get("method") if service is not None else "unknown"
                        conf = service.get("conf") if service is not None else "0"
                        
                        cpes = [cpe.text for cpe in service.findall("cpe")] if service is not None else []
                        
                        parsed_ports.append({
                            "port": int(port_id) if port_id and port_id.isdigit() else port_id,
                            "protocol": protocol,
                            "state": port_state,
                            "reason": port_reason,
                            "service": service_name,
                            "product": product,
                            "version": version,
                            "extrainfo": extrainfo,
                            "tunnel": tunnel,
                            "method": method,
                            "confidence": int(conf) if conf.isdigit() else 0,
                            "cpe": cpes
                        })
                    
                    # If host is up, or if it has open ports despite being down
                    if state != "up" and not any(p["state"] == "open" for p in parsed_ports):
                        continue

                    vulns = []
                    
                    # Parse Host scripts
                    for script in host.xpath("hostscript/script"):
                        script_id = script.get("id")
                        output_text = script.get("output", "")
                        
                        if "ERROR:" in output_text:
                            logger.warning(f"Host script {script_id} failed: {output_text}")
                            continue
                        
                        if script_id in ("smb-os-discovery", "nbstat"):
                            if not hostname or hostname.startswith("Discovered Host"):
                                m = re.search(r"(?i)(?:Computer name|NetBIOS computer name|NetBIOS name):\s*([^\r\n,\\]+)", output_text)
                                if m: hostname = m.group(1).strip()
                            continue
                            
                        cve_matches = re.findall(r"(CVE-\d{4}-\d{4,})\s*([\d.]*)", output_text)
                        if cve_matches:
                            unique_cves = {}
                            for cve_id, cvss_str in cve_matches:
                                val = _to_cvss(cvss_str) or 0.0
                                unique_cves[cve_id] = max(unique_cves.get(cve_id, 0.0), val)
                                
                            for cve_id, cvss_val in unique_cves.items():
                                vulns.append({
                                    "id": f"nmap-host-{cve_id.lower()}",
                                    "cve_id": cve_id,
                                    "cvss_score": cvss_val if cvss_val > 0 else None,
                                    "name": f"Host Vuln {cve_id}",
                                    "description": f"Script {script_id}:\n{output_text}",
                                    "severity": "high" if cvss_val > 7.0 else "medium"
                                })
                        else:
                            vulns.append({
                                "id": f"nmap-host-{script_id}",
                                "name": f"Host Script {script_id}",
                                "description": output_text,
                                "severity": "info"
                            })

                    # Parse Port scripts
                    for port_elem in host.xpath("ports/port"):
                        port_num = port_elem.get("portid")
                        for script in port_elem.xpath("script"):
                            script_id = script.get("id")
                            output_text = script.get("output", "")
                            
                            if "ERROR:" in output_text:
                                logger.warning(f"Port script {script_id} failed on port {port_num}: {output_text}")
                                continue
                                
                            if len(output_text.strip()) < 5: 
                                continue
                                
                            if script_id in ["vulners", "vulscan"]:
                                for line in output_text.splitlines():
                                    line = line.strip()
                                    if not line or line.startswith("cpe:/"): continue
                                    
                                    cve_match = re.search(r"\b(CVE-\d{4}-\d{4,})\b(?:[ \t]+(\d{1,2}\.\d))?", line)
                                    if cve_match:
                                        cve_id = cve_match.group(1)
                                        cvss_str = cve_match.group(2)
                                        cvss_val = _to_cvss(cvss_str)
                                        vulns.append({
                                            "id": f"nmap-{port_num}-{cve_id.lower()}",
                                            "cve_id": cve_id,
                                            "cvss_score": cvss_val,
                                            "name": f"Port {port_num} Vuln {cve_id}",
                                            "description": line,
                                            "severity": "high" if (cvss_val and cvss_val > 7.0) else "medium"
                                        })
                                    elif script_id == "vulscan":
                                        vscan_match = re.search(r"\[([^\]]+)\]\s*(.*)", line)
                                        if vscan_match:
                                            v_id = vscan_match.group(1)
                                            v_desc = vscan_match.group(2)
                                            vulns.append({
                                                "id": f"nmap-{port_num}-vulscan-{v_id}",
                                                "name": f"Vulscan {v_id} on Port {port_num}",
                                                "description": line,
                                                "severity": "medium"
                                            })
                            else:
                                cve_matches = re.findall(r"(CVE-\d{4}-\d{4,})\s*([\d.]*)", output_text)
                                if cve_matches:
                                    unique_cves = {}
                                    for cve_id, cvss_str in cve_matches:
                                        val = _to_cvss(cvss_str) or 0.0
                                        unique_cves[cve_id] = max(unique_cves.get(cve_id, 0.0), val)
                                        
                                    for cve_id, cvss_val in unique_cves.items():
                                        vulns.append({
                                            "id": f"nmap-{port_num}-{script_id}-{cve_id.lower()}",
                                            "cve_id": cve_id,
                                            "cvss_score": cvss_val if cvss_val > 0 else None,
                                            "name": f"Port {port_num} Vuln {cve_id}",
                                            "description": f"Script {script_id}:\n{output_text}",
                                            "severity": "high" if cvss_val > 7.0 else "medium"
                                        })
                                else:
                                    vulns.append({
                                        "id": f"nmap-{port_num}-{script_id}",
                                        "name": f"Script {script_id} on Port {port_num}",
                                        "description": output_text,
                                        "severity": "info"
                                    })
                        
                    # De-duplicate vulns based on ID
                    unique_vulns = {v["id"]: v for v in vulns}.values()
                    
                    hosts_data.append({
                        "ip": ip,
                        "hostname": hostname,
                        "mac_address": mac_address,
                        "os": os_name,
                        "os_accuracy": int(os_accuracy) if os_accuracy.isdigit() else 0,
                        "ports": parsed_ports,
                        "services": parsed_ports,
                        "vulns": list(unique_vulns)
                    })
                except Exception as ex:
                    logger.error(f"Error parsing Nmap host: {ex}")
                    continue
                    
        except Exception as e:
            raise ScanError(f"Failed to parse Nmap XML: {e}") from e
            
        logger.debug(f"Nmap successfully parsed {len(hosts_data)} hosts.")
        return hosts_data
