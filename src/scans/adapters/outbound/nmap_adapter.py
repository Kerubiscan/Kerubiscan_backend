import subprocess
import logging
from lxml import etree
from sqlalchemy.orm import Session
from typing import List, Dict

logger = logging.getLogger(__name__)

class NmapAdapter:
    @staticmethod
    def run_discovery_scan(target: str) -> List[Dict]:
        """Runs an Nmap ping sweep and returns a list of discovered hosts."""
        logger.info(f"Running Nmap discovery scan on {target}")
        
        try:
            # -sn: Ping Scan (disable port scan)
            # -oX -: Output XML to stdout
            result = subprocess.run(
                ["nmap", "-sn", "-oX", "-", target], 
                capture_output=True, text=True, check=True, timeout=300
            )
            logger.info(f"Nmap discovery scan raw output for {target}:\n{result.stdout}")
            return NmapAdapter._parse_nmap_xml(result.stdout)
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap discovery scan timed out for {target}")
            raise Exception(f"Nmap discovery timed out on {target}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Nmap discovery failed: {e.stderr}")
            raise Exception(f"Nmap discovery failed: {e.stderr}")

    @staticmethod
    def _build_nmap_auth_args(credentials: Dict = None) -> List[str]:
        if not credentials:
            return []
        
        args = []
        if credentials.get("credential_type") == "SMB":
            args.append(f"smbusername={credentials.get('username','')}")
            if credentials.get("password"):
                args.append(f"smbpassword={credentials.get('password','')}")
            if credentials.get("domain"):
                args.append(f"smbdomain={credentials.get('domain','')}")
        elif credentials.get("credential_type") == "SSH":
            args.append(f"ssh.username={credentials.get('username','')}")
            if credentials.get("password"):
                args.append(f"ssh.password={credentials.get('password','')}")
        elif credentials.get("credential_type") == "HTTP":
            args.append(f"http.user={credentials.get('username','')}")
            if credentials.get("password"):
                args.append(f"http.password={credentials.get('password','')}")
        elif credentials.get("credential_type") == "DATABASE":
            args.append(f"mysqluser={credentials.get('username','')}")
            if credentials.get("password"):
                args.append(f"mysqlpass={credentials.get('password','')}")
                
        if args:
            return ["--script-args", ",".join(args)]
        return []

    @staticmethod
    def run_detailed_discovery_scan(target: str, ports: str = None, credentials: Dict = None) -> List[Dict]:
        """Runs a detailed Nmap scan to get OS, hostnames, and ports without full vulnerability scripts.
           Falls back to -sV if -O fails (e.g. due to lack of root privileges)."""
        logger.info(f"Running Nmap detailed discovery scan on {target} with ports option: {ports}")
        
        try:
            cmd = ["nmap", "-sS", "-sV", "-O", "-Pn"]
            
            if ports:
                if "!" in ports:
                    p_parts = ports.split("!")
                    scan_p = p_parts[0].rstrip(",")
                    exclude_p = p_parts[1]
                    if scan_p:
                        cmd.extend(["-p", scan_p])
                    cmd.extend(["--exclude-ports", exclude_p])
                else:
                    cmd.extend(["-p", ports])
                
            cmd.extend(["-T4", "--script", "nbstat,smb-os-discovery"])
            cmd.extend(NmapAdapter._build_nmap_auth_args(credentials))
            cmd.extend(["-oX", "-"])
            
            result = subprocess.run(
                cmd + target.split(','), 
                capture_output=True, text=True, check=True, timeout=86400
            )
            logger.info(f"Nmap detailed scan raw output for {target}:\n{result.stdout}")
            return NmapAdapter._parse_nmap_xml(result.stdout)
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap detailed scan timed out for {target}")
            raise Exception(f"Nmap detailed scan timed out on {target}")
        except subprocess.CalledProcessError as e:
            if "requires root privileges" in e.stderr.lower() or "requires root" in e.stderr.lower() or "root" in e.stderr.lower() or "privilege" in e.stderr.lower():
                logger.warning(f"OS detection (-O) failed due to privileges. Falling back to -sV only for {target}")
                try:
                    result = subprocess.run(
                        ["nmap", "-sS", "-sV", "-Pn", "-T4", "--script", "nbstat,smb-os-discovery", "-oX", "-"] + target.split(','), 
                        capture_output=True, text=True, check=True, timeout=86400
                    )
                    logger.info(f"Nmap detailed scan (fallback) raw output for {target}:\n{result.stdout}")
                    return NmapAdapter._parse_nmap_xml(result.stdout)
                except subprocess.TimeoutExpired:
                    logger.error(f"Nmap fallback detailed scan timed out for {target}")
                    raise Exception(f"Nmap fallback detailed scan timed out on {target}")
                except subprocess.CalledProcessError as e2:
                    logger.error(f"Nmap fallback detailed scan failed: {e2.stderr}")
                    raise Exception(f"Nmap fallback detailed scan failed: {e2.stderr}")
            else:
                logger.error(f"Nmap detailed scan failed: {e.stderr}")
                raise Exception(f"Nmap detailed scan failed: {e.stderr}")

    @staticmethod
    def run_vulnerability_scan(target: str, ports: str = None, credentials: Dict = None) -> List[Dict]:
        """Runs an Nmap deep scan (ports, OS, versions) with optional custom port ranges / exclusions."""
        logger.info(f"Running Nmap deep scan on {target} with ports option: {ports}")
        
        try:
            cmd = ["nmap", "-sS", "-sV", "-Pn"]
            
            if ports:
                # Handle exclusion ranges if specified in format "1-65535,!7000" or "--exclude-ports 7000"
                if "!" in ports:
                    p_parts = ports.split("!")
                    scan_p = p_parts[0].rstrip(",")
                    exclude_p = p_parts[1]
                    if scan_p:
                        cmd.extend(["-p", scan_p])
                    cmd.extend(["--exclude-ports", exclude_p])
                else:
                    cmd.extend(["-p", ports])
            
            # vulscan removed due to excessive memory usage and frequent OOM crashes
            cmd.extend(["--script", "vuln,vulners"])
            cmd.extend(NmapAdapter._build_nmap_auth_args(credentials))
            cmd.extend(["-oX", "-", target])
            
            result = subprocess.run(
                cmd, 
                capture_output=True, text=True, check=True, timeout=86400, stdin=subprocess.DEVNULL
            )
            logger.info(f"Nmap vulnerability scan raw output for {target}:\n{result.stdout}")
            return NmapAdapter._parse_nmap_xml(result.stdout)
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap deep scan timed out for {target}")
            raise Exception(f"Nmap deep scan timed out on {target}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Nmap deep scan failed: {e.stderr}")
            raise Exception(f"Nmap deep scan failed: {e.stderr}")

    @staticmethod
    def _parse_nmap_xml(xml_output: str) -> List[Dict]:
        """Parses Nmap XML output and returns a list of dictionaries with host data."""
        if not xml_output or not xml_output.strip():
            logger.error("Nmap XML output is empty.")
            raise ValueError("Nmap generated empty output.")
            
        hosts_data = []
        try:
            root = etree.fromstring(xml_output.encode('utf-8'))
            for host in root.xpath("//host"):
                status = host.find("status")
                state = status.get("state") if status is not None else "down"
                if state != "up":
                    continue
                
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
                
                # Ports and Services
                open_ports = []
                running_services = []
                for port in host.xpath("ports/port"):
                    state_elem = port.find("state")
                    if state_elem is not None and state_elem.get("state") == "open":
                        port_id = port.get("portid")
                        protocol = port.get("protocol")
                        service = port.find("service")
                        service_name = service.get("name") if service is not None else "unknown"
                        open_ports.append(f"{port_id}/{protocol} ({service_name})")
                        
                        if service is not None:
                            product = service.get("product")
                            version = service.get("version")
                            extrainfo = service.get("extrainfo")
                            
                            svc_str = service_name
                            if product:
                                svc_str += f": {product}"
                            if version:
                                svc_str += f" {version}"
                            if extrainfo:
                                svc_str += f" ({extrainfo})"
                            
                            if product or version or extrainfo:
                                running_services.append(f"Port {port_id}/{protocol} - {svc_str}")
                
                # Nmap NSE Vulnerabilities (if run with --script vuln)
                vulns = []
                import re
                
                def parse_script_output(script_elem, port_id="host"):
                    s_id = script_elem.get("id")
                    s_out = script_elem.get("output", "")
                    if s_id in ("smb-os-discovery", "nbstat"): return None, None
                    
                    cves = re.findall(r"(CVE-\d{4}-\d+)(?:[^\d]+([\d.]+))?", s_out)
                    return s_id, s_out, cves
                    
                # Parse Host scripts
                for script in host.xpath("hostscript/script"):
                    script_id = script.get("id")
                    output_text = script.get("output", "")
                    
                    if script_id in ("smb-os-discovery", "nbstat"):
                        if not hostname or hostname.startswith("Discovered Host"):
                            m = re.search(r"(?i)(?:Computer name|NetBIOS computer name|NetBIOS name):\s*([^\r\n,\\]+)", output_text)
                            if m: hostname = m.group(1).strip()
                        continue
                        
                    cve_matches = re.findall(r"(CVE-\d{4}-\d+)\s*([\d.]*)", output_text)
                    if cve_matches:
                        unique_cves = {c[0]: c[1] for c in cve_matches}
                        for cve_id, cvss_str in unique_cves.items():
                            vulns.append({
                                "id": f"Nmap (Host): {cve_id}",
                                "cve_id": cve_id,
                                "cvss": float(cvss_str) if cvss_str else 0.0,
                                "output": f"Script {script_id}:\n{output_text}"
                            })
                    else:
                        vulns.append({
                            "id": f"Nmap (Host): {script_id}",
                            "output": output_text
                        })

                # Parse Port scripts
                for port_elem in host.xpath("ports/port"):
                    port_num = port_elem.get("portid")
                    for script in port_elem.xpath("script"):
                        script_id = script.get("id")
                        output_text = script.get("output", "")
                        
                        if "ERROR" in output_text or len(output_text.strip()) < 5: 
                            continue
                            
                        # Handle tabular/multi-finding scripts like vulners and vulscan line-by-line
                        if script_id in ["vulners", "vulscan"]:
                            for line in output_text.splitlines():
                                line = line.strip()
                                if not line or line.startswith("cpe:/"): continue
                                
                                cve_match = re.search(r"(CVE-\d{4}-\d+)\s*([\d.]*)", line)
                                if cve_match:
                                    cve_id = cve_match.group(1)
                                    cvss_str = cve_match.group(2)
                                    vulns.append({
                                        "id": f"Nmap ({port_num}): {cve_id}",
                                        "cve_id": cve_id,
                                        "cvss": float(cvss_str) if cvss_str else 0.0,
                                        "output": f"Port {port_num} ({script_id}): {line}"
                                    })
                                elif script_id == "vulscan":
                                    # Vulscan often outputs IDs in brackets like [12345] OpenSSH Security Bypass
                                    vscan_match = re.search(r"\[([^\]]+)\]\s*(.*)", line)
                                    if vscan_match:
                                        v_id = vscan_match.group(1)
                                        v_desc = vscan_match.group(2)
                                        vulns.append({
                                            "id": f"Nmap ({port_num}): vulscan-{v_id}",
                                            "output": f"Port {port_num} ({script_id}): {line}"
                                        })
                        else:
                            # Standard single-vulnerability scripts (e.g. ssl-poodle, http-vuln-*)
                            cve_matches = re.findall(r"(CVE-\d{4}-\d+)\s*([\d.]*)", output_text)
                            if cve_matches:
                                unique_cves = {c[0]: c[1] for c in cve_matches}
                                for cve_id, cvss_str in unique_cves.items():
                                    vulns.append({
                                        "id": f"Nmap ({port_num}): {cve_id}",
                                        "cve_id": cve_id,
                                        "cvss": float(cvss_str) if cvss_str else 0.0,
                                        "output": f"Script {script_id} on port {port_num}:\n{output_text}"
                                    })
                            else:
                                vulns.append({
                                    "id": f"Nmap ({port_num}): {script_id}",
                                    "output": f"Script {script_id} on port {port_num}:\n{output_text}"
                                })
                    
                hosts_data.append({
                    "ip": ip,
                    "hostname": hostname or f"Discovered Host ({ip})",
                    "mac_address": mac_address,
                    "os": os_name,
                    "ports": ", ".join(open_ports) if open_ports else None,
                    "services": "\n".join(running_services) if running_services else None,
                    "vulns": vulns
                })
                
        except Exception as e:
            logger.error(f"Failed to parse Nmap XML: {str(e)}")
            raise e
            
        import json
        logger.info(f"Nmap parsed result:\n{json.dumps(hosts_data, indent=2)}")
        return hosts_data
