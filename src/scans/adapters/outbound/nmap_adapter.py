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
            result = subprocess.run(["nmap", "-sn", "-oX", "-", target], capture_output=True, text=True, check=True)
            return NmapAdapter._parse_nmap_xml(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"Nmap discovery failed: {e.stderr}")
            raise Exception(f"Nmap discovery failed: {e.stderr}")

    @staticmethod
    def run_vulnerability_scan(target: str) -> List[Dict]:
        """Runs an Nmap deep scan (ports, OS, versions) and returns structured data."""
        logger.info(f"Running Nmap deep scan on {target}")
        
        try:
            # -sT: TCP Connect scan (works better in Docker/Windows than SYN scan -sS)
            # -sV: Version detection
            # -Pn: Disable ping (fixes Docker NAT dropping ICMP)
            # -oX -: Output XML to stdout
            result = subprocess.run(["nmap", "-sT", "-sV", "-Pn", "--script", "vuln", "-oX", "-", target], capture_output=True, text=True, check=True)
            return NmapAdapter._parse_nmap_xml(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"Nmap deep scan failed: {e.stderr}")
            raise Exception(f"Nmap deep scan failed: {e.stderr}")

    @staticmethod
    def _parse_nmap_xml(xml_output: str) -> List[Dict]:
        """Parses Nmap XML output and returns a list of dictionaries with host data."""
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
                
                if not ip:
                    continue
                
                hostname_elem = host.find("hostnames/hostname")
                hostname = hostname_elem.get("name") if hostname_elem is not None else None
                
                # OS Detection
                os_match = host.find("os/osmatch")
                os_name = os_match.get("name") if os_match is not None else "Unknown"
                
                # Ports
                open_ports = []
                for port in host.xpath("ports/port"):
                    state_elem = port.find("state")
                    if state_elem is not None and state_elem.get("state") == "open":
                        port_id = port.get("portid")
                        protocol = port.get("protocol")
                        service = port.find("service")
                        service_name = service.get("name") if service is not None else "unknown"
                        open_ports.append(f"{port_id}/{protocol} ({service_name})")
                
                # Nmap NSE Vulnerabilities (if run with --script vuln)
                vulns = []
                for script in host.xpath("hostscript/script") + host.xpath("ports/port/script"):
                    vulns.append({
                        "id": script.get("id"),
                        "output": script.get("output")
                    })
                    
                hosts_data.append({
                    "ip": ip,
                    "hostname": hostname or f"Discovered Host ({ip})",
                    "os": os_name,
                    "ports": ", ".join(open_ports) if open_ports else None,
                    "vulns": vulns
                })
                
        except Exception as e:
            logger.error(f"Failed to parse Nmap XML: {str(e)}")
            
        return hosts_data
