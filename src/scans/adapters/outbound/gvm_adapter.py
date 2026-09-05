from typing import List
from gvm.connections import TLSConnection, UnixSocketConnection
from gvm.protocols.gmpv225 import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from gvm.errors import GvmError
import logging

from src.scans.ports.outbound.scan_engine import ScanEnginePort

logger = logging.getLogger(__name__)

class GVMAdapter(ScanEnginePort):
    def __init__(self, host: str = "localhost", port: int = 9390, user: str = "admin", password: str = "admin", socket_path: str = "/run/gvmd/gvmd.sock"):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.socket_path = socket_path
        self.connection = None
        self.gmp = None

    def connect(self) -> bool:
        try:
            import os
            transform = EtreeCheckCommandTransform()
            if os.path.exists(self.socket_path):
                self.connection = UnixSocketConnection(path=self.socket_path)
            else:
                self.connection = TLSConnection(hostname=self.host, port=self.port)
            self.gmp = Gmp(connection=self.connection, transform=transform)
            self.gmp.connect()
            # Authenticate
            self.gmp.authenticate(self.user, self.password)
            return True
        except Exception as e:
            logger.error(f"Failed to connect to GVM: {str(e)}")
            return False

    def disconnect(self) -> None:
        if self.gmp:
            try:
                self.gmp.disconnect()
            except Exception:
                pass

    def create_target(self, name: str, hosts: List[str], port_list_id: str = "", port_range: str = "T:1-65535,U:1-65535") -> str:
        if not self.gmp:
            raise Exception("Not connected to GVM")
            
        try:
            # Join list of hosts into a comma-separated string
            hosts_str = ",".join(hosts)
            
            from gvm.protocols.gmpv225 import AliveTest
            kwargs = {"name": name, "hosts": [hosts_str], "alive_test": AliveTest.CONSIDER_ALIVE}
            if port_list_id:
                kwargs["port_list_id"] = port_list_id
            else:
                kwargs["port_range"] = port_range
                
            response = self.gmp.create_target(**kwargs)
            return response.get("id")
        except GvmError as e:
            logger.error(f"Failed to create target: {str(e)}")
            raise

    def create_task(self, name: str, target_id: str, scanner_id: str, config_id: str) -> str:
        if not self.gmp:
            raise Exception("Not connected to GVM")
            
        try:
            response = self.gmp.create_task(
                name=name,
                target_id=target_id,
                scanner_id=scanner_id,
                config_id=config_id
            )
            return response.get("id")
        except GvmError as e:
            logger.error(f"Failed to create task: {str(e)}")
            raise

    def start_task(self, task_id: str) -> str:
        if not self.gmp:
            raise Exception("Not connected to GVM")
            
        try:
            response = self.gmp.start_task(task_id=task_id)
            # The report_id is usually returned when starting a task
            report_id = response.xpath("//report_id/text()")[0]
            return report_id
        except GvmError as e:
            logger.error(f"Failed to start task: {str(e)}")
            raise

    def get_task_status_and_progress(self, task_id: str) -> tuple[str, int]:
        if not self.gmp:
            raise Exception("Not connected to GVM")
            
        try:
            response = self.gmp.get_task(task_id=task_id)
            status = response.xpath("//status/text()")[0]
            progress_nodes = response.xpath("//progress/text()")
            progress = 0
            if progress_nodes:
                try:
                    progress = int(progress_nodes[0])
                except ValueError:
                    pass
            return status, progress
        except GvmError as e:
            logger.error(f"Failed to get task status: {str(e)}")
            raise

    def get_task_status(self, task_id: str) -> str:
        status, _ = self.get_task_status_and_progress(task_id)
        return status

    def get_report(self, report_id: str) -> str:
        if not self.gmp:
            raise Exception("Not connected to GVM")
            
        try:
            # We want the raw XML to parse it later
            response = self.gmp.get_report(report_id=report_id, details=True, ignore_pagination=True)
            from lxml import etree
            return etree.tostring(response, encoding='unicode')
        except GvmError as e:
            logger.error(f"Failed to get report: {str(e)}")
            raise
