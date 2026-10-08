from typing import List, Optional
from gvm.connections import TLSConnection, UnixSocketConnection
from gvm.protocols.gmpv225 import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from gvm.errors import GvmError
import logging

from src.scans.ports.outbound.scan_engine import ScanEnginePort

logger = logging.getLogger(__name__)

class GVMAdapter(ScanEnginePort):
    def __init__(self, host: str = None, port: int = 9390, user: str = "admin", password: str = "admin", socket_path: str = "/run/gvmd/gvmd.sock"):
        import os
        self.host = host or os.getenv("OPENVAS_HOST", "openvas")
        self.port = port
        self.user = os.getenv("OPENVAS_USER", user)
        self.password = os.getenv("OPENVAS_PASSWORD", password)
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

    def stop_task(self, task_id: str) -> bool:
        if not self.gmp:
            raise Exception("Not connected to GVM")
        try:
            self.gmp.stop_task(task_id=task_id)
            logger.info(f"OpenVAS task {task_id} stopped")
            return True
        except GvmError as e:
            logger.warning(f"Could not stop OpenVAS task {task_id}: {e}")
            return False

    def check_feeds(self) -> tuple:
        """(ok, detail). OpenVAS finds nothing without its NVT feed.

        Fail-OPEN by design: this check must never block scanning because of its own incompatibility
        with a given OpenVAS image. It returns False (block) only when it positively reads that the
        NVT feed is still syncing or is absent while other feeds are present. Any other situation
        (read error, unexpected structure, no feed returned) proceeds with a warning.
        """
        if not self.gmp:
            raise Exception("Not connected to GVM")
        try:
            response = self.gmp.get_feeds()
            feeds = {}
            for feed in response.xpath("//feed"):
                ftype = (feed.findtext("type") or "").upper()
                if ftype:
                    feeds[ftype] = {
                        "version": feed.findtext("version") or "",
                        "syncing": bool(feed.xpath("currently_syncing")),
                    }
        except Exception as e:
            logger.warning(f"Could not read OpenVAS feed status, proceeding anyway: {e}")
            return True, "état du feed indéterminé (vérification ignorée)"

        nvt = feeds.get("NVT")
        if nvt and nvt["syncing"]:
            return False, "Feed OpenVAS en cours de synchronisation : réessayez plus tard"
        if nvt and nvt["version"]:
            return True, f"Feed NVT {nvt['version']}"
        if feeds and nvt is None:
            # Other feeds present but no NVT one: the NVT feed is genuinely missing
            return False, "Feed NVT OpenVAS absent : la synchronisation n'est pas terminée"
        # Could not interpret the feeds (unknown structure / none returned): do not block
        logger.warning(f"OpenVAS feed status inconclusive ({list(feeds)}), proceeding anyway")
        return True, "état du feed indéterminé (vérification ignorée)"

    def get_task_creation_time(self, task_id: str) -> Optional[str]:
        """ISO creation time of a GVM task, to bound its follow-up when started_at is unknown."""
        if not self.gmp:
            raise Exception("Not connected to GVM")
        times = self.gmp.get_task(task_id=task_id).xpath("//task/creation_time/text()")
        return times[0] if times else None

    def get_task_report_id(self, task_id: str) -> str:
        """Report of the running (or last) execution of a task, to resume its follow-up."""
        if not self.gmp:
            raise Exception("Not connected to GVM")
        response = self.gmp.get_task(task_id=task_id)
        ids = response.xpath("//task/current_report/report/@id") or response.xpath("//task/last_report/report/@id")
        return ids[0] if ids else ""

    def find_tasks(self, name_part: str) -> List[dict]:
        """Tasks whose name contains `name_part` (task names embed the scan id)."""
        if not self.gmp:
            raise Exception("Not connected to GVM")
        response = self.gmp.get_tasks(filter_string=f"name~{name_part} rows=-1")
        tasks = []
        for task in response.xpath("//task[@id]"):
            tasks.append({
                "id": task.get("id"),
                "name": task.findtext("name") or "",
                "status": task.findtext("status") or "",
                "progress": task.findtext("progress") or "",
            })
        return tasks

    def get_task_status(self, task_id: str) -> str:
        status, _ = self.get_task_status_and_progress(task_id)
        return status

    def get_report(self, report_id: str) -> str:
        if not self.gmp:
            raise Exception("Not connected to GVM")
            
        try:
            # We want the raw XML to parse it later
            # Explicit filter (same as the Greenbone UI default) so results do not depend on the user's saved filter
            response = self.gmp.get_report(report_id=report_id, details=True, ignore_pagination=True,
                                           filter_string="apply_overrides=1 min_qod=70 rows=-1")
            from lxml import etree
            xml_report = etree.tostring(response, encoding='unicode')
            # The full report used to be logged here: one report wiped every other log line (rotation at 100 KB)
            logger.info(f"OpenVAS report {report_id} retrieved ({len(xml_report)} bytes)")
            logger.debug(xml_report)
            return xml_report
        except GvmError as e:
            logger.error(f"Failed to get report: {str(e)}")
            raise
