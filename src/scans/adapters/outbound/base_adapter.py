import os
import signal
import subprocess
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)

class ScanError(RuntimeError):
    pass


class ScanTimeout(ScanError):
    """The scanner exceeded its time budget (retrying would only waste the worker's time)."""

@dataclass
class Finding:
    id: str
    name: str
    severity: str
    description: str
    remediation: str
    cvss_score: Optional[float]
    cve_id: Optional[str]
    host: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[str] = None
    protocol: Optional[str] = None
    matched_at: Optional[str] = None
    extracted_results: Optional[List[str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "host": self.host,
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "matched_at": self.matched_at,
            "extracted_results": self.extracted_results or []
        }

class BaseScannerAdapter:
    @staticmethod
    def _kill(proc) -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (AttributeError, ProcessLookupError, PermissionError):
            proc.kill()  # Windows (no process groups) or already gone
        try:
            proc.wait(timeout=30)
        except Exception:
            pass

    @staticmethod
    def run_process(cmd: List[str], timeout: int, err_file_path: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
        """Runs a scanner subprocess in a new process group with timeout and standard error capturing."""
        if not err_file_path:
            import tempfile
            fd, err_file_path = tempfile.mkstemp(prefix="scanner_stderr_")
            os.close(fd)
            
        with open(err_file_path, "w") as err:
            proc = subprocess.Popen(
                cmd, 
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, 
                stderr=err,
                env=env or os.environ.copy(), 
                start_new_session=True
            )
            
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                logger.error(f"Scanner process timed out after {timeout} seconds.")
                BaseScannerAdapter._kill(proc)
                raise ScanTimeout(f"Scan timed out after {timeout} seconds.")
            except BaseException:
                # e.g. Celery SoftTimeLimitExceeded: the scanner must not keep running orphaned
                BaseScannerAdapter._kill(proc)
                raise
                
        with open(err_file_path, "r", encoding="utf-8", errors="replace") as f:
            stderr_tail = f.read()[-500:]
            
        return proc.returncode, stderr_tail
