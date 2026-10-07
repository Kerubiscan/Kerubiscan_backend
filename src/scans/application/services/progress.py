"""Per-target scan states and overall scan status.

A scan used to end "COMPLETED" even when nothing had been tested. Each target now ends in an
explicit state, and the scan is FAILED when no target could actually be scanned.
"""
import logging
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified
from src.core.database import SessionLocal
from src.scans.domain.entities import ScanEntity, ScanStatus

logger = logging.getLogger(__name__)

PENDING = "PENDING"
IN_PROGRESS = "IN_PROGRESS"

# The target was scanned
COMPLETED = "COMPLETED"            # scanned, results (possibly none) recorded
NO_OPEN_PORTS = "NO_OPEN_PORTS"    # host answered but no open port: nothing to test
NO_WEB_SERVICE = "NO_WEB_SERVICE"  # web engine: no HTTP(S) service found on the host

# The target was NOT (fully) scanned
FAILED = "FAILED"
ABANDONED = "ABANDONED"            # legacy value
TIMEOUT = "TIMEOUT"                # Nmap gave up on the host (host timeout) or engine time budget exceeded
HOST_UNREACHABLE = "HOST_UNREACHABLE"
INVALID_TARGET = "INVALID_TARGET"
INTERRUPTED = "INTERRUPTED"        # OpenVAS task stopped/interrupted: partial results only

SUCCESS_STATES = {COMPLETED, NO_OPEN_PORTS, NO_WEB_SERVICE}
FAILURE_STATES = {FAILED, ABANDONED, TIMEOUT, HOST_UNREACHABLE, INVALID_TARGET, INTERRUPTED}
TERMINAL_STATES = SUCCESS_STATES | FAILURE_STATES


def overall_status(states: dict) -> ScanStatus:
    values = list(states.values())
    if not values or any(v not in TERMINAL_STATES for v in values):
        return ScanStatus.IN_PROGRESS
    if any(v in SUCCESS_STATES for v in values):
        return ScanStatus.COMPLETED
    return ScanStatus.FAILED


def update_scan_progress(scan_id: str, target: str, target_status: str):
    db: Session = SessionLocal()
    try:
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        if not scan:
            return
        states = dict(scan.target_states or {})
        states[target] = target_status
        scan.target_states = states
        flag_modified(scan, "target_states")

        total = len(states)
        done = sum(1 for s in states.values() if s in TERMINAL_STATES)
        scan.progress = int((done / total) * 100) if total else 100

        status = overall_status(states)
        if status != ScanStatus.IN_PROGRESS and scan.status != ScanStatus.PAUSED:
            scan.status = status
            from src.audit.domain.models import AuditLog
            action = "SCAN_COMPLETED" if status == ScanStatus.COMPLETED else "SCAN_FAILED"
            db.add(AuditLog(user_id="system", username="celery_worker", action=action, resource_type="SCAN",
                            resource_id=str(scan_id), details={"status": status.name, "targets": states}))
        db.commit()
        logger.info(f"Scan {scan_id}: target {target} -> {target_status} ({done}/{total})")
    finally:
        db.close()
