"""Per-target scan states and overall scan status.

A scan used to end "COMPLETED" even when nothing had been tested, or to stay "IN_PROGRESS" forever
when its follow-up was lost. Each target now ends in an explicit state, keeps timestamps and the
reason of a failure (scans.target_meta), and the watchdog (watchdog.py) closes forgotten targets.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified
from src.core.database import SessionLocal
from src.scans.domain.entities import ScanEntity, ScanStatus

logger = logging.getLogger(__name__)

PENDING = "PENDING"
QUEUED = "QUEUED"                  # accepted by the engine (OpenVAS) but waiting for a free slot
IN_PROGRESS = "IN_PROGRESS"

# The target was scanned
COMPLETED = "COMPLETED"            # scanned, results (possibly none) recorded
NO_OPEN_PORTS = "NO_OPEN_PORTS"    # host answered but no open port: nothing to test
NO_WEB_SERVICE = "NO_WEB_SERVICE"  # web engine: no HTTP(S) service found on the host

# The target was NOT (fully) scanned
FAILED = "FAILED"
ABANDONED = "ABANDONED"            # legacy value
TIMEOUT = "TIMEOUT"                # time budget exceeded, or no activity any more (watchdog)
HOST_UNREACHABLE = "HOST_UNREACHABLE"
INVALID_TARGET = "INVALID_TARGET"
INTERRUPTED = "INTERRUPTED"        # OpenVAS task stopped/interrupted: partial results only

ACTIVE_STATES = {QUEUED, IN_PROGRESS}
SUCCESS_STATES = {COMPLETED, NO_OPEN_PORTS, NO_WEB_SERVICE}
FAILURE_STATES = {FAILED, ABANDONED, TIMEOUT, HOST_UNREACHABLE, INVALID_TARGET, INTERRUPTED}
TERMINAL_STATES = SUCCESS_STATES | FAILURE_STATES


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def overall_status(states: dict) -> ScanStatus:
    values = list(states.values())
    if not values or any(v not in TERMINAL_STATES for v in values):
        return ScanStatus.IN_PROGRESS
    if any(v in SUCCESS_STATES for v in values):
        return ScanStatus.COMPLETED
    return ScanStatus.FAILED


def _locked_scan(db: Session, scan_id: str) -> Optional[ScanEntity]:
    # Row lock: two targets finishing at the same time used to overwrite each other's state
    # (read-modify-write of the JSON column), leaving one target IN_PROGRESS forever.
    return db.query(ScanEntity).filter(ScanEntity.id == scan_id).with_for_update().first()


def apply_target_state(db: Session, scan: ScanEntity, target: str, target_status: Optional[str] = None,
                       detail: Optional[str] = None, engine_task: Optional[str] = None) -> None:
    """Updates state and metadata of one target on a scan loaded in `db` (caller commits)."""
    states = dict(scan.target_states or {})
    meta = dict(scan.target_meta or {})
    entry = dict(meta.get(target) or {})
    stamp = now_iso()

    if target_status:
        states[target] = target_status
        if target_status in ACTIVE_STATES and not entry.get("started_at"):
            entry["started_at"] = stamp
        if target_status == PENDING:
            entry.pop("started_at", None)
            entry.pop("detail", None)
    entry["updated_at"] = stamp
    if detail is not None:
        entry["detail"] = detail[:500]
    if engine_task:
        entry["engine_task"] = engine_task
    meta[target] = entry

    scan.target_states = states
    scan.target_meta = meta
    flag_modified(scan, "target_states")
    flag_modified(scan, "target_meta")

    total = len(states)
    done = sum(1 for s in states.values() if s in TERMINAL_STATES)
    scan.progress = int((done / total) * 100) if total else 100

    status = overall_status(states)
    if status != ScanStatus.IN_PROGRESS and scan.status not in (ScanStatus.PAUSED, status):
        scan.status = status
        from src.audit.domain.models import AuditLog
        action = "SCAN_COMPLETED" if status == ScanStatus.COMPLETED else "SCAN_FAILED"
        db.add(AuditLog(user_id="system", username="celery_worker", action=action, resource_type="SCAN",
                        resource_id=str(scan.id), details={"status": status.name, "targets": states}))
    elif status == ScanStatus.IN_PROGRESS and scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        scan.status = ScanStatus.IN_PROGRESS

    if target_status in FAILURE_STATES:
        from src.audit.domain.models import AuditLog
        db.add(AuditLog(user_id="system", username="celery_worker", action="SCAN_TARGET_FAILED",
                        resource_type="SCAN", resource_id=str(scan.id),
                        details={"target": target, "state": target_status, "reason": entry.get("detail")}))


def update_scan_progress(scan_id: str, target: str, target_status: str, detail: Optional[str] = None,
                         engine_task: Optional[str] = None):
    db: Session = SessionLocal()
    try:
        scan = _locked_scan(db, scan_id)
        if not scan:
            return
        apply_target_state(db, scan, target, target_status, detail, engine_task)
        db.commit()
        logger.info(f"Scan {scan_id}: target {target} -> {target_status}" + (f" ({detail})" if detail else ""))
    finally:
        db.close()


def heartbeat(scan_id: str, target: str, target_status: Optional[str] = None, engine_task: Optional[str] = None):
    """Records activity on a target (and optionally QUEUED/IN_PROGRESS) without ending it."""
    db: Session = SessionLocal()
    try:
        scan = _locked_scan(db, scan_id)
        if not scan:
            return
        current = (scan.target_states or {}).get(target)
        if current in TERMINAL_STATES:
            return  # never reopen a finished target
        apply_target_state(db, scan, target, target_status, None, engine_task)
        db.commit()
    finally:
        db.close()


def recompute_status(scan: ScanEntity) -> None:
    """Sets the scan status from its target states (e.g. after a resume with nothing left to run)."""
    status = overall_status(dict(scan.target_states or {}))
    if status != ScanStatus.IN_PROGRESS:
        scan.status = status
        scan.progress = 100
