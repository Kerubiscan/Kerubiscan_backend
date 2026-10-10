"""Per-target scan states and overall scan status.

A scan used to end "COMPLETED" even when nothing had been tested, or to stay "IN_PROGRESS" forever
when its follow-up was lost. Each target now ends in an explicit state, keeps timestamps and the
reason of a failure (scans.target_meta), and the watchdog (watchdog.py) closes forgotten targets.
"""
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple

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


def target_fraction(state: Optional[str], entry: Optional[dict]) -> float:
    """Progress of one target, 0..1, from real events only.

    A finished target counts 1. A running one counts its last recorded step (start, port discovery
    done, engine done...) or, for OpenVAS, the progress reported by OpenVAS itself. Never 1 before
    the target is really finished.
    """
    if state in TERMINAL_STATES:
        return 1.0
    entry = entry or {}
    steps = [entry.get("progress") or 0]
    if entry.get("ov_progress") is not None:
        steps.append(entry["ov_progress"])
    return min(max(float(v) for v in steps), 99.0) / 100.0


def run_duration_seconds(meta: Optional[dict]) -> Optional[int]:
    """Duration of the current run: first target start -> now."""
    starts = [_parse_iso(e.get("started_at")) for e in (meta or {}).values() if isinstance(e, dict)]
    starts = [t for t in starts if t]
    if not starts:
        return None
    return max(int((datetime.now(timezone.utc) - min(starts)).total_seconds()), 0)


def recompute_progress(scan: ScanEntity) -> None:
    """Overall percentage = mean progress of the targets (used to be finished targets / targets,
    which stayed at 0 % for the whole duration of a one-target scan)."""
    states = scan.target_states or {}
    meta = scan.target_meta or {}
    if not states:
        scan.progress = 100
        return
    total = sum(target_fraction(state, meta.get(t)) for t, state in states.items())
    scan.progress = int(total / len(states) * 100)


def set_target_progress(scan_id: str, target: str, percent: int, remaining_s: Optional[float] = None) -> None:
    """Records a step of a running target (0-99) and updates the scan percentage. remaining_s, when
    the engine can tell, is the time it still needs (read back with engine_remaining)."""
    db: Session = SessionLocal()
    try:
        scan = _locked_scan(db, scan_id)
        if not scan or (scan.target_states or {}).get(target) in TERMINAL_STATES:
            return
        meta = dict(scan.target_meta or {})
        entry = dict(meta.get(target) or {})
        entry["progress"] = max(int(entry.get("progress") or 0), min(int(percent), 99))
        entry["updated_at"] = now_iso()
        if remaining_s is not None:
            entry["eta_s"] = max(int(remaining_s), 0)
            entry["eta_at"] = entry["updated_at"]
        meta[target] = entry
        scan.target_meta = meta
        flag_modified(scan, "target_meta")
        recompute_progress(scan)
        db.commit()
    finally:
        db.close()


def _locked_scan(db: Session, scan_id: str) -> Optional[ScanEntity]:
    # Row lock: two targets finishing at the same time used to overwrite each other's state
    # (read-modify-write of the JSON column), leaving one target IN_PROGRESS forever.
    return db.query(ScanEntity).filter(ScanEntity.id == scan_id).with_for_update().first()


def apply_target_state(db: Session, scan: ScanEntity, target: str, target_status: Optional[str] = None,
                       detail: Optional[str] = None, engine_task: Optional[str] = None,
                       celery_task: Optional[str] = None) -> None:
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
    if celery_task:
        entry["celery_task"] = celery_task
    meta[target] = entry

    scan.target_states = states
    scan.target_meta = meta
    flag_modified(scan, "target_states")
    flag_modified(scan, "target_meta")

    if target_status == PENDING:
        entry.pop("progress", None)
        entry.pop("ov_progress", None)
        meta[target] = entry
    recompute_progress(scan)

    status = overall_status(states)
    if status != ScanStatus.IN_PROGRESS and scan.status not in (ScanStatus.PAUSED, status):
        scan.status = status
        from src.audit.domain.models import AuditLog
        action = "SCAN_COMPLETED" if status == ScanStatus.COMPLETED else "SCAN_FAILED"
        details = {"status": status.name, "targets": states, "engine": scan.scanner_engine.name if scan.scanner_engine else None}
        duration = run_duration_seconds(meta)
        if duration is not None:
            # History used to estimate the end of the next runs (see endpoints._estimate_remaining)
            details["duration_seconds"] = duration
        db.add(AuditLog(user_id="system", username="celery_worker", action=action, resource_type="SCAN",
                        resource_id=str(scan.id), details=details))
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


def heartbeat(scan_id: str, target: str, target_status: Optional[str] = None, engine_task: Optional[str] = None,
              celery_task: Optional[str] = None):
    """Records activity on a target (and optionally QUEUED/IN_PROGRESS) without ending it."""
    db: Session = SessionLocal()
    try:
        scan = _locked_scan(db, scan_id)
        if not scan:
            return
        current = (scan.target_states or {}).get(target)
        if current in TERMINAL_STATES:
            return  # never reopen a finished target
        apply_target_state(db, scan, target, target_status, None, engine_task, celery_task)
        db.commit()
    finally:
        db.close()


def parse_ts(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def run_window(scan) -> Tuple[Optional[datetime], Optional[datetime]]:
    """(start, end) of the scan's latest run, from the per-target timestamps (target_meta).

    A rerun keeps the row (and its created_at): the start is the earliest target start of this
    run, the end (finished scans only) the last update of its targets. Older scans without
    per-target timestamps fall back to created_at / updated_at."""
    meta = scan.target_meta or {}
    entries = [e for e in meta.values() if isinstance(e, dict)]
    starts = [t for t in (parse_ts(e.get("started_at")) for e in entries) if t]
    ends = [t for t in (parse_ts(e.get("updated_at")) for e in entries) if t]
    started = min(starts) if starts else parse_ts(scan.created_at)
    finished = None
    if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        finished = max(ends) if ends else parse_ts(scan.updated_at)
    if started is not None and finished is not None and finished < started:
        finished = started
    return started, finished


def last_run_at(scan) -> Optional[datetime]:
    """When the scan last ran: its end once finished, else its start (UTC)."""
    started, finished = run_window(scan)
    return finished or started


def engine_remaining(scan) -> Optional[int]:
    """Seconds the running targets' engines still need, as they last estimated it, minus the time
    elapsed since. None when no running engine gave an estimate."""
    now = datetime.now(timezone.utc)
    best = None
    for target, entry in (scan.target_meta or {}).items():
        if (scan.target_states or {}).get(target) in TERMINAL_STATES or not isinstance(entry, dict):
            continue
        at = _parse_iso(entry.get("eta_at"))
        if entry.get("eta_s") is None or at is None:
            continue
        left = max(int(entry["eta_s"] - (now - at).total_seconds()), 0)
        best = left if best is None else max(best, left)
    return best


def record_openvas_progress(scan_id: str, target: str, value: int) -> float:
    """Stores the OpenVAS progress and returns the seconds since it last changed (stall detection)."""
    db: Session = SessionLocal()
    try:
        scan = _locked_scan(db, scan_id)
        if not scan:
            return 0.0
        meta = dict(scan.target_meta or {})
        entry = dict(meta.get(target) or {})
        now = datetime.now(timezone.utc)
        changed_at = _parse_iso(entry.get("ov_progress_at"))
        if entry.get("ov_progress") != value or changed_at is None:
            entry["ov_progress"] = value
            entry["ov_progress_at"] = now.isoformat()
            stalled = 0.0
        else:
            stalled = (now - changed_at).total_seconds()
        # Time OpenVAS still needs, from its own pace since its task started reporting (from 5 %,
        # earlier figures say little); read back by engine_remaining like the other engines
        started = _parse_iso(entry.get("ov_started_at"))
        if started is None:
            entry["ov_started_at"] = now.isoformat()
        elif value >= 5:
            entry["eta_s"] = int((now - started).total_seconds() * (100 - value) / value)
            entry["eta_at"] = now.isoformat()
        meta[target] = entry
        scan.target_meta = meta
        flag_modified(scan, "target_meta")
        recompute_progress(scan)
        db.commit()
        return stalled
    finally:
        db.close()


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def recompute_status(scan: ScanEntity) -> None:
    """Sets the scan status from its target states (e.g. after a resume with nothing left to run)."""
    status = overall_status(dict(scan.target_states or {}))
    if status != ScanStatus.IN_PROGRESS:
        scan.status = status
        scan.progress = 100
