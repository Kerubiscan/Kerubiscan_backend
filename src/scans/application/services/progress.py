"""Per-target scan states and overall scan status.

A scan used to end "COMPLETED" even when nothing had been tested, or to stay "IN_PROGRESS" forever
when its follow-up was lost. Each target now ends in an explicit state, keeps timestamps and the
reason of a failure (scans.target_meta), and the watchdog (watchdog.py) closes forgotten targets.
"""
import heapq
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

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


def run_duration_seconds(meta: Optional[dict], paused_seconds: int = 0) -> Optional[int]:
    """Duration of the current run: first target start -> now, pauses left out."""
    starts = [_parse_iso(v) for e in (meta or {}).values() if isinstance(e, dict)
              for v in (e.get("started_at"), e.get("run_started_at"))]
    starts = [t for t in starts if t]
    if not starts:
        return None
    return max(int((datetime.now(timezone.utc) - min(starts)).total_seconds()) - (paused_seconds or 0), 0)


def close_pause(scan, now: Optional[datetime] = None) -> None:
    """Ends the current pause of a scan (resume, stop): its length joins paused_seconds.

    Only the part of the pause after the start of the run counts, as the elapsed time is measured
    from the first target start. A batch paused before any of its targets started, then resumed
    32 h later, had those 32 h taken off a run that only began at the resume: it showed 00:00."""
    paused = parse_ts(scan.paused_at)
    if paused is None:
        return
    now = now or datetime.now(timezone.utc)
    entries = [e for e in (scan.target_meta or {}).values() if isinstance(e, dict)]
    starts = [t for t in (parse_ts(v) for e in entries for v in (e.get("started_at"), e.get("run_started_at"))) if t]
    if starts:
        counted_from = max(paused, min(starts))
        scan.paused_seconds = (scan.paused_seconds or 0) + max(int((now - counted_from).total_seconds()), 0)
    scan.paused_at = None


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
        if target_status in ACTIVE_STATES and states.get(target) == PENDING:
            entry.pop("detail", None)  # a waiting reason ("En attente d'OpenVAS…") ends when the target starts
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
        duration = run_duration_seconds(meta, scan.paused_seconds or 0)
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


def interrupt_targets(scan_id: str, detail: str) -> dict:
    """Marks every non-finished target of the scan INTERRUPTED, all in one locked transaction, and
    returns their metadata (Celery and OpenVAS task ids) as recorded at that moment.

    Stopping target by target let a queued target start in the slot freed by the first one: the
    batch went on although the user pressed Stop. A task starting now finds its target INTERRUPTED."""
    db: Session = SessionLocal()
    try:
        scan = _locked_scan(db, scan_id)
        if not scan:
            return {}
        pending = [t for t, s in (scan.target_states or {}).items() if s not in TERMINAL_STATES]
        if scan.status == ScanStatus.PAUSED:
            # A paused scan kept the PAUSED status once all its targets were interrupted
            close_pause(scan)
            scan.status = ScanStatus.IN_PROGRESS
        for target in pending:
            apply_target_state(db, scan, target, INTERRUPTED, detail)
        meta = {t: dict((scan.target_meta or {}).get(t) or {}) for t in pending}
        db.commit()
        return meta
    finally:
        db.close()


def claim_shared_ports(scan_id: str, target: str, ip: str, ports: List[int]) -> Dict[int, str]:
    """Shares out, between the targets of one scan, the extra web ports of a server they all point to.

    kimia-technologies.com: 5 sub-domains on one IP, whose ports 8080/8443/9443 are services of the
    server itself (same answer whatever the name). Each sub-domain scanned them again. Under the scan
    lock, the first target to ask claims them; the others skip them. Claims of a target that failed
    are ignored (it may not have scanned them). Returns {port: target scanning it} for the ports
    already claimed by another target; this target claims all the others."""
    db: Session = SessionLocal()
    try:
        scan = _locked_scan(db, scan_id)
        if not scan:
            return {}
        states = scan.target_states or {}
        meta = dict(scan.target_meta or {})
        taken: Dict[int, str] = {}
        for other, entry in meta.items():
            if other == target or not isinstance(entry, dict) or states.get(other) in FAILURE_STATES:
                continue
            shared = entry.get("shared_ports") or {}
            if shared.get("ip") == ip:
                for port in shared.get("ports") or []:
                    taken.setdefault(int(port), other)
        entry = dict(meta.get(target) or {})
        entry["shared_ports"] = {"ip": ip, "ports": [p for p in ports if p not in taken]}
        meta[target] = entry
        scan.target_meta = meta
        flag_modified(scan, "target_meta")
        db.commit()
        return {p: taken[p] for p in ports if p in taken}
    finally:
        db.close()


def shared_phase1(scan_id: str, target: str, ip: str, port_range: str) -> Optional[tuple]:
    """Port scan of an IP already done, with the same port range, by another target of the scan.

    kimia-technologies.com: some twenty sub-domains on one IP, and the 65 535 ports of that IP swept
    again for each of them. Returns (other target, host) or None. A failed target's scan is ignored."""
    db: Session = SessionLocal()
    try:
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        if not scan:
            return None
        states = scan.target_states or {}
        for other, entry in (scan.target_meta or {}).items():
            if other == target or not isinstance(entry, dict) or states.get(other) in FAILURE_STATES:
                continue
            done = entry.get("phase1") or {}
            if done.get("ip") == ip and done.get("ports") == port_range and done.get("host"):
                return other, done["host"]
        return None
    finally:
        db.close()


def record_phase1(scan_id: str, target: str, ip: str, port_range: str, host: dict) -> None:
    """Keeps the port scan of a target for the other targets of the scan on the same IP."""
    db: Session = SessionLocal()
    try:
        scan = _locked_scan(db, scan_id)
        if not scan:
            return
        meta = dict(scan.target_meta or {})
        entry = dict(meta.get(target) or {})
        entry["phase1"] = {"ip": ip, "ports": port_range, "host": host}
        meta[target] = entry
        scan.target_meta = meta
        flag_modified(scan, "target_meta")
        db.commit()
    finally:
        db.close()


def claim_openvas_host(scan_id: str, target: str, ip: str) -> Tuple[Optional[str], Optional[str]]:
    """One OpenVAS scan per machine in a scan: (other target, its state) when another target of the
    scan already scans this IP with OpenVAS, else (None, None) and this target takes the IP.

    OpenVAS tests a machine, not a site: 19 kimia-technologies.com domains on one IP made it scan
    that machine 19 times (1-2 days, and ospd-openvas killed by lack of memory). A failed target's
    claim is ignored: another target of the IP then scans it."""
    db: Session = SessionLocal()
    try:
        scan = _locked_scan(db, scan_id)
        if not scan:
            return None, None
        states = scan.target_states or {}
        meta = dict(scan.target_meta or {})
        for other, entry in meta.items():
            if other != target and isinstance(entry, dict) and entry.get("openvas_ip") == ip \
                    and states.get(other) not in FAILURE_STATES:
                return other, states.get(other)
        entry = dict(meta.get(target) or {})
        entry["openvas_ip"] = ip
        meta[target] = entry
        scan.target_meta = meta
        flag_modified(scan, "target_meta")
        db.commit()
        return None, None
    finally:
        db.close()


def pause_running_targets(scan_id: str) -> dict:
    """Puts the running targets of a scan back to PENDING, in one locked transaction, and returns
    their metadata (Celery and OpenVAS task ids) as recorded then, so the caller can stop the
    engines. On resume these targets start over (ZAP cannot resume mid-scan)."""
    db: Session = SessionLocal()
    try:
        scan = _locked_scan(db, scan_id)
        if not scan:
            return {}
        running = [t for t, st in (scan.target_states or {}).items() if st == IN_PROGRESS]
        meta = {t: dict((scan.target_meta or {}).get(t) or {}) for t in running}
        for target in running:
            apply_target_state(db, scan, target, PENDING)
            # PENDING drops started_at (the target starts over on resume): the start of the run is
            # kept apart, and the estimate of the stopped engine is dropped
            entries = dict(scan.target_meta or {})
            entry = dict(entries.get(target) or {})
            if meta[target].get("started_at"):
                entry["run_started_at"] = meta[target].get("run_started_at") or meta[target]["started_at"]
            entry.pop("eta_s", None)
            entry.pop("eta_at", None)
            entries[target] = entry
            scan.target_meta = entries
            flag_modified(scan, "target_meta")
        db.commit()
        return meta
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
    starts = [t for t in (parse_ts(v) for e in entries for v in (e.get("started_at"), e.get("run_started_at"))) if t]
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


def batch_remaining(scan, concurrency: int = 1) -> Optional[int]:
    """Seconds a multi-target scan still needs, every target included: the running ones (their
    engine's estimate, or their own pace) and the waiting ones, each at the pace of the targets
    already done, `concurrency` at a time. None for a single target, or while no target gives a pace.

    The running target's estimate alone said "end imminent" while targets were still queued."""
    states = scan.target_states or {}
    if len(states) < 2:
        return None
    meta = scan.target_meta or {}
    now = datetime.now(timezone.utc)
    done, running, waiting = [], [], 0
    for target, state in states.items():
        entry = meta.get(target) if isinstance(meta.get(target), dict) else {}
        started = _parse_iso(entry.get("started_at"))
        if state in TERMINAL_STATES:
            ended = _parse_iso(entry.get("updated_at"))
            # A failed target (unreachable in seconds) says nothing about the pace of the others
            if state in SUCCESS_STATES and started and ended and ended > started:
                done.append((ended - started).total_seconds())
            continue
        if state != IN_PROGRESS or started is None:
            waiting += 1
            continue
        elapsed = (now - started).total_seconds()
        at = _parse_iso(entry.get("eta_at"))
        percent = entry.get("progress") or 0
        if entry.get("eta_s") is not None and at is not None:
            left = max(entry["eta_s"] - (now - at).total_seconds(), 0)
        elif percent >= 10:
            left = max(elapsed * 100 / percent - elapsed, 0)
        else:
            left = None
        running.append((elapsed, left))
    paces = sorted(done) or sorted(e + left for e, left in running if left is not None)
    if not paces:
        return None
    pace = paces[len(paces) // 2]
    # Each worker slot frees up when its target ends; a waiting target then takes it for `pace`
    slots = [left if left is not None else max(pace - e, 0) for e, left in running]
    slots += [0.0] * max(concurrency - len(slots), 0)
    heapq.heapify(slots)
    for _ in range(waiting):
        heapq.heappush(slots, heapq.heappop(slots) + pace)
    return int(max(slots))


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
