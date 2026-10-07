"""Watchdog: no scan target may stay "in progress" forever.

Runs every 10 minutes (Celery Beat). For each target of a running scan, it looks at the last
activity recorded in scans.target_meta (scans of the previous version have none: the scan's
updated_at is used instead):
  * OpenVAS: the follow-up loop records activity every 30 s. When it went silent (worker restart),
    the OpenVAS task is looked up and its follow-up resumed if it still runs; otherwise the target
    is closed as TIMEOUT.
  * Nmap / Nuclei / ZAP: a target silent for longer than the Celery hard limit cannot be running
    any more: it is closed as TIMEOUT.
  * A target that never started (lost message) is closed as FAILED.
Every closure records its reason, shown in the scan details.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from src.core.celery_app import celery_app
from src.core.database import SessionLocal
from src.scans.domain.entities import ScanEntity, ScanStatus, ScannerEngine
from src.scans.application.services import progress

logger = logging.getLogger(__name__)

OPENVAS_SILENCE_S = 2 * 3600       # the follow-up loop records activity every 30 s
ENGINE_SILENCE_S = 25 * 3600       # longer than the Celery hard limit (24 h)
NEVER_STARTED_S = 26 * 3600        # longer than the Redis visibility timeout (re-delivery)
OPENVAS_RUNNING = {"New", "Requested", "Queued", "Running", "Stop Requested"}


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _silence_s(scan: ScanEntity, target: str, now: datetime) -> float:
    entry = (scan.target_meta or {}).get(target) or {}
    last = _parse(entry.get("updated_at")) or _as_utc(scan.updated_at) or _as_utc(scan.created_at) or now
    return (now - last).total_seconds()


def _find_openvas_task(adapter, scan: ScanEntity, target: str) -> Optional[dict]:
    entry = (scan.target_meta or {}).get(target) or {}
    tasks = adapter.find_tasks(scan.id)
    if entry.get("engine_task"):
        for t in tasks:
            if t["id"] == entry["engine_task"]:
                return t
    # Scans of the previous version: tasks are named "Task_<target>_<scan id>"
    for t in tasks:
        if f"_{target}_" in t["name"]:
            return t
    return None


def _check_openvas_target(adapter, scan: ScanEntity, target: str) -> Optional[tuple]:
    """Returns (state, detail) to close the target, or None when its follow-up was resumed."""
    if adapter is None:
        return None  # OpenVAS unreachable: try again at the next run rather than closing blindly
    task = _find_openvas_task(adapter, scan, target)
    if task and task["status"] in OPENVAS_RUNNING:
        report_id = adapter.get_task_report_id(task["id"])
        from src.scans.application.services.tasks import poll_scan_status
        poll_scan_status.apply_async(args=[scan.id, task["id"], report_id, target], countdown=5)
        logger.warning(f"Watchdog: follow-up of OpenVAS task {task['id']} ({target}, scan {scan.id}) was lost, resumed")
        progress.heartbeat(scan.id, target, engine_task=task["id"])
        return None
    if task and task["status"] in ("Done", "Stopped", "Interrupted"):
        report_id = adapter.get_task_report_id(task["id"])
        from src.scans.application.services.tasks import parse_report
        final = progress.COMPLETED if task["status"] == "Done" else progress.INTERRUPTED
        parse_report(adapter, report_id, target, scan.id, final,
                     detail=None if final == progress.COMPLETED else f"Tâche OpenVAS {task['status']} : résultats partiels")
        logger.warning(f"Watchdog: OpenVAS task {task['id']} ({target}) ended without follow-up, report imported")
        return None
    return (progress.TIMEOUT, "Suivi OpenVAS perdu et tâche OpenVAS introuvable : cible non scannée")


def _scan_id_of(task_name: str) -> Optional[str]:
    # Vulnerability scan tasks are named "Task_<target>_<scan id (uuid, 36 chars)>"
    if not task_name.startswith("Task_") or len(task_name) < 42 or task_name[-37] != "_":
        return None
    return task_name[-36:]


def stop_orphan_openvas_tasks(adapter, db) -> int:
    """Stops running OpenVAS tasks that nothing follows any more: scan deleted, target already
    closed, or scan that is not an OpenVAS scan (tasks started by the former hidden fallback of
    failed Nmap/Nuclei/ZAP targets, which kept OpenVAS busy and left new scans queued at 0 %)."""
    stopped = 0
    for task in adapter.find_tasks("Task_"):
        if task["status"] not in OPENVAS_RUNNING or task["status"] == "Stop Requested":
            continue
        scan_id = _scan_id_of(task["name"])
        if not scan_id:
            continue
        scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()
        target = task["name"][len("Task_"):-37]
        state = (scan.target_states or {}).get(target) if scan else None
        reason = None
        if scan is None or scan.is_deleted:
            reason = "scan supprimé"
        elif scan.scanner_engine != ScannerEngine.OPENVAS:
            reason = f"scan {scan.scanner_engine.name} : tâche lancée par l'ancienne bascule automatique vers OpenVAS"
        elif state in progress.TERMINAL_STATES:
            reason = f"cible déjà terminée ({state})"
        if reason and adapter.stop_task(task["id"]):
            stopped += 1
            logger.warning(f"Watchdog: orphan OpenVAS task {task['name']} stopped ({reason})")
    return stopped


@celery_app.task(name="scan_watchdog")
def scan_watchdog():
    now = datetime.now(timezone.utc)
    db = SessionLocal()
    adapter = None
    closed = 0
    try:
        try:
            adapter = _connect_openvas()
            if adapter is not None:
                stop_orphan_openvas_tasks(adapter, db)
        except Exception as e:
            logger.error(f"Watchdog: orphan OpenVAS task check failed: {e}")
        scans = db.query(ScanEntity).filter(ScanEntity.status == ScanStatus.IN_PROGRESS,
                                            ScanEntity.is_deleted.is_not(True)).all()
        for scan in scans:
            for target, state in dict(scan.target_states or {}).items():
                if state in progress.TERMINAL_STATES:
                    continue
                silence = _silence_s(scan, target, now)
                decision = None
                if state == progress.PENDING:
                    if silence > NEVER_STARTED_S:
                        decision = (progress.FAILED, f"Le scan de cette cible n'a jamais démarré (aucune activité depuis {int(silence // 3600)} h)")
                elif scan.scanner_engine == ScannerEngine.OPENVAS:
                    if silence > OPENVAS_SILENCE_S:
                        if adapter is None:
                            adapter = _connect_openvas()
                        try:
                            decision = _check_openvas_target(adapter, scan, target)
                        except Exception as e:
                            logger.error(f"Watchdog: OpenVAS check failed for {target} (scan {scan.id}): {e}")
                elif silence > ENGINE_SILENCE_S:
                    decision = (progress.TIMEOUT, f"Aucune activité depuis {int(silence // 3600)} h : tâche de scan perdue "
                                                  f"(worker redémarré ou limite de durée atteinte)")
                if decision:
                    progress.update_scan_progress(scan.id, target, decision[0], detail=decision[1])
                    closed += 1
                    logger.warning(f"Watchdog: scan {scan.id}, target {target} closed as {decision[0]}: {decision[1]}")
    finally:
        if adapter is not None:
            adapter.disconnect()
        db.close()
    return closed


def _connect_openvas():
    from src.scans.adapters.outbound.gvm_adapter import GVMAdapter
    adapter = GVMAdapter()
    return adapter if adapter.connect() else None
