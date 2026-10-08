#!/usr/bin/env python
"""One-shot reconciliation for a database coming from the previous version.

Finds and reports (read-only by default):
  * scan targets stuck IN_PROGRESS / QUEUED / PENDING on IN_PROGRESS scans;
  * OpenVAS (GVM) tasks that nothing follows any more (scan deleted, target finished, or a task
    started by the former hidden fallback of a failed Nmap/Nuclei/ZAP target).

With --apply, it stops the orphan OpenVAS tasks and marks the stuck targets TIMEOUT, logging a
SCAN_RECONCILED audit event. It never deletes data.

Usage (inside the api or a worker container):
    python -m scripts.reconcile_scans            # dry-run: shows what it would do
    python -m scripts.reconcile_scans --apply    # acts, after the confirmation prompt
    python -m scripts.reconcile_scans --apply --yes   # acts without prompting (CI/automation)

The scheduled watchdog does the same automatically every 10 minutes; this script is for an
immediate, operator-driven cleanup right after deploying over an old-version database.
"""
import argparse
import sys

from src.core.database import SessionLocal
from src.scans.domain.entities import ScanEntity, ScanStatus, ScannerEngine
from src.scans.application.services import progress
from src.scans.application.services import watchdog


def _stuck_targets(db):
    rows = []
    scans = db.query(ScanEntity).filter(ScanEntity.status == ScanStatus.IN_PROGRESS,
                                        ScanEntity.is_deleted.is_not(True)).all()
    for scan in scans:
        for target, state in (scan.target_states or {}).items():
            if state not in progress.TERMINAL_STATES:
                rows.append((scan.id, scan.scanner_engine.name, target, state))
    return rows


def main():
    parser = argparse.ArgumentParser(description="Reconcile stuck scans and orphan OpenVAS tasks.")
    parser.add_argument("--apply", action="store_true", help="act instead of only reporting")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        stuck = _stuck_targets(db)
        print(f"Cibles bloquées (scans IN_PROGRESS) : {len(stuck)}")
        for scan_id, engine, target, state in stuck:
            print(f"  - scan {scan_id} [{engine}] {target} = {state}")

        orphans = []
        adapter = watchdog._connect_openvas()
        if adapter is None:
            print("OpenVAS injoignable : les tâches GVM orphelines ne peuvent pas être listées.")
        else:
            try:
                for task in adapter.find_tasks("Task_"):
                    if task["status"] not in watchdog.OPENVAS_RUNNING:
                        continue
                    scan_id = watchdog._scan_id_of(task["name"])
                    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).first() if scan_id else None
                    if scan is None or scan.is_deleted or scan.scanner_engine != ScannerEngine.OPENVAS:
                        orphans.append(task)
                print(f"Tâches OpenVAS orphelines : {len(orphans)}")
                for t in orphans:
                    print(f"  - {t['name']} (id {t['id']}, {t['status']} {t['progress']}%)")
            finally:
                if not args.apply:
                    adapter.disconnect()

        if not args.apply:
            print("\nMode lecture seule. Relancez avec --apply pour agir.")
            return 0

        if not args.yes:
            reply = input(f"\nArrêter {len(orphans)} tâche(s) OpenVAS et clore {len(stuck)} cible(s) ? [oui/non] ")
            if reply.strip().lower() not in ("oui", "o", "yes", "y"):
                print("Annulé.")
                return 1

        stopped = watchdog.stop_orphan_openvas_tasks(adapter, db) if adapter is not None else 0
        if adapter is not None:
            adapter.disconnect()
        closed = 0
        for scan_id, _engine, target, _state in stuck:
            progress.update_scan_progress(scan_id, target, progress.TIMEOUT,
                                          detail="Cible close par la reprise (reconcile_scans)")
            closed += 1
        from src.audit.domain.models import AuditLog
        db.add(AuditLog(user_id="system", username="reconcile_scans", action="SCAN_RECONCILED",
                        resource_type="SCAN", resource_id="ALL",
                        details={"orphan_openvas_stopped": stopped, "targets_closed": closed}))
        db.commit()
        print(f"\nFait : {stopped} tâche(s) OpenVAS arrêtée(s), {closed} cible(s) close(s).")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
