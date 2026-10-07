"""Scans can no longer stay "in progress" forever, and every failure keeps its reason.

Reproduces what was observed on the server: OpenVAS tasks left running by the former hidden
fallback, a new OpenVAS scan queued at 0 % for hours, follow-ups lost after a restart.
"""
import sys
import types
from datetime import datetime, timedelta, timezone

import pytest
from celery.exceptions import Retry, SoftTimeLimitExceeded

from src.assets.domain.entities import AssetEntity
from src.audit.domain.models import AuditLog
from src.scans.domain.entities import ScanEntity, ScanType, ScanStatus, ScannerEngine
from src.scans.application.services import progress, watchdog
from src.scans.application.services import tasks as scan_tasks
from src.scans.adapters.outbound.nmap_adapter import NmapAdapter
from src.scans.adapters.outbound.zap_adapter import alerts_for_hosts
from test_scan_pipeline import fakes, _host, WEB_PORTS  # noqa: F401  (fixture re-used)

UUID_A = "11111111-1111-1111-1111-111111111111"


def _ago(**kw) -> str:
    return (datetime.now(timezone.utc) - timedelta(**kw)).isoformat()


def _scan(db, company, engine="NUCLEI", states=None, meta=None, status=ScanStatus.IN_PROGRESS, scan_id=None, updated=None):
    scan = ScanEntity(id=scan_id or None, company_id=company.id, name="t", target=",".join(states or {"10.0.0.5": "x"}),
                      scan_type=ScanType.VULNERABILITY, scanner_engine=ScannerEngine[engine], status=status,
                      target_states=states or {}, target_meta=meta)
    if updated:
        scan.updated_at = updated
    db.add(scan)
    db.commit()
    return scan.id


def _reload(db, scan_id) -> ScanEntity:
    db.expire_all()
    return db.query(ScanEntity).filter(ScanEntity.id == scan_id).one()


class FakeGVM:
    """Stands in for GVMAdapter (python-gvm is not installed in the test environment)."""
    tasks = {}
    stopped = []
    reachable = True
    created = 0

    def __init__(self, *a, **kw):
        self.gmp = self

    def connect(self):
        return FakeGVM.reachable

    def disconnect(self):
        pass

    def create_target(self, name, hosts, port_range=None, **kw):
        FakeGVM.last_port_range = port_range
        return "target-1"

    def create_task(self, name, target_id, scanner_id, config_id):
        FakeGVM.created += 1
        FakeGVM.tasks["task-1"] = {"id": "task-1", "name": name, "status": "Requested", "progress": "0"}
        return "task-1"

    def start_task(self, task_id):
        return "report-1"

    def get_task_status_and_progress(self, task_id):
        return FakeGVM.tasks[task_id]["status"], int(FakeGVM.tasks[task_id]["progress"])

    def get_task_report_id(self, task_id):
        return f"report-of-{task_id}"

    def get_report(self, report_id):
        return "<report/>"

    def find_tasks(self, name_part):
        return [dict(t) for t in FakeGVM.tasks.values() if name_part in t["name"]]

    def stop_task(self, task_id):
        FakeGVM.stopped.append(task_id)
        if task_id in FakeGVM.tasks:
            FakeGVM.tasks[task_id]["status"] = "Stopped"
        return True


@pytest.fixture()
def gvm(monkeypatch):
    FakeGVM.tasks, FakeGVM.stopped, FakeGVM.reachable, FakeGVM.created = {}, [], True, 0
    module = types.ModuleType("src.scans.adapters.outbound.gvm_adapter")
    module.GVMAdapter = FakeGVM
    monkeypatch.setitem(sys.modules, "src.scans.adapters.outbound.gvm_adapter", module)
    polls, parsed = [], []
    monkeypatch.setattr(scan_tasks.poll_scan_status, "apply_async", lambda *a, **kw: polls.append((a, kw)))
    monkeypatch.setattr(scan_tasks, "parse_report", lambda *a, **kw: parsed.append((a, kw)))
    monkeypatch.setattr(scan_tasks, "_resolve_dns", lambda host: "10.0.0.5")
    return polls, parsed


# ----------------------------------------------------------------------------- OpenVAS


def test_openvas_scan_is_shown_queued_and_keeps_its_task_id(db, company, gvm):
    polls, _ = gvm
    scan_id = _scan(db, company, "OPENVAS", {"192.168.3.179": "PENDING"})
    scan_tasks.run_vulnerability_scan(scan_id, "192.168.3.179", "192.168.3.179", "cfg")
    scan = _reload(db, scan_id)
    assert scan.target_states["192.168.3.179"] == "QUEUED"
    assert scan.target_meta["192.168.3.179"]["engine_task"] == "task-1"
    assert "U:1-65535" not in FakeGVM.last_port_range            # no more full UDP sweep
    assert len(polls) == 1


def test_openvas_follow_up_reports_queue_then_running(db, company, gvm):
    scan_id = _scan(db, company, "OPENVAS", {"192.168.3.179": "QUEUED"})
    FakeGVM.tasks["task-1"] = {"id": "task-1", "name": f"Task_192.168.3.179_{scan_id}", "status": "Queued", "progress": "0"}
    with pytest.raises(Retry):
        scan_tasks.poll_scan_status(scan_id, "task-1", "report-1", "192.168.3.179")
    assert _reload(db, scan_id).target_states["192.168.3.179"] == "QUEUED"
    FakeGVM.tasks["task-1"]["status"] = "Running"
    with pytest.raises(Retry):
        scan_tasks.poll_scan_status(scan_id, "task-1", "report-1", "192.168.3.179")
    assert _reload(db, scan_id).target_states["192.168.3.179"] == "IN_PROGRESS"


@pytest.mark.parametrize("status,deleted,expected_state", [(ScanStatus.PAUSED, False, "PENDING"), (ScanStatus.IN_PROGRESS, True, "IN_PROGRESS")])
def test_openvas_task_is_stopped_when_scan_is_paused_or_deleted(db, company, gvm, status, deleted, expected_state):
    scan_id = _scan(db, company, "OPENVAS", {"10.0.0.5": "IN_PROGRESS"}, status=status)
    if deleted:
        scan = _reload(db, scan_id)
        scan.is_deleted = True
        db.commit()
    FakeGVM.tasks["task-1"] = {"id": "task-1", "name": f"Task_10.0.0.5_{scan_id}", "status": "Running", "progress": "40"}
    assert scan_tasks.poll_scan_status(scan_id, "task-1", "report-1", "10.0.0.5") is False
    assert FakeGVM.stopped == ["task-1"]
    assert _reload(db, scan_id).target_states["10.0.0.5"] == expected_state


# ----------------------------------------------------------------------------- watchdog


def test_watchdog_closes_a_silent_engine_target_with_its_reason(db, company, gvm):
    scan_id = _scan(db, company, "NUCLEI", {"10.0.0.5": "IN_PROGRESS", "10.0.0.6": "IN_PROGRESS"},
                    meta={"10.0.0.5": {"updated_at": _ago(hours=26)}, "10.0.0.6": {"updated_at": _ago(minutes=5)}})
    assert watchdog.scan_watchdog() == 1
    scan = _reload(db, scan_id)
    assert scan.target_states == {"10.0.0.5": "TIMEOUT", "10.0.0.6": "IN_PROGRESS"}
    assert "Aucune activité depuis 26 h" in scan.target_meta["10.0.0.5"]["detail"]
    assert db.query(AuditLog).filter(AuditLog.action == "SCAN_TARGET_FAILED").count() == 1


def test_watchdog_closes_targets_that_never_started(db, company, gvm):
    scan_id = _scan(db, company, "NMAP", {"10.0.0.5": "PENDING"}, meta={"10.0.0.5": {"updated_at": _ago(hours=30)}})
    watchdog.scan_watchdog()
    scan = _reload(db, scan_id)
    assert scan.target_states["10.0.0.5"] == "FAILED" and scan.status == ScanStatus.FAILED
    assert "jamais démarré" in scan.target_meta["10.0.0.5"]["detail"]


def test_watchdog_handles_scans_of_the_previous_version(db, company, gvm):
    """No target_meta: the scan's last update is used (case of the .179 scan stuck for 6 h+)."""
    old = datetime.now(timezone.utc) - timedelta(hours=30)
    scan_id = _scan(db, company, "NMAP", {"10.0.0.5": "IN_PROGRESS"}, updated=old)
    watchdog.scan_watchdog()
    assert _reload(db, scan_id).target_states["10.0.0.5"] == "TIMEOUT"


def test_watchdog_resumes_a_lost_openvas_follow_up_instead_of_closing(db, company, gvm):
    polls, _ = gvm
    scan_id = _scan(db, company, "OPENVAS", {"192.168.3.179": "IN_PROGRESS"}, meta={"192.168.3.179": {"updated_at": _ago(hours=6)}})
    FakeGVM.tasks["t-179"] = {"id": "t-179", "name": f"Task_192.168.3.179_{scan_id}", "status": "Queued", "progress": "0"}
    watchdog.scan_watchdog()
    assert _reload(db, scan_id).target_states["192.168.3.179"] == "IN_PROGRESS"     # not closed
    assert polls and polls[-1][1]["args"][:3] == [scan_id, "t-179", "report-of-t-179"]


def test_watchdog_closes_openvas_target_whose_task_vanished(db, company, gvm):
    scan_id = _scan(db, company, "OPENVAS", {"10.0.0.5": "IN_PROGRESS"}, meta={"10.0.0.5": {"updated_at": _ago(hours=6)}})
    watchdog.scan_watchdog()
    scan = _reload(db, scan_id)
    assert scan.target_states["10.0.0.5"] == "TIMEOUT" and "introuvable" in scan.target_meta["10.0.0.5"]["detail"]


def test_watchdog_does_not_guess_when_openvas_is_unreachable(db, company, gvm):
    FakeGVM.reachable = False
    scan_id = _scan(db, company, "OPENVAS", {"10.0.0.5": "IN_PROGRESS"}, meta={"10.0.0.5": {"updated_at": _ago(hours=6)}})
    watchdog.scan_watchdog()
    assert _reload(db, scan_id).target_states["10.0.0.5"] == "IN_PROGRESS"


def test_watchdog_stops_orphan_openvas_tasks_of_the_former_hidden_fallback(db, company, gvm):
    """Server case: a Nuclei 'Multi scan' whose ABANDONED targets had silently started OpenVAS tasks."""
    nuclei_scan = _scan(db, company, "NUCLEI", {"10.0.0.70": "ABANDONED", "10.0.0.71": "COMPLETED"}, status=ScanStatus.COMPLETED)
    openvas_scan = _scan(db, company, "OPENVAS", {"10.0.0.5": "IN_PROGRESS", "10.0.0.6": "COMPLETED"},
                         meta={"10.0.0.5": {"updated_at": _ago(minutes=1)}})
    FakeGVM.tasks = {
        "orphan": {"id": "orphan", "name": f"Task_10.0.0.70_{nuclei_scan}", "status": "Running", "progress": "82"},
        "done-target": {"id": "done-target", "name": f"Task_10.0.0.6_{openvas_scan}", "status": "Running", "progress": "10"},
        "active": {"id": "active", "name": f"Task_10.0.0.5_{openvas_scan}", "status": "Running", "progress": "30"},
        "deleted": {"id": "deleted", "name": f"Task_10.0.0.9_{UUID_A}", "status": "Queued", "progress": "0"},
    }
    watchdog.scan_watchdog()
    assert sorted(FakeGVM.stopped) == ["deleted", "done-target", "orphan"]


# ----------------------------------------------------------------------------- engines


def test_soft_time_limit_closes_the_target_with_a_reason(db, make_scan, fakes, monkeypatch):  # noqa: F811
    def too_long(*a, **kw):
        raise SoftTimeLimitExceeded()
    monkeypatch.setattr(NmapAdapter, "run_detailed_discovery_scan", staticmethod(too_long))
    scan_id = make_scan("10.0.0.5", "NMAP")
    scan_tasks.run_vulnerability_scan(scan_id, "10.0.0.5", "10.0.0.5", "cfg")
    scan = _reload(db, scan_id)
    assert scan.target_states["10.0.0.5"] == "TIMEOUT" and "23 h" in scan.target_meta["10.0.0.5"]["detail"]


def test_engine_failure_reason_is_kept_for_the_user(db, make_scan, fakes, monkeypatch):  # noqa: F811
    from src.scans.adapters.outbound import nuclei_adapter
    from src.scans.adapters.outbound.base_adapter import ScanError

    def broken(*a, **kw):
        raise ScanError("Templates Nuclei absents (0 trouvés)")
    monkeypatch.setattr(nuclei_adapter.NucleiAdapter, "run_scan", staticmethod(broken))
    monkeypatch.setattr(scan_tasks.run_vulnerability_scan, "max_retries", 0)
    scan_id = make_scan("app.exemple.com", "NUCLEI")
    scan_tasks.run_vulnerability_scan(scan_id, "app.exemple.com", "app.exemple.com", "cfg")
    scan = _reload(db, scan_id)
    assert scan.target_states["app.exemple.com"] == "FAILED"
    assert "Templates Nuclei absents" in scan.target_meta["app.exemple.com"]["detail"]
    assert scan.target_meta["app.exemple.com"]["started_at"]


def test_rescan_does_not_double_count_findings(db, make_scan, fakes):  # noqa: F811
    scan_id = make_scan("app.exemple.com", "NUCLEI")
    for _ in range(2):  # e.g. a retried target
        scan_tasks.run_vulnerability_scan(scan_id, "app.exemple.com", "app.exemple.com", "cfg")
    assert _reload(db, scan_id).vulnerabilities_found == 1


def test_finished_target_is_never_reopened_by_a_late_heartbeat(db, company):
    scan_id = _scan(db, company, "NMAP", {"10.0.0.5": "COMPLETED"})
    progress.heartbeat(scan_id, "10.0.0.5", progress.IN_PROGRESS)
    assert _reload(db, scan_id).target_states["10.0.0.5"] == "COMPLETED"


def test_manual_asset_named_after_a_domain_keeps_its_ip(db, company, make_scan, fakes):  # noqa: F811
    db.add(AssetEntity(company_id=company.id, name="app.exemple.com", ip_address="10.9.9.9", asset_type="Server"))
    db.commit()
    scan_id = make_scan("app.exemple.com", "NUCLEI")
    scan_tasks.run_vulnerability_scan(scan_id, "app.exemple.com", "app.exemple.com", "cfg")
    assets = {a.ip_address: a for a in db.query(AssetEntity).all()}
    assert set(assets) == {"10.9.9.9", "app.exemple.com"}       # untouched + one asset for the domain


def test_zap_alerts_after_an_http_to_https_redirect_are_kept():
    alerts = [{"url": "https://site.com/login"}, {"url": "http://site.com/"}, {"url": "https://cdn.other.com/x.js"}]
    assert alerts_for_hosts(alerts, ["http://site.com"]) == alerts[:2]


def test_resuming_a_scan_whose_targets_all_finished_closes_it(db, company):
    pytest.importorskip("fastapi")
    from src.scans.adapters.inbound.api import endpoints
    scan_id = _scan(db, company, "NMAP", {"10.0.0.5": "COMPLETED", "10.0.0.6": "TIMEOUT"}, status=ScanStatus.PAUSED)
    response = endpoints.resume_scan(scan_id, db=db, current_user={"sub": "u", "preferred_username": "analyst"})
    assert response.status == "COMPLETED"                   # used to stay IN_PROGRESS forever
