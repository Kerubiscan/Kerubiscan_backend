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

    feed_ok = (True, "Feed NVT 20261001")

    def check_feeds(self):
        return FakeGVM.feed_ok

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

    def get_task_creation_time(self, task_id):
        return None

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
    assert polls[-1][1]["kwargs"]["started_at"]                                # 72 h cap kept


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


# ----------------------------------------------------------------------------- stop / shutdown


def test_stop_scan_revokes_tasks_and_stops_openvas(db, company, gvm, monkeypatch):
    revoked = []
    monkeypatch.setattr(scan_tasks.celery_app.control, "revoke", lambda tid, **kw: revoked.append((tid, kw)))
    scan_id = _scan(db, company, "OPENVAS", {"10.0.0.5": "IN_PROGRESS", "10.0.0.6": "COMPLETED"},
                    meta={"10.0.0.5": {"celery_task": "celery-1", "engine_task": "gvm-1"}})
    FakeGVM.tasks["gvm-1"] = {"id": "gvm-1", "name": "x", "status": "Running", "progress": "20"}
    n = scan_tasks.stop_scan_task(scan_id)
    assert n == 1
    assert revoked == [("celery-1", {"terminate": True, "signal": "SIGTERM"})]
    assert FakeGVM.stopped == ["gvm-1"]
    scan = _reload(db, scan_id)
    assert scan.target_states == {"10.0.0.5": "INTERRUPTED", "10.0.0.6": "COMPLETED"}
    assert "arrêté" in scan.target_meta["10.0.0.5"]["detail"]


def test_worker_shutdown_kills_registered_scanner_processes(monkeypatch):
    from src.scans.adapters.outbound import base_adapter

    class FakeProc:
        def __init__(self): self.killed = False
        def poll(self): return None if not self.killed else 0
        def kill(self): self.killed = True
        def wait(self, timeout=None): return 0

    killed = []
    monkeypatch.setattr(base_adapter.BaseScannerAdapter, "_kill", staticmethod(lambda p: (p.kill(), killed.append(p))))
    base_adapter._RUNNING_PROCS.clear()
    p1, p2 = FakeProc(), FakeProc()
    base_adapter._register(p1)
    base_adapter._register(p2)
    assert base_adapter.kill_all_running() == 2
    assert p1.killed and p2.killed
    base_adapter._RUNNING_PROCS.clear()


def test_scan_task_received_by_default_worker_is_redispatched(db, make_scan, fakes, monkeypatch):  # noqa: F811
    sent = []
    monkeypatch.setattr(scan_tasks.run_vulnerability_scan, "apply_async", lambda *a, **kw: sent.append(kw))

    scan_id = make_scan("10.0.0.5", "NMAP")
    scan_tasks.run_vulnerability_scan.push_request(hostname="default@host", id="t1")
    try:
        scan_tasks.run_vulnerability_scan.run(scan_id, "10.0.0.5", "10.0.0.5", "cfg")
    finally:
        scan_tasks.run_vulnerability_scan.pop_request()
    assert sent and sent[0]["queue"] == "scans"


# ----------------------------------------------------------------------------- discovery R5


def test_discovery_sets_every_target_state(db, company, monkeypatch):
    scan_id = _scan(db, company, "NMAP", {"192.168.3.0/24": "PENDING"})
    db_scan = _reload(db, scan_id)
    db_scan.scan_type = ScanType.DISCOVERY
    db.commit()
    scan_tasks._finish_discovery(scan_id, ScanStatus.COMPLETED, {"hosts_found": 3})
    scan = _reload(db, scan_id)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.target_states == {"192.168.3.0/24": "COMPLETED"}      # was left PENDING (R5)


# ----------------------------------------------------------------------------- secrets never on the cmdline


def test_nuclei_credentials_go_to_a_config_file_not_the_command_line(db, monkeypatch, tmp_path):
    from src.scans.adapters.outbound import nuclei_adapter
    captured = {}

    def fake_run(cmd, timeout, err_file_path=None, env=None):
        captured["cmd"] = cmd
        import os as _os
        cfg = [c for c in cmd if c.endswith(".yaml")]
        captured["cfg"] = open(cfg[0]).read() if cfg else ""
        open(err_file_path, "w").close()
        out = cmd[cmd.index("-jle") + 1]
        open(out, "w").close()
        return 0, ""
    monkeypatch.setattr(nuclei_adapter.NucleiAdapter, "run_process", staticmethod(fake_run))
    monkeypatch.setattr(nuclei_adapter, "ensure_templates", lambda: 1000)
    nuclei_adapter.NucleiAdapter.run_scan(["http://site"], credentials={"credential_type": "HTTP", "username": "u", "password": "s3cr3t"})
    assert "s3cr3t" not in " ".join(captured["cmd"])            # never on the command line
    assert "Basic" in captured["cfg"]                           # but used, via the 0600 config file


def test_zap_credentials_are_set_via_the_api_not_the_command_line(monkeypatch):
    from src.scans.adapters.outbound import zap_adapter
    calls = []

    class FakeProc:
        pid = 1234
        def poll(self): return None
        def wait(self, timeout=None): return 0
    monkeypatch.setattr(zap_adapter.subprocess, "Popen", lambda cmd, **kw: (calls.append(("cmd", cmd)), FakeProc())[1])
    monkeypatch.setattr(zap_adapter, "_register", lambda p: None)
    monkeypatch.setattr(zap_adapter, "_unregister", lambda p: None)

    def fake_api(zap_url, api_key, path, **params):
        calls.append((path, params))
        if "version" in path:
            return {"version": "2.15"}
        if path.endswith("/scan/"):
            return {"scan": "0"}
        return {"status": "100", "alerts": []}
    monkeypatch.setattr(zap_adapter.ZAPAdapter, "_api", staticmethod(fake_api))
    monkeypatch.setattr(zap_adapter.ZAPAdapter, "_wait", staticmethod(lambda *a, **kw: True))
    monkeypatch.setattr(zap_adapter.os, "killpg", lambda *a: None, raising=False)
    zap_adapter.ZAPAdapter.run_scan(["http://site.com"], credentials={"credential_type": "HTTP", "username": "u", "password": "s3cr3t"})
    cmd = next(c for tag, c in calls if tag == "cmd")
    assert "s3cr3t" not in " ".join(cmd)                         # not on the command line
    addrule = [p for path, p in calls if isinstance(path, str) and "addRule" in path]
    assert addrule and "s3cr3t" not in str(addrule)             # set via API, as base64 only


# ----------------------------------------------------------------------------- retention


def test_cleanup_task_exists_and_startup_no_longer_purges():
    from pathlib import Path
    main_src = (Path(__file__).resolve().parents[1] / "src" / "main.py").read_text(encoding="utf-8")
    assert "last_scan_raw_output = NULL" not in main_src         # purge removed from startup (R8)
    assert hasattr(watchdog, "cleanup_old_data")


def test_openvas_refuses_scan_when_feed_not_ready(db, company, gvm):
    FakeGVM.feed_ok = (False, "Feed NVT OpenVAS absent : la synchronisation n'est pas terminée")
    try:
        scan_id = _scan(db, company, "OPENVAS", {"10.0.0.5": "PENDING"})
        assert scan_tasks.run_vulnerability_scan(scan_id, "10.0.0.5", "10.0.0.5", "cfg") is False
        scan = _reload(db, scan_id)
        assert scan.target_states["10.0.0.5"] == "FAILED"
        assert "Feed NVT" in scan.target_meta["10.0.0.5"]["detail"]
    finally:
        FakeGVM.feed_ok = (True, "Feed NVT 20261001")


def test_feed_check_is_fail_open_on_read_error():
    """A feed-check incompatibility must never block scanning (it only blocks when it is sure)."""
    from src.scans.adapters.outbound.gvm_adapter import GVMAdapter

    class Gmp:
        def get_feeds(self):
            raise RuntimeError("get_feeds unsupported by this image")
    a = GVMAdapter.__new__(GVMAdapter)
    a.gmp = Gmp()
    ok, detail = a.check_feeds()
    assert ok is True and "indéterminé" in detail


def test_nuclei_template_download_targets_the_templates_dir_without_duc(monkeypatch, tmp_path):
    # nuclei 3.11: `-duc -ut` exits 0 without downloading anything (broke the image build)
    from src.scans.adapters.outbound import nuclei_adapter
    from src.scans.adapters.outbound.base_adapter import ScanError
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(tmp_path))
    calls = []
    monkeypatch.setattr(nuclei_adapter.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    with pytest.raises(ScanError):  # nothing downloaded by the fake: the scan is refused, not run blind
        nuclei_adapter.ensure_templates()
    assert calls and "-duc" not in calls[0]
    assert calls[0][-3:] == ["-ut", "-ud", str(tmp_path)]


def test_worker_process_registers_every_model_for_foreign_keys(tmp_path):
    # Seen on the test server: the worker only imported some models and every scan failed with
    # NoReferencedTableError (scans.company_id -> companies). Must run in a fresh interpreter: the
    # test session itself already imports every model.
    import subprocess
    from pathlib import Path
    code = (
        "import importlib\n"
        "import src.core.celery_app\n"
        "for m in ['src.scans.application.services.tasks', 'src.vulnerabilities.application.services.tasks',\n"
        "          'src.scheduling.application.services.tasks', 'src.scans.application.services.watchdog']:\n"
        "    importlib.import_module(m)\n"
        "from src.core.database import Base\n"
        "for t in Base.metadata.tables.values():\n"
        "    for fk in t.foreign_keys:\n"
        "        fk.column\n"
        "print('OK')\n"
    )
    env = {**__import__("os").environ, "POSTGRES_URL": f"sqlite:///{(tmp_path / 'w.db').as_posix()}",
           "REDIS_URL": "memory://"}
    root = Path(__file__).resolve().parents[1]
    res = subprocess.run([sys.executable, "-c", code], cwd=root, env=env, capture_output=True, text=True, timeout=120)
    assert res.returncode == 0 and "OK" in res.stdout, res.stderr[-1500:]


def test_scan_percentage_follows_real_steps_and_reaches_100_only_when_finished():
    # One-target scans used to stay at 0 % until the very end (finished targets / targets)
    scan = ScanEntity(target_states={"a": progress.IN_PROGRESS, "b": progress.COMPLETED},
                      target_meta={"a": {"progress": 30}})
    progress.recompute_progress(scan)
    assert scan.progress == 65                              # (30 % + 100 %) / 2
    scan.target_meta = {"a": {"progress": 30, "ov_progress": 80}}
    progress.recompute_progress(scan)
    assert scan.progress == 90                              # OpenVAS-reported progress is used
    scan.target_meta = {"a": {"progress": 100}}
    progress.recompute_progress(scan)
    assert scan.progress < 100                              # 100 % only once every target is finished


def test_engine_steps_are_recorded_and_finished_scan_is_100(db, make_scan, fakes):  # noqa: F811
    scan_id = make_scan("app.exemple.com", "NMAP")
    scan_tasks.run_vulnerability_scan(scan_id, "app.exemple.com", "app.exemple.com", "cfg")
    db.expire_all()
    scan = db.query(ScanEntity).filter(ScanEntity.id == scan_id).one()
    assert scan.target_meta["app.exemple.com"]["progress"] == 95   # last step before the final state
    assert scan.progress == 100 and scan.status == ScanStatus.COMPLETED


def test_scan_response_gives_end_time_and_duration():
    from src.scans.adapters.inbound.api.endpoints import _timing
    scan = ScanEntity(status=ScanStatus.COMPLETED, created_at=datetime(2026, 10, 8, 19, 22, 0, tzinfo=timezone.utc),
                      target_meta={"a": {"started_at": "2026-10-08T19:22:14+00:00", "updated_at": "2026-10-08T19:41:18+00:00"}})
    started, finished, duration = _timing(scan)
    assert finished == "2026-10-08T19:41:18+00:00" and duration == 19 * 60 + 4
    scan.status = ScanStatus.IN_PROGRESS
    started, finished, duration = _timing(scan)
    assert finished is None and duration > 0                 # elapsed time while it runs
