"""End-to-end scan pipeline with the scanner binaries replaced by fakes (no network, no subprocess)."""
import pytest
from conftest import read_fixture

from src.assets.domain.entities import AssetEntity
from src.scans.domain.entities import ScanEntity, ScanStatus
from src.vulnerabilities.domain.entities import VulnerabilityEntity
from src.vulnerabilities.domain.models import VulnSeverity, VulnStatus
from src.scans.adapters.outbound.nmap_adapter import NmapAdapter
from src.scans.adapters.outbound.base_adapter import ScanError
from src.scans.application.services import tasks as scan_tasks
from src.scans.application.services.progress import overall_status


# ----------------------------------------------------------------------------- fakes

def _host(ip="203.0.113.10", hostname="app.exemple.com", ports=None, timed_out=False):
    return {"ip": ip, "hostname": hostname, "mac_address": None, "os": "Linux", "os_accuracy": 90,
            "ports": ports or [], "services": ports or [], "timed_out": timed_out, "vulns": []}


WEB_PORTS = [{"port": 443, "state": "open", "service": "http", "tunnel": "ssl", "protocol": "tcp"},
             {"port": 22, "state": "open", "service": "ssh", "protocol": "tcp"}]


@pytest.fixture()
def fakes(monkeypatch):
    calls = {"phase1": [], "nuclei": [], "zap": [], "nmap_vuln": []}
    state = {"phase1_hosts": [_host(ports=WEB_PORTS)], "probe": []}

    monkeypatch.setattr(scan_tasks, "_resolve_dns", lambda host: "203.0.113.10")
    monkeypatch.setattr(scan_tasks, "_probe_web", lambda host, path="": list(state["probe"]))

    def phase1(target, ports=None, credentials=None, profile="lan", **kw):
        calls["phase1"].append((target, profile, credentials))
        return state["phase1_hosts"]
    monkeypatch.setattr(NmapAdapter, "run_detailed_discovery_scan", staticmethod(phase1))

    def nmap_vuln(target, ports=None, credentials=None, profile="lan", **kw):
        calls["nmap_vuln"].append((target, ports))
        return NmapAdapter._parse_nmap_xml(read_fixture("nmap_vuln.xml"))[:1]
    monkeypatch.setattr(NmapAdapter, "run_vulnerability_scan", staticmethod(nmap_vuln))

    from src.scans.adapters.outbound import nuclei_adapter, zap_adapter

    def nuclei(target, ports=None, credentials=None, profile="lan", **kw):
        calls["nuclei"].append(list(target))
        return [{"template_id": "CVE-2021-41773", "name": "Apache 2.4.49 - Path Traversal", "severity": "high",
                 "cvss_score": 7.5, "cve_id": "CVE-2021-41773", "cve_ids": ["CVE-2021-41773"],
                 "matched_at": f"{target[0]}/cgi-bin/x", "host": target[0]}]
    monkeypatch.setattr(nuclei_adapter.NucleiAdapter, "run_scan", staticmethod(nuclei))

    def zap(targets, credentials=None, **kw):
        calls["zap"].append(list(targets))
        return [{"pluginId": "40012", "alert": "Cross Site Scripting (Reflected)", "risk": "High",
                 "confidence": "Medium", "url": f"{targets[0]}/search?q=1", "param": "q"}]
    monkeypatch.setattr(zap_adapter.ZAPAdapter, "run_scan", staticmethod(zap))
    return calls, state


def _run(scan_id, target):
    return scan_tasks.run_vulnerability_scan(scan_id, target, target, "cfg")


def _scan(db, scan_id):
    db.expire_all()
    return db.query(ScanEntity).filter(ScanEntity.id == scan_id).first()


# ----------------------------------------------------------------------------- domains

def test_domain_scan_with_nuclei_keeps_the_domain(db, make_scan, fakes):
    calls, _ = fakes
    scan_id = make_scan("app.exemple.com", "NUCLEI")
    assert _run(scan_id, "app.exemple.com") is True

    # Nuclei must call the domain (Host header / SNI), never the resolved IP
    assert calls["nuclei"][0][0] == "https://app.exemple.com"
    assert all("203.0.113.10" not in t for t in calls["nuclei"][0])
    assert "app.exemple.com:22" in calls["nuclei"][0]
    assert calls["phase1"][0][1] == "internet"

    asset = db.query(AssetEntity).one()
    assert (asset.ip_address, asset.resolved_ip) == ("app.exemple.com", "203.0.113.10")
    vuln = db.query(VulnerabilityEntity).one()
    assert (vuln.severity, vuln.cvss_base_score, vuln.port, vuln.source_engine) == (VulnSeverity.HIGH, 7.5, 443, "NUCLEI")

    scan = _scan(db, scan_id)
    assert scan.status == ScanStatus.COMPLETED and scan.target_states == {"app.exemple.com": "COMPLETED"}


def test_two_domains_on_the_same_ip_get_their_own_asset(db, make_scan, fakes):
    scan_id = make_scan("site.com,www.site.com", "OWASP_ZAP")
    _run(scan_id, "site.com")
    _run(scan_id, "www.site.com")
    assert sorted(a.ip_address for a in db.query(AssetEntity).all()) == ["site.com", "www.site.com"]
    assert db.query(VulnerabilityEntity).count() == 2
    assert _scan(db, scan_id).status == ScanStatus.COMPLETED


def test_waf_blocking_port_scan_falls_back_to_web_probe(db, make_scan, fakes):
    calls, state = fakes
    state["phase1_hosts"] = [_host(ports=[])]          # every port filtered by the WAF
    state["probe"] = ["https://app.exemple.com"]
    scan_id = make_scan("app.exemple.com", "OWASP_ZAP")
    _run(scan_id, "app.exemple.com")
    assert calls["zap"] == [["https://app.exemple.com"]]
    assert _scan(db, scan_id).target_states["app.exemple.com"] == "COMPLETED"


def test_url_target_scans_exactly_that_url_without_port_sweep(db, make_scan, fakes):
    calls, _ = fakes
    scan_id = make_scan("https://app.exemple.com:8443/portal", "OWASP_ZAP")
    _run(scan_id, "https://app.exemple.com:8443/portal")
    assert calls["phase1"] == []
    assert calls["zap"] == [["https://app.exemple.com:8443/portal"]]
    assert db.query(AssetEntity).one().ip_address == "app.exemple.com"


def test_legacy_asset_with_overwritten_ip_gets_its_domain_back(db, company, make_scan, fakes):
    db.add(AssetEntity(company_id=company.id, name="app.exemple.com", ip_address="203.0.113.10"))
    db.commit()
    scan_id = make_scan("app.exemple.com", "NUCLEI")
    _run(scan_id, "app.exemple.com")
    asset = db.query(AssetEntity).one()
    assert (asset.ip_address, asset.resolved_ip) == ("app.exemple.com", "203.0.113.10")


# ----------------------------------------------------------------------------- honest states

def test_nmap_findings_are_stored_with_real_severity(db, make_scan, fakes):
    scan_id = make_scan("app.exemple.com", "NMAP")
    _run(scan_id, "app.exemple.com")
    vulns = {(v.title, v.port): v for v in db.query(VulnerabilityEntity).all()}
    critical = vulns[("CVE-2021-42013 – Apache httpd 2.4.49", 443)]
    assert critical.severity == VulnSeverity.CRITICAL and critical.cvss_base_score == 9.8
    assert critical.description and "vulners.com" in critical.description
    assert critical.contextual_risk_score == 9.8


def test_no_open_ports_is_reported_not_hidden(db, make_scan, fakes):
    calls, state = fakes
    state["phase1_hosts"] = [_host(ports=[])]
    scan_id = make_scan("app.exemple.com", "NMAP")
    _run(scan_id, "app.exemple.com")
    assert calls["nmap_vuln"] == []
    assert _scan(db, scan_id).target_states["app.exemple.com"] == "NO_OPEN_PORTS"


def test_host_timeout_is_reported(db, make_scan, fakes):
    _, state = fakes
    state["phase1_hosts"] = [_host(ports=[], timed_out=True)]
    scan_id = make_scan("app.exemple.com", "NMAP")
    _run(scan_id, "app.exemple.com")
    scan = _scan(db, scan_id)
    assert scan.target_states["app.exemple.com"] == "TIMEOUT" and scan.status == ScanStatus.FAILED


def test_invalid_target_fails_explicitly(db, make_scan, fakes):
    scan_id = make_scan("ftp://site.com", "NMAP")
    assert _run(scan_id, "ftp://site.com") is False
    scan = _scan(db, scan_id)
    assert scan.target_states["ftp://site.com"] == "INVALID_TARGET" and scan.status == ScanStatus.FAILED


def test_engine_failure_never_falls_back_to_openvas(db, make_scan, fakes, monkeypatch):
    def boom(*a, **kw):
        raise ScanError("nmap crashed")
    monkeypatch.setattr(NmapAdapter, "run_detailed_discovery_scan", staticmethod(boom))
    monkeypatch.setattr(scan_tasks.run_vulnerability_scan, "max_retries", 0)
    monkeypatch.setattr(scan_tasks, "_start_openvas", lambda *a, **kw: pytest.fail("OpenVAS must not be started"))
    scan_id = make_scan("10.0.0.5", "NMAP")
    assert _run(scan_id, "10.0.0.5") is False
    assert _scan(db, scan_id).target_states["10.0.0.5"] == "FAILED"


def test_cidr_results_go_to_each_host(db, make_scan, fakes):
    calls, state = fakes
    state["phase1_hosts"] = [_host("10.0.0.5", None, WEB_PORTS), _host("10.0.0.6", None, WEB_PORTS)]
    scan_id = make_scan("10.0.0.0/24", "NUCLEI")
    _run(scan_id, "10.0.0.0/24")
    assert calls["phase1"][0][1] == "lan"
    assets = {a.ip_address: a for a in db.query(AssetEntity).all()}
    assert set(assets) == {"10.0.0.5", "10.0.0.6"}
    for asset in assets.values():
        assert db.query(VulnerabilityEntity).filter(VulnerabilityEntity.asset_id == asset.id).count() == 1


def test_overall_status():
    assert overall_status({"a": "COMPLETED", "b": "IN_PROGRESS"}) == ScanStatus.IN_PROGRESS
    assert overall_status({"a": "COMPLETED", "b": "FAILED"}) == ScanStatus.COMPLETED
    assert overall_status({"a": "HOST_UNREACHABLE", "b": "FAILED"}) == ScanStatus.FAILED


# ----------------------------------------------------------------------------- storage

def test_rescan_updates_instead_of_duplicating_and_detects_regression(db, make_scan, fakes):
    scan_id = make_scan("app.exemple.com", "NUCLEI")
    _run(scan_id, "app.exemple.com")
    vuln = db.query(VulnerabilityEntity).one()
    vuln.status = VulnStatus.FIXED
    db.commit()

    scan_id2 = make_scan("app.exemple.com", "NUCLEI")
    _run(scan_id2, "app.exemple.com")
    db.expire_all()
    assert db.query(VulnerabilityEntity).count() == 1
    assert db.query(VulnerabilityEntity).one().status == VulnStatus.NEW


def test_findings_never_land_on_a_deleted_or_foreign_asset(db, company, make_scan, fakes):
    from src.companies.domain.entities import CompanyEntity
    other = CompanyEntity(name="Other")
    db.add(other)
    db.commit()
    db.add_all([
        AssetEntity(company_id=company.id, name="old", ip_address="app.exemple.com", is_deleted=True),
        AssetEntity(company_id=other.id, name="theirs", ip_address="app.exemple.com"),
    ])
    db.commit()
    scan_id = make_scan("app.exemple.com", "NUCLEI")
    _run(scan_id, "app.exemple.com")
    vuln = db.query(VulnerabilityEntity).one()
    asset = db.query(AssetEntity).filter(AssetEntity.id == vuln.asset_id).one()
    assert asset.company_id == company.id and not asset.is_deleted


def test_openvas_report_is_stored_per_host(db, make_scan):
    from src.vulnerabilities.application.services.tasks import parse_scan_report
    scan_id = make_scan("10.0.0.0/24", "OPENVAS")
    parse_scan_report(read_fixture("openvas_report.xml"), "10.0.0.0/24", scan_id, "INTERRUPTED")
    assets = {a.ip_address: a for a in db.query(AssetEntity).all()}
    assert set(assets) == {"10.0.0.5", "10.0.0.6"}
    assert db.query(VulnerabilityEntity).filter(VulnerabilityEntity.asset_id == assets["10.0.0.5"].id).count() == 2
    scan = _scan(db, scan_id)
    assert scan.target_states["10.0.0.0/24"] == "INTERRUPTED" and scan.status == ScanStatus.FAILED
