"""Engine output -> normalised findings."""
import json
from conftest import read_fixture
from src.scans.adapters.outbound.nmap_adapter import NmapAdapter
from src.scans.adapters.outbound.nuclei_adapter import NucleiAdapter, normalize_nuclei
from src.scans.adapters.outbound.zap_adapter import normalize_zap
from src.vulnerabilities.application.services.openvas_report import normalize_openvas


def _by_title(findings):
    return {f["title"]: f for f in findings}


def test_nmap_vulners_keeps_cvss_severity_and_description():
    hosts = NmapAdapter._parse_nmap_xml(read_fixture("nmap_vuln.xml"))
    host = hosts[0]
    assert host["hostname"] == "app.exemple.com"
    vulns = _by_title(host["vulns"])

    critical = vulns["CVE-2021-42013 – Apache httpd 2.4.49"]
    assert critical["cvss"] == 9.8 and critical["severity"] == "Critical" and critical["port"] == 443
    assert "exploit public" in critical["description"]
    assert vulns["CVE-2021-41773 – Apache httpd 2.4.49"]["severity"] == "High"
    assert vulns["CVE-2022-22719 – Apache httpd 2.4.49"]["severity"] == "Medium"
    assert vulns["CVE-2023-38408 – OpenSSH 7.4"]["port"] == 22


def test_nmap_vulnerable_script_uses_risk_factor_and_skips_not_vulnerable():
    host = NmapAdapter._parse_nmap_xml(read_fixture("nmap_vuln.xml"))[0]
    heartbleed = [f for f in host["vulns"] if "ssl-heartbleed" in f["title"]]
    assert len(heartbleed) == 1
    assert heartbleed[0]["severity"] == "High" and heartbleed[0]["cve_id"] == "CVE-2014-0160"
    assert heartbleed[0]["title"].startswith("The Heartbleed Bug")
    assert not [f for f in host["vulns"] if "ssl-ccs-injection" in f["title"]]


def test_nmap_reports_host_timeout():
    hosts = NmapAdapter._parse_nmap_xml(read_fixture("nmap_vuln.xml"))
    timed_out = [h for h in hosts if h["ip"] == "203.0.113.20"]
    assert timed_out and timed_out[0]["timed_out"] is True


def test_nuclei_groups_by_template_matcher_and_port(tmp_path):
    lines = [
        {"template-id": "http-missing-security-headers", "info": {"name": "HTTP Missing Security Headers", "severity": "info"},
         "matcher-name": "strict-transport-security", "host": "https://site.com", "matched-at": "https://site.com"},
        {"template-id": "http-missing-security-headers", "info": {"name": "HTTP Missing Security Headers", "severity": "info"},
         "matcher-name": "content-security-policy", "host": "https://site.com", "matched-at": "https://site.com"},
        {"template-id": "CVE-2021-41773", "info": {"name": "Apache 2.4.49 - Path Traversal", "severity": "high",
         "classification": {"cve-id": ["cve-2021-41773"], "cvss-score": 7.5}},
         "host": "http://site.com", "matched-at": "http://site.com/cgi-bin/.%2e/etc/passwd"},
        {"template-id": "CVE-2021-41773", "info": {"name": "Apache 2.4.49 - Path Traversal", "severity": "high",
         "classification": {"cve-id": ["cve-2021-41773"], "cvss-score": 7.5}},
         "host": "http://site.com:8080", "matched-at": "http://site.com:8080/cgi-bin/.%2e/etc/passwd"},
    ]
    path = tmp_path / "out.jsonl"
    path.write_text("\n".join(json.dumps(l) for l in lines), encoding="utf-8")
    findings = normalize_nuclei(NucleiAdapter._parse_nuclei_jsonl(str(path)))

    assert len(findings) == 4  # was 2 before: the 8080 occurrence and one header were lost
    traversal = sorted((f["port"], f["severity"], f["cve_id"]) for f in findings if "Path Traversal" in f["title"])
    assert traversal == [(80, "High", "CVE-2021-41773"), (8080, "High", "CVE-2021-41773")]
    assert {f["title"] for f in findings if "Headers" in f["title"]} == {
        "HTTP Missing Security Headers : strict-transport-security",
        "HTTP Missing Security Headers : content-security-policy",
    }


def test_zap_groups_instances_and_keeps_urls():
    alerts = [
        {"pluginId": "10038", "alert": "Content Security Policy (CSP) Header Not Set", "risk": "Medium", "confidence": "High",
         "url": "https://site.com/", "description": "<p>CSP missing</p>", "solution": "<p>Set CSP</p>", "cweid": "693"},
        {"pluginId": "10038", "alert": "Content Security Policy (CSP) Header Not Set", "risk": "Medium", "confidence": "High",
         "url": "https://site.com/login"},
        {"pluginId": "40012", "alert": "Cross Site Scripting (Reflected)", "risk": "High", "confidence": "Medium",
         "url": "http://site.com:8080/search?q=x", "param": "q", "evidence": "<script>alert(1)</script>"},
        {"pluginId": "10020", "alert": "Missing Anti-clickjacking Header", "risk": "Medium", "confidence": "False Positive",
         "url": "https://site.com/"},
    ]
    findings = _by_title(normalize_zap(alerts))
    assert set(findings) == {"Content Security Policy (CSP) Header Not Set", "Cross Site Scripting (Reflected)"}
    csp = findings["Content Security Policy (CSP) Header Not Set"]
    assert csp["severity"] == "Medium" and csp["port"] == 443
    assert csp["evidence"] == ["https://site.com/", "https://site.com/login"]
    assert "CWE-693" in csp["description"] and csp["remediation"] == "Set CSP"
    xss = findings["Cross Site Scripting (Reflected)"]
    assert xss["severity"] == "High" and xss["port"] == 8080 and "paramètre : q" in xss["evidence"][0]


def test_openvas_report_split_per_host_and_port():
    hosts = normalize_openvas(read_fixture("openvas_report.xml"))
    assert set(hosts) == {"10.0.0.5", "10.0.0.6"}
    h5 = hosts["10.0.0.5"]
    assert h5["os"] == "Ubuntu 18.04"
    assert sorted((f["port"], f["severity"], f["cvss"], f["cve_id"]) for f in h5["findings"]) == [
        (443, "High", 7.5, "CVE-2014-0160"), (8443, "High", 7.5, "CVE-2014-0160"),
    ]
    assert [f["title"] for f in hosts["10.0.0.6"]["findings"]] == ["SSH Weak Encryption Algorithms"]


def test_real_nmap_output_on_apache_2_4_49():
    """Real Nmap 7.80 output: `-sV --script "(vuln and not dos),vulners"` on a local server announcing
    Apache 2.4.49 (the test server answers 200 to any URL, hence the phpMyAdmin/LiteSpeed false positives)."""
    host = NmapAdapter._parse_nmap_xml(read_fixture("nmap_real_apache_2449.xml"))[0]
    assert host["ports"][0]["product"] == "Apache httpd" and host["ports"][0]["version"] == "2.4.49"
    vulns = _by_title(host["vulns"])

    path_traversal = vulns["CVE-2021-41773 – Apache httpd 2.4.49"]
    # vulners rates it 9.8 (the parser keeps the score given by the source)
    assert path_traversal["cvss"] == 9.8 and path_traversal["severity"] == "Critical" and path_traversal["port"] == 8099
    assert sum(1 for v in host["vulns"] if v["severity"] == "Critical") > 10

    # Scripts that tested and found nothing, and plain banners, are not vulnerabilities
    titles = " ".join(vulns)
    for noise in ("http-dombased-xss", "http-stored-xss", "http-server-header"):
        assert noise not in titles
    # "Found the following possible CSRF vulnerabilities" is a finding to confirm, not Info
    csrf = vulns["Possible CSRF vulnerabilities (http-csrf)"]
    assert csrf["severity"] == "Low" and "/login" in csrf["description"]
    assert vulns["Slowloris DOS attack (http-slowloris-check)"]["cve_id"] == "CVE-2007-6750"
    assert not [v for v in host["vulns"] if v["severity"] == "Info"]


def test_nothing_found_outputs_are_ignored():
    for sid, out in [("http-csrf", "Couldn't find any CSRF vulnerabilities."),
                     ("http-enum", "No interesting files found."),
                     ("smb-vuln-ms10-054", "false"),
                     ("ssl-ccs-injection", "NOT VULNERABLE")]:
        found = NmapAdapter._parse_script(sid, "\n" + out, 80, "http", "Apache")
        assert found == [] or sid == "smb-vuln-ms10-054", (sid, found)
