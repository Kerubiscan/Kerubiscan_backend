"""Scan -> stored findings -> HTML and PDF reports, for IPs, domains, several domains and networks.

The scanner binaries are simulated (see test_scan_pipeline.fakes); the report endpoints and the
real HTML (Jinja2) and PDF (ReportLab) generators are executed.
"""
import asyncio
import io

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("reportlab")
pypdf = pytest.importorskip("pypdf")

from test_scan_pipeline import fakes, _host, WEB_PORTS  # noqa: F401,E402  (fixture re-used)
from src.scans.application.services import tasks as scan_tasks  # noqa: E402
from src.scans.adapters.inbound.api import endpoints  # noqa: E402

USER = {"sub": "u1", "preferred_username": "analyst", "realm_access": {"roles": ["Security Analyst"]}}


def _body(response) -> bytes:
    async def collect():
        return b"".join([chunk async for chunk in response.body_iterator])
    return asyncio.run(collect())


def _html_report(db, scan_id) -> str:
    return _body(endpoints.download_scan_report(scan_id, db=db, current_user=USER)).decode("utf-8")


def _pdf_text(db, scan_id) -> str:
    response = endpoints.download_scan_report_pdf(scan_id, endpoints.PdfReportRequest(), db=db, current_user=USER)
    reader = pypdf.PdfReader(io.BytesIO(_body(response)))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def _scan(db, make_scan, target, engine):
    scan_id = make_scan(target, engine)
    for t in target.split(","):
        scan_tasks.run_vulnerability_scan(scan_id, t, t, "cfg")
    return scan_id


def test_domain_scan_findings_reach_html_and_pdf_reports(db, make_scan, fakes):  # noqa: F811
    scan_id = _scan(db, make_scan, "app.exemple.com", "NMAP")

    html = _html_report(db, scan_id)
    assert "app.exemple.com" in html
    assert "CVE-2021-42013" in html and "Critical" in html          # CVSS 9.8 from vulners
    assert "The Heartbleed Bug" in html                              # VULNERABLE block

    pdf = _pdf_text(db, scan_id)
    assert "CVE-2021-42013" in pdf and "app.exemple.com" in pdf


def test_ip_scan_findings_reach_reports(db, make_scan, fakes):  # noqa: F811
    _, state = fakes
    state["phase1_hosts"] = [_host("10.0.0.5", None, WEB_PORTS)]
    scan_id = _scan(db, make_scan, "10.0.0.5", "NUCLEI")

    html = _html_report(db, scan_id)
    assert "10.0.0.5" in html and "Apache 2.4.49 - Path Traversal" in html
    assert "Apache 2.4.49 - Path Traversal" in _pdf_text(db, scan_id)


def test_two_domains_on_same_ip_both_appear_in_the_reports(db, make_scan, fakes):  # noqa: F811
    scan_id = _scan(db, make_scan, "site.com,www.site.com", "OWASP_ZAP")

    html = _html_report(db, scan_id)
    assert "https://site.com/search" in html and "https://www.site.com/search" in html
    pdf = _pdf_text(db, scan_id)
    assert "Cross Site Scripting" in pdf and "www.site.com" in pdf and "site.com" in pdf


def test_network_scan_lists_each_host_in_the_reports(db, make_scan, fakes):  # noqa: F811
    _, state = fakes
    state["phase1_hosts"] = [_host("10.0.0.5", None, WEB_PORTS), _host("10.0.0.6", None, WEB_PORTS)]
    scan_id = _scan(db, make_scan, "10.0.0.0/24", "NUCLEI")

    html = _html_report(db, scan_id)
    assert "10.0.0.5" in html and "10.0.0.6" in html
    pdf = _pdf_text(db, scan_id)
    assert "10.0.0.5" in pdf and "10.0.0.6" in pdf


def test_report_of_one_company_never_shows_another_company(db, company, make_scan, fakes):  # noqa: F811
    from src.companies.domain.entities import CompanyEntity
    from src.scans.domain.entities import ScanEntity, ScanType, ScanStatus, ScannerEngine
    _, state = fakes
    state["phase1_hosts"] = [_host("10.0.0.5", None, WEB_PORTS)]
    _scan(db, make_scan, "10.0.0.5", "NUCLEI")              # company ACME has a finding on 10.0.0.5

    other = CompanyEntity(name="Other")
    db.add(other)
    db.commit()
    other_scan = ScanEntity(company_id=other.id, name="other", target="10.0.0.0/24", scan_type=ScanType.VULNERABILITY,
                            scanner_engine=ScannerEngine.NUCLEI, status=ScanStatus.COMPLETED, target_states={})
    db.add(other_scan)
    db.commit()
    assert "Apache 2.4.49 - Path Traversal" not in _pdf_text(db, other_scan.id)


# ----------------------------------------------------------------------------- PDF = HTML


def _chromium_available() -> bool:
    try:
        from src.reporting.application.services.pdf_renderer import html_to_pdf
        html_to_pdf("<html><body>ok</body></html>")
        return True
    except Exception:
        return False


needs_chromium = pytest.mark.skipif(not _chromium_available(), reason="Chromium (playwright install chromium) not available")


@needs_chromium
def test_pdf_is_the_print_rendering_of_the_html_report(db, make_scan, fakes):  # noqa: F811
    scan_id = _scan(db, make_scan, "app.exemple.com", "NMAP")
    response = endpoints.download_scan_report_pdf(scan_id, endpoints.PdfReportRequest(), db=db, current_user=USER)
    reader = pypdf.PdfReader(io.BytesIO(_body(response)))
    producer = str(reader.metadata.get("/Producer", "")) + str(reader.metadata.get("/Creator", ""))
    assert "Skia" in producer or "Chromium" in producer          # printed by Chromium, not ReportLab
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    # Same content as the HTML report, including the detail rows that are collapsed on screen
    for expected in ("CVE-2021-42013", "CVE-2023-38408", "The Heartbleed Bug", "vulners.com/cve/CVE-2021-42013"):
        assert expected in text


def test_target_controlled_content_is_escaped_in_the_report(db, company):
    """A scanned site must not be able to inject HTML/JavaScript into the report (stored XSS)."""
    from src.assets.domain.entities import AssetEntity
    from src.vulnerabilities.domain.entities import VulnerabilityEntity
    from src.vulnerabilities.domain.models import VulnSeverity
    from src.reporting.application.services.html_generator import generate_vulnerability_html
    asset = AssetEntity(company_id=company.id, name="evil.com", ip_address="evil.com")
    db.add(asset)
    db.commit()
    vuln = VulnerabilityEntity(asset_id=asset.id, title="<img src=x onerror=alert(1)>", severity=VulnSeverity.HIGH,
                               description="preuve : <script>alert(document.cookie)</script>", source_engine="OWASP_ZAP")
    db.add(vuln)
    db.commit()
    html = generate_vulnerability_html(assets=[asset], all_vulnerabilities={asset.id: [vuln]},
                                       executive_summary=None).decode("utf-8")
    assert "<script>alert(document.cookie)</script>" not in html and "<img src=x onerror" not in html
    assert "&lt;script&gt;alert(document.cookie)&lt;/script&gt;" in html


def test_pdf_falls_back_to_legacy_layout_when_chromium_is_missing(monkeypatch):
    from src.reporting.application.services import pdf_renderer

    def no_chromium(html):
        raise pdf_renderer.PdfRenderingError("no browser")
    monkeypatch.setattr(pdf_renderer, "html_to_pdf", no_chromium)
    assert pdf_renderer.render_pdf("<html></html>", fallback=lambda: b"%PDF-legacy") == b"%PDF-legacy"
