import pytest
from src.scans.domain.targets import (
    parse_target, validate_targets, InvalidTargetError, web_urls_from_ports, split_targets,
)


@pytest.mark.parametrize("raw,host,kind", [
    ("site.com", "site.com", "hostname"),
    ("WWW.Site.com/", "www.site.com", "hostname"),
    ("10.0.0.5", "10.0.0.5", "ip"),
    ("10.0.0.0/24", "10.0.0.0/24", "cidr"),
    ("2001:db8::1", "2001:db8::1", "ip"),
])
def test_bare_targets(raw, host, kind):
    t = parse_target(raw)
    assert (t.host, t.kind, t.is_url) == (host, kind, False)


def test_url_target_keeps_hostname_port_and_path():
    t = parse_target("https://App.site.com:8443/portal/")
    assert (t.host, t.kind, t.scheme, t.port, t.path) == ("app.site.com", "hostname", "https", 8443, "/portal")
    assert t.url == "https://app.site.com:8443/portal"


def test_url_default_port():
    t = parse_target("https://site.com")
    assert t.port == 443 and t.url == "https://site.com"


@pytest.mark.parametrize("raw", [
    "ftp://site.com", "https://user:pass@site.com", "site.com:8443", "site.com/app",
    "-oX /tmp/x", "10.0.0.0/8", "bad_host!", "",
])
def test_invalid_targets(raw):
    with pytest.raises(InvalidTargetError):
        parse_target(raw)


def test_validate_targets_reports_every_error():
    with pytest.raises(InvalidTargetError) as exc:
        validate_targets("site.com, bad_host!, ftp://x.com")
    assert "bad_host!" in str(exc.value) and "ftp" in str(exc.value)


def test_split_targets_removes_blanks_and_duplicates():
    assert split_targets("site.com, www.site.com,,site.com") == ["site.com", "www.site.com"]


@pytest.mark.parametrize("raw", [
    "site.com,www.site.com", "site.com, www.site.com", "site.com ,  www.site.com",
    "site.com www.site.com", "site.com;www.site.com", "site.com\nwww.site.com", " site.com\r\n www.site.com ,",
])
def test_every_usual_separator_is_accepted(raw):
    assert [t.host for t in validate_targets(raw)] == ["site.com", "www.site.com"]


def test_private_vs_public_profile():
    assert parse_target("192.168.1.0/24").is_private
    assert not parse_target("8.8.8.8").is_private
    assert not parse_target("site.com").is_private


def test_web_urls_keep_the_domain_and_detect_cdn_ports():
    ports = [
        {"port": 443, "state": "open", "service": "http", "tunnel": "ssl"},
        {"port": 8080, "state": "open", "service": "http-proxy"},
        {"port": 80, "state": "open", "service": "tcpwrapped"},
        {"port": 22, "state": "open", "service": "ssh"},
        {"port": 8443, "state": "filtered", "service": "https-alt"},
    ]
    assert web_urls_from_ports("site.com", ports) == [
        "https://site.com", "http://site.com:8080", "http://site.com",
    ]


def test_perimeter_guard(monkeypatch):
    from src.scans.domain.targets import check_allowed, TargetNotAllowedError
    monkeypatch.setenv("SCAN_ALLOWED_TARGETS", "10.0.0.0/24, *.lab.internal, scanme.example.com")
    # allowed
    check_allowed(validate_targets("10.0.0.5", enforce_perimeter=False))
    check_allowed(validate_targets("10.0.0.0/28", enforce_perimeter=False))
    check_allowed(validate_targets("app.lab.internal", enforce_perimeter=False))
    check_allowed(validate_targets("https://app.lab.internal:8443/x", enforce_perimeter=False))
    check_allowed(validate_targets("scanme.example.com", enforce_perimeter=False))
    # refused
    for bad in ["8.8.8.8", "10.0.1.5", "evil.com", "lab.internal.evil.com", "10.0.0.0/16"]:
        with pytest.raises(TargetNotAllowedError):
            check_allowed(validate_targets(bad, enforce_perimeter=False))


def test_no_perimeter_means_everything_allowed(monkeypatch):
    monkeypatch.delenv("SCAN_ALLOWED_TARGETS", raising=False)
    from src.scans.domain.targets import check_allowed
    check_allowed(validate_targets("8.8.8.8", enforce_perimeter=False))  # no raise
