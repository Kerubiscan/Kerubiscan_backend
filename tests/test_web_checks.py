"""Web checks against real sockets on 127.0.0.1, shaped like the kimia-technologies.com server:
a firewall accepting every port (tcpwrapped), a silent port, an admin console redirecting to its
login page, and a site whose http:// only redirects to https://."""
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from src.scans.application.services import tasks as scan_tasks


def _serve_http(location=None, status=200):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            if location:
                self.send_header("Location", location.format(port=self.server.server_port))
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _serve_tcp(close_at_once: bool):
    """Accepts connections, then closes them at once (tcpwrapped firewall) or never answers."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    held = []

    def loop():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            if close_at_once:
                conn.close()
            else:
                held.append(conn)
    threading.Thread(target=loop, daemon=True).start()
    return listener


@pytest.fixture(autouse=True)
def short_timeout(monkeypatch):
    monkeypatch.setattr(scan_tasks, "WEB_PROBE_TIMEOUT_S", 2)
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")


def test_a_login_console_answers_http():
    server = _serve_http(location="/login.html", status=307)
    try:
        assert scan_tasks._answers_http(f"http://127.0.0.1:{server.server_port}") is True
    finally:
        server.shutdown()


@pytest.mark.parametrize("close_at_once", [True, False], ids=["tcpwrapped", "silent"])
def test_firewall_ports_give_no_http_answer(close_at_once):
    listener = _serve_tcp(close_at_once)
    try:
        assert scan_tasks._answers_http(f"http://127.0.0.1:{listener.getsockname()[1]}") is False
    finally:
        listener.close()


def test_closed_port_gives_no_http_answer():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    assert scan_tasks._answers_http(f"http://127.0.0.1:{port}") is False


@pytest.mark.parametrize("location,status,expected", [
    ("https://127.0.0.1/", 301, True),                 # http:// only sends to the https:// site
    ("https://127.0.0.1/accueil", 302, True),
    ("https://autre-site.exemple/", 301, False),        # another host: a different site
    ("/login.html", 307, False),                        # stays on http://
    (None, 200, False),                                 # a page of its own
])
def test_http_redirect_to_the_https_site(location, status, expected):
    server = _serve_http(location=location, status=status)
    try:
        assert scan_tasks._redirects_to_https(f"http://127.0.0.1:{server.server_port}") is expected
    finally:
        server.shutdown()


def test_unreachable_http_is_not_taken_for_a_redirect():
    listener = _serve_tcp(close_at_once=True)
    try:
        assert scan_tasks._redirects_to_https(f"http://127.0.0.1:{listener.getsockname()[1]}") is False
    finally:
        listener.close()


def test_only_the_ports_answering_http_reach_zap(monkeypatch):
    """_confirmed_web_urls on real sockets: unidentified ports on web port numbers are checked."""
    import src.scans.domain.targets as targets
    console = _serve_http(location="/login.html", status=307)
    wrapped = _serve_tcp(close_at_once=True)
    silent = _serve_tcp(close_at_once=False)
    ports = [{"port": console.server_port, "state": "open", "service": "tcpwrapped"},
             {"port": wrapped.getsockname()[1], "state": "open", "service": "tcpwrapped"},
             {"port": silent.getsockname()[1], "state": "open", "service": "unknown"}]
    # The real ports are random: they stand for common web ports, as 8080/8000/8888 would
    common = {p["port"] for p in ports}
    original = targets.is_web_service

    def is_web_service(name, tunnel=None, port=None):
        return original(name, tunnel) or (port is not None and int(port) in common and name in ("tcpwrapped", "unknown"))
    monkeypatch.setattr(targets, "is_web_service", is_web_service)
    monkeypatch.setattr(scan_tasks, "is_web_service", is_web_service)
    try:
        assert scan_tasks._confirmed_web_urls("127.0.0.1", ports) == [f"http://127.0.0.1:{console.server_port}"]
    finally:
        console.shutdown()
        wrapped.close()
        silent.close()
