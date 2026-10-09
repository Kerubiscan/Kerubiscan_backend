import os
import base64
import shutil
import signal
import socket
import subprocess
import tempfile
import logging
import re
import time
import secrets
import requests
import urllib3
from html import unescape
from typing import Callable, List, Dict, Optional, Union
from urllib.parse import urlsplit
from src.scans.adapters.outbound.base_adapter import ScanError, _register, _unregister, kill_session
from src.vulnerabilities.domain import severity as sev

logger = logging.getLogger(__name__)

ZAP_BIN = "/usr/local/bin/zap"

_TAG = re.compile(r"<[^>]+>")


def _clean(html: str) -> str:
    """Removes HTML tags and unescapes entities from ZAP descriptions."""
    return unescape(_TAG.sub("", html or "")).strip()


# Time budgets (minutes). Without them a large site keeps the worker busy for up to 24 h.
SPIDER_MAX_MINUTES = 15
AJAX_SPIDER_MAX_MINUTES = 10
ASCAN_MAX_MINUTES = 90
PASSIVE_SCAN_MAX_S = 300
BOOT_TIMEOUT_S = 300
# Browser of the AJAX spider: Firefox ESR from the image + the geckodriver bundled with ZAP
AJAX_SPIDER_BROWSER = "firefox-headless"
# Browsers opened at once by the AJAX spider (ZAP's default: one per CPU). Each Firefox takes
# 300 MB or more: with 5 of them and ZAP, the 6 GB test server ran out of memory.
AJAX_SPIDER_BROWSERS = 2
# Active scan rules that drive their own browsers: "Cross Site Scripting (DOM Based)" kept up to
# 8 Firefox open during the active scan, and ZAP was killed (connection reset) after 55 min.
BROWSER_SCAN_RULES = "40026"
# Share of each phase in the ZAP progress reported to the scan (the active scan is by far the longest)
PHASE_SPIDER, PHASE_AJAX = 0.10, 0.15


class ZAPAdapter:
    @staticmethod
    def _api(zap_url: str, api_key: str, path: str, **params) -> Dict:
        resp = requests.get(f"{zap_url}{path}", params={"apikey": api_key, **params}, timeout=60)
        try:
            data = resp.json()
        except ValueError:
            raise ScanError(f"ZAP API {path} returned non JSON (HTTP {resp.status_code})")
        if resp.status_code != 200 or "code" in data and "message" in data:
            raise ScanError(f"ZAP API {path} error: {data}")
        return data

    @staticmethod
    def _wait(zap_url: str, api_key: str, kind: str, scan_id: str, deadline: float, poll_s: int,
              on_status: Optional[Callable[[int], None]] = None) -> bool:
        """Polls spider/ascan status. Returns False (and stops the scan) when the deadline is exceeded."""
        while True:
            status = ZAPAdapter._api(zap_url, api_key, f"/JSON/{kind}/view/status/", scanId=scan_id).get("status")
            if on_status and str(status).isdigit():
                on_status(int(status))
            if status == "100":
                return True
            if time.time() > deadline:
                logger.warning(f"ZAP {kind} {scan_id} exceeded its time budget, stopping it (partial results kept)")
                try:
                    ZAPAdapter._api(zap_url, api_key, f"/JSON/{kind}/action/stop/", scanId=scan_id)
                except ScanError:
                    pass
                return False
            time.sleep(poll_s)

    @staticmethod
    def _ajax_spider(zap_url: str, api_key: str, target: str, minutes: int,
                     on_fraction: Optional[Callable[[float], None]] = None) -> None:
        """Explores the target in a real browser. The classic spider only follows links in the HTML:
        on a JavaScript application (Angular, React...) it finds the static files but none of the API
        calls, so the active scan had no parameter to attack (Juice Shop: CSP/CORS alerts only).
        Never fatal: without a browser the scan goes on with the classic spider's results."""
        try:
            ZAPAdapter._api(zap_url, api_key, "/JSON/ajaxSpider/action/setOptionBrowserId/", String=AJAX_SPIDER_BROWSER)
            ZAPAdapter._api(zap_url, api_key, "/JSON/ajaxSpider/action/setOptionNumberOfBrowsers/",
                            Integer=AJAX_SPIDER_BROWSERS)
            ZAPAdapter._api(zap_url, api_key, "/JSON/ajaxSpider/action/setOptionMaxDuration/", Integer=minutes)
            ZAPAdapter._api(zap_url, api_key, "/JSON/ajaxSpider/action/scan/", url=target)
        except ScanError as e:
            logger.warning(f"ZAP AJAX spider unavailable on {target}, classic spider only: {e}")
            return
        started = time.time()
        deadline = started + minutes * 60 + 60
        while ZAPAdapter._api(zap_url, api_key, "/JSON/ajaxSpider/view/status/").get("status") == "running":
            if on_fraction:   # the AJAX spider reports no percentage: share of its time budget used
                on_fraction(min((time.time() - started) / (minutes * 60), 1.0))
            if time.time() > deadline:
                logger.warning(f"ZAP AJAX spider on {target} exceeded its time budget, stopping it")
                try:
                    ZAPAdapter._api(zap_url, api_key, "/JSON/ajaxSpider/action/stop/")
                except ScanError:
                    pass
                break
            time.sleep(5)
        found = ZAPAdapter._api(zap_url, api_key, "/JSON/ajaxSpider/view/numberOfResults/").get("numberOfResults", "?")
        logger.info(f"ZAP AJAX spider on {target}: {found} requests found")

    @staticmethod
    def _wait_passive_scan(zap_url: str, api_key: str) -> None:
        """Alerts read while the passive scanner still has records queued would be missing."""
        deadline = time.time() + PASSIVE_SCAN_MAX_S
        while time.time() < deadline:
            left = ZAPAdapter._api(zap_url, api_key, "/JSON/pscan/view/recordsToScan/").get("recordsToScan", "0")
            if str(left) == "0":
                return
            time.sleep(3)
        logger.warning("ZAP passive scan still running after its time budget, reading the alerts found so far")

    @staticmethod
    def run_scan(targets: Union[str, List[str]], credentials: Dict = None,
                 spider_minutes: int = SPIDER_MAX_MINUTES, ascan_minutes: int = ASCAN_MAX_MINUTES,
                 ajax_minutes: int = AJAX_SPIDER_MAX_MINUTES,
                 on_progress: Optional[Callable[[float], None]] = None) -> List[Dict]:
        """Runs ZAP spider + active scan on a list of URLs and returns the raw alerts.

        on_progress receives the real progress of ZAP's work, from 0 to 1 (spider, AJAX spider,
        then the active scan status reported by ZAP).

        Every target must be a full URL (scheme://host[:port][/path]) so ZAP keeps the
        original hostname (Host header, SNI, virtual hosts).
        """
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.split(",") if t.strip()]
        target_list = [t for t in targets if t.startswith(("http://", "https://"))]
        if not target_list:
            return []

        logger.info(f"Running OWASP ZAP on {len(target_list)} URL(s): {target_list}")

        zap_home_dir = tempfile.mkdtemp(prefix="zap_home_")
        proc = None
        log_handle = None
        api_key = secrets.token_hex(16)

        try:
            os.environ["NO_PROXY"] = "127.0.0.1,localhost"
            os.environ["no_proxy"] = "127.0.0.1,localhost"
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', 0))
                free_port = s.getsockname()[1]

            # -silent: no unsolicited request at startup (update check, news, telemetry). Without it
            # the API answered only after ~160 s on the test server, then not within 180 s at all.
            cmd = [ZAP_BIN, "-daemon", "-silent", "-host", "127.0.0.1", "-dir", zap_home_dir,
                   "-port", str(free_port), "-config", f"api.key={api_key}"]

            c_type = str((credentials or {}).get("credential_type", "")).upper()
            basic_auth_b64 = None
            if credentials and c_type in ("HTTP", "HTTP_BASIC"):
                user = credentials.get("username", "")
                pwd = credentials.get("password", "")
                if user or pwd:
                    # Kept for after startup: set via the local API, never on the command line (ps)
                    basic_auth_b64 = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("utf-8")
            elif credentials:
                logger.warning(f"ZAP: credential of type {c_type or 'UNKNOWN'} not usable by ZAP, scan runs unauthenticated")

            env = os.environ.copy()
            env["_JAVA_OPTIONS"] = "-Xmx1g -Xms256m"

            # ZAP output goes to a file: an unread PIPE fills up and freezes the JVM.
            log_path = os.path.join(zap_home_dir, "zap_stdout.log")
            log_handle = open(log_path, "w", encoding="utf-8", errors="replace")
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log_handle, stderr=subprocess.STDOUT,
                                    env=env, start_new_session=True)
            _register(proc)  # killed on worker shutdown like any scanner process

            zap_url = f"http://127.0.0.1:{free_port}"
            boot_deadline = time.time() + BOOT_TIMEOUT_S
            while True:
                if proc.poll() is not None:
                    raise ScanError(f"ZAP exited during startup (code {proc.returncode}): {ZAPAdapter._tail(log_path)}")
                try:
                    ZAPAdapter._api(zap_url, api_key, "/JSON/core/view/version/")
                    break
                except Exception:
                    if time.time() > boot_deadline:
                        raise ScanError(f"ZAP did not start within {BOOT_TIMEOUT_S}s: {ZAPAdapter._tail(log_path)}")
                    time.sleep(2)

            ZAPAdapter._api(zap_url, api_key, "/JSON/spider/action/setOptionMaxDuration/", Integer=spider_minutes)
            ZAPAdapter._api(zap_url, api_key, "/JSON/ascan/action/setOptionMaxScanDurationInMins/", Integer=ascan_minutes)
            if basic_auth_b64:
                # Added via the local API (goes over localhost HTTP, not the process cmdline).
                # matchRegex is required by the replacer addRule endpoint; without it the call errors
                # and would fail the whole authenticated scan.
                try:
                    ZAPAdapter._api(zap_url, api_key, "/JSON/replacer/action/addRule/",
                                    description="auth1", enabled="true", matchType="REQ_HEADER",
                                    matchString="Authorization", matchRegex="false",
                                    replacement=f"Basic {basic_auth_b64}")
                    logger.info("ZAP: authenticated scan enabled (HTTP Basic)")
                except ScanError as e:
                    # Degrade gracefully: scan unauthenticated rather than fail entirely
                    logger.error(f"ZAP: could not set authentication, scanning unauthenticated: {e}")
            try:
                ZAPAdapter._api(zap_url, api_key, "/JSON/ascan/action/disableScanners/", ids=BROWSER_SCAN_RULES)
            except ScanError as e:
                logger.warning(f"ZAP: browser-driven scan rules could not be disabled: {e}")
            logger.info("ZAP daemon ready")

            def report(fraction: float) -> None:
                if on_progress:
                    try:
                        on_progress(min(max(fraction, 0.0), 1.0))
                    except Exception as e:   # progress display must never stop the scan
                        logger.warning(f"ZAP progress not recorded: {e}")

            n = len(target_list)
            reached = []
            for k, target in enumerate(target_list):
                try:
                    ZAPAdapter._api(zap_url, api_key, "/JSON/core/action/accessUrl/", url=target, followRedirects="true")
                except ScanError as e:
                    logger.warning(f"ZAP could not reach {target}: {e}")
                    continue
                spider_id = ZAPAdapter._api(zap_url, api_key, "/JSON/spider/action/scan/", url=target).get("scan")
                if spider_id is not None:
                    ZAPAdapter._wait(zap_url, api_key, "spider", spider_id, time.time() + spider_minutes * 60 + 60, 2,
                                     on_status=lambda st, k=k: report(PHASE_SPIDER * (k + st / 100) / n))
                if ajax_minutes:
                    ZAPAdapter._ajax_spider(zap_url, api_key, target, ajax_minutes,
                                            on_fraction=lambda f, k=k: report(PHASE_SPIDER + PHASE_AJAX * (k + f) / n))
                reached.append(target)
            report(PHASE_SPIDER + PHASE_AJAX)

            if not reached:
                raise ScanError(f"ZAP n'a pu joindre aucune URL : {target_list}")

            ascan_ids = []
            for target in reached:
                try:
                    ascan_ids.append(ZAPAdapter._api(zap_url, api_key, "/JSON/ascan/action/scan/", url=target, recurse="true").get("scan"))
                except ScanError as e:
                    logger.warning(f"ZAP active scan could not start on {target}: {e}")
            deadline = time.time() + ascan_minutes * 60 + 120
            started_ids = [i for i in ascan_ids if i is not None]
            base = PHASE_SPIDER + PHASE_AJAX
            for j, ascan_id in enumerate(started_ids):
                ZAPAdapter._wait(zap_url, api_key, "ascan", ascan_id, deadline, 10,
                                 on_status=lambda st, j=j: report(base + (1 - base) * (j + st / 100) / len(started_ids)))
            report(1.0)
            ZAPAdapter._wait_passive_scan(zap_url, api_key)

            # All alerts, kept when they belong to a scanned host: filtering by base URL lost the
            # alerts of http:// targets redirected to https://
            alerts = alerts_for_hosts(ZAPAdapter._api(zap_url, api_key, "/JSON/core/view/alerts/").get("alerts", []), reached)
            logger.info(f"ZAP finished: {len(alerts)} alert instances on {len(reached)} URL(s)")

            try:
                ZAPAdapter._api(zap_url, api_key, "/JSON/core/action/shutdown/")
                proc.wait(timeout=30)
            except Exception:
                pass
            return alerts

        except ScanError:
            raise
        except Exception as e:
            raise ScanError(f"ZAP scan failed: {e}") from e
        finally:
            if proc:
                _unregister(proc)
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                        # Reaped here, or it stays a <defunct> java process as long as the worker lives
                        proc.wait(timeout=10)
                    except Exception:
                        pass
                # Browsers have their own process groups and outlived ZAP (8 Firefox left after a crash)
                left = kill_session(proc.pid)
                if left:
                    logger.warning(f"ZAP: {left} leftover process(es) of the scan killed (browsers)")
            if log_handle:
                log_handle.close()
            shutil.rmtree(zap_home_dir, ignore_errors=True)

    @staticmethod
    def _tail(path: str, size: int = 1500) -> str:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read()[-size:]
        except OSError:
            return ""

    @staticmethod
    def _parse_zap_alerts(alerts: List[Dict]) -> List[Dict]:
        """Kept for compatibility: returns the normalised findings."""
        return normalize_zap(alerts)


def alerts_for_hosts(alerts: List[Dict], targets: List[str]) -> List[Dict]:
    hosts = {(urlsplit(t).hostname or "").lower() for t in targets}
    return [a for a in alerts if (urlsplit(a.get("url", a.get("uri", "")) or "").hostname or "").lower() in hosts]


def _risk(alert: Dict) -> str:
    risk = str(alert.get("risk", alert.get("riskcode", "0")))
    if risk.isdigit():
        return {"3": "high", "2": "medium", "1": "low"}.get(risk, "info")
    return risk


def normalize_zap(alerts: List[Dict], max_evidence: int = 20) -> List[Dict]:
    """One finding per (ZAP rule, port); the affected URLs are kept as evidence."""
    grouped: Dict[tuple, Dict] = {}
    for alert in alerts:
        confidence = str(alert.get("confidence", "")).lower()
        if confidence in ("false positive", "0"):
            continue
        url = alert.get("url", alert.get("uri", "")) or ""
        parts = urlsplit(url) if url else None
        port = (parts.port or {"http": 80, "https": 443}.get(parts.scheme)) if parts else None
        plugin = alert.get("pluginId", alert.get("pluginid", "unknown"))
        key = (plugin, alert.get("alert", alert.get("name")), port)
        f = grouped.get(key)
        if f is None:
            cwe = alert.get("cweid")
            refs = _clean(alert.get("reference", ""))
            desc = _clean(alert.get("description", alert.get("desc", "")))
            if cwe and cwe not in ("-1", "0"):
                desc += f"\nCWE-{cwe}"
            if refs:
                desc += f"\nRéférences :\n{refs}"
            f = grouped[key] = {
                "rule_id": f"zap:{plugin}",
                "title": (alert.get("alert") or alert.get("name") or "ZAP Finding")[:250],
                "severity": sev.resolve(_risk(alert)).value,
                "cvss": None,
                "cve_id": None,
                "cve_ids": [],
                "description": desc,
                "remediation": _clean(alert.get("solution", "")),
                "port": port,
                "service": parts.scheme if parts else None,
                "evidence": [],
                "confidence": alert.get("confidence"),
            }
        if url and len(f["evidence"]) < max_evidence:
            item = url
            if alert.get("param"):
                item += f" (paramètre : {alert['param']})"
            if alert.get("evidence"):
                item += f" — preuve : {str(alert['evidence'])[:200]}"
            if item not in f["evidence"]:
                f["evidence"].append(item)
    return list(grouped.values())
