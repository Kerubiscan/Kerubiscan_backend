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
from typing import List, Dict, Union
from urllib.parse import urlsplit
from src.scans.adapters.outbound.base_adapter import ScanError, _register, _unregister
from src.vulnerabilities.domain import severity as sev

logger = logging.getLogger(__name__)

ZAP_BIN = "/usr/local/bin/zap"

_TAG = re.compile(r"<[^>]+>")


def _clean(html: str) -> str:
    """Removes HTML tags and unescapes entities from ZAP descriptions."""
    return unescape(_TAG.sub("", html or "")).strip()


# Time budgets (minutes). Without them a large site keeps the worker busy for up to 24 h.
SPIDER_MAX_MINUTES = 15
ASCAN_MAX_MINUTES = 90
BOOT_TIMEOUT_S = 180


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
    def _wait(zap_url: str, api_key: str, kind: str, scan_id: str, deadline: float, poll_s: int) -> bool:
        """Polls spider/ascan status. Returns False (and stops the scan) when the deadline is exceeded."""
        while True:
            status = ZAPAdapter._api(zap_url, api_key, f"/JSON/{kind}/view/status/", scanId=scan_id).get("status")
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
    def run_scan(targets: Union[str, List[str]], credentials: Dict = None,
                 spider_minutes: int = SPIDER_MAX_MINUTES, ascan_minutes: int = ASCAN_MAX_MINUTES) -> List[Dict]:
        """Runs ZAP spider + active scan on a list of URLs and returns the raw alerts.

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

            cmd = [ZAP_BIN, "-daemon", "-host", "127.0.0.1", "-dir", zap_home_dir,
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
                # Added via the local API (goes over localhost HTTP, not the process cmdline)
                ZAPAdapter._api(zap_url, api_key, "/JSON/replacer/action/addRule/",
                                description="auth1", enabled="true", matchType="REQ_HEADER",
                                matchString="Authorization", replacement=f"Basic {basic_auth_b64}")
                logger.info("ZAP: authenticated scan enabled (HTTP Basic)")
            logger.info("ZAP daemon ready")

            reached = []
            for target in target_list:
                try:
                    ZAPAdapter._api(zap_url, api_key, "/JSON/core/action/accessUrl/", url=target, followRedirects="true")
                except ScanError as e:
                    logger.warning(f"ZAP could not reach {target}: {e}")
                    continue
                spider_id = ZAPAdapter._api(zap_url, api_key, "/JSON/spider/action/scan/", url=target).get("scan")
                if spider_id is not None:
                    ZAPAdapter._wait(zap_url, api_key, "spider", spider_id, time.time() + spider_minutes * 60 + 60, 2)
                reached.append(target)

            if not reached:
                raise ScanError(f"ZAP n'a pu joindre aucune URL : {target_list}")

            ascan_ids = []
            for target in reached:
                try:
                    ascan_ids.append(ZAPAdapter._api(zap_url, api_key, "/JSON/ascan/action/scan/", url=target, recurse="true").get("scan"))
                except ScanError as e:
                    logger.warning(f"ZAP active scan could not start on {target}: {e}")
            deadline = time.time() + ascan_minutes * 60 + 120
            for ascan_id in (i for i in ascan_ids if i is not None):
                ZAPAdapter._wait(zap_url, api_key, "ascan", ascan_id, deadline, 10)

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
                    except Exception:
                        pass
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
