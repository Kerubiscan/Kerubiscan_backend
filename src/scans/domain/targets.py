"""Parsing and normalisation of scan targets.

A target typed by a user can be an IP, a CIDR, a hostname or a web URL.
Each engine needs a different representation:
  * Nmap / OpenVAS work on a host (IP, CIDR or hostname),
  * ZAP / Nuclei work on URLs and must keep the hostname (Host header, SNI, virtual hosts).
"""
import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional
from urllib.parse import urlsplit

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")

# Largest networks accepted for a single target, to avoid accidental huge scans.
_MAX_IPV4_PREFIX = 16
_MAX_IPV6_PREFIX = 112

WEB_SERVICE_HINTS = ("http", "https", "ssl/http", "http-proxy", "http-alt", "https-alt", "www")
DEFAULT_WEB_PORTS = {"http": 80, "https": 443}


class InvalidTargetError(ValueError):
    pass


@dataclass(frozen=True)
class ScanTarget:
    raw: str
    host: str
    kind: str  # "ip" | "cidr" | "hostname"
    scheme: Optional[str] = None
    port: Optional[int] = None
    path: str = ""

    @property
    def is_url(self) -> bool:
        return self.scheme is not None

    @property
    def is_hostname(self) -> bool:
        return self.kind == "hostname"

    @property
    def is_ipv6(self) -> bool:
        if self.kind == "hostname":
            return False
        return ipaddress.ip_network(self.host, strict=False).version == 6

    @property
    def is_private(self) -> bool:
        """True for RFC1918 / loopback / link-local IPs and networks (LAN timing profile)."""
        if self.kind == "hostname":
            return False
        net = ipaddress.ip_network(self.host, strict=False)
        return net.is_private or net.is_loopback or net.is_link_local

    @property
    def url(self) -> Optional[str]:
        """The explicit URL typed by the user, normalised (None if the target is not a URL)."""
        if not self.is_url:
            return None
        return build_url(self.scheme, self.host, self.port, self.path)


def build_url(scheme: str, host: str, port: Optional[int] = None, path: str = "") -> str:
    netloc = f"[{host}]" if ":" in host else host
    if port and port != DEFAULT_WEB_PORTS.get(scheme):
        netloc = f"{netloc}:{port}"
    return f"{scheme}://{netloc}{path or ''}"


def _classify_host(host: str) -> str:
    try:
        net = ipaddress.ip_network(host, strict=False)
    except ValueError:
        if host.startswith("-") or not _HOST_RE.match(host):
            raise InvalidTargetError(f"Cible invalide : {host!r}")
        return "hostname"
    if "/" in host:
        limit = _MAX_IPV4_PREFIX if net.version == 4 else _MAX_IPV6_PREFIX
        if net.prefixlen < limit:
            raise InvalidTargetError(f"Réseau trop large : {host!r} (minimum /{limit})")
        return "cidr"
    return "ip"


def parse_target(raw: str) -> ScanTarget:
    value = (raw or "").strip()
    if not value:
        raise InvalidTargetError("Cible vide")

    if "://" in value:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise InvalidTargetError(f"Schéma non supporté : {scheme!r} (http ou https uniquement)")
        if parts.username or parts.password:
            raise InvalidTargetError("Les identifiants ne doivent pas figurer dans l'URL : utilisez le module Secrets")
        host = (parts.hostname or "").lower()
        if not host:
            raise InvalidTargetError(f"URL sans hôte : {value!r}")
        try:
            port = parts.port
        except ValueError:
            raise InvalidTargetError(f"Port invalide dans {value!r}")
        kind = _classify_host(host)
        if kind == "cidr":
            raise InvalidTargetError("Une URL ne peut pas viser un réseau")
        path = parts.path.rstrip("/") if parts.path not in ("", "/") else ""
        if parts.query:
            path = f"{path}?{parts.query}"
        return ScanTarget(raw=value, host=host, kind=kind, scheme=scheme,
                          port=port or DEFAULT_WEB_PORTS[scheme], path=path)

    # Tolerate a trailing slash on a bare host ("site.com/")
    host = value.rstrip("/").lower() if not _looks_like_cidr(value) else value
    if "/" in host and not _looks_like_cidr(host):
        raise InvalidTargetError(f"Cible invalide : {value!r} (pour une URL, ajoutez http:// ou https://)")
    if ":" in host and not _is_ip(host.split("/")[0]):
        raise InvalidTargetError(f"Cible invalide : {value!r} (pour préciser un port, utilisez une URL https://hôte:port)")
    return ScanTarget(raw=value, host=host, kind=_classify_host(host))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _looks_like_cidr(value: str) -> bool:
    if value.count("/") != 1:
        return False
    addr, prefix = value.split("/")
    return _is_ip(addr) and prefix.isdigit()


_SEPARATORS = re.compile(r"[,;\s]+")


def split_targets(raw: str) -> List[str]:
    """Split a list of targets, removing blanks and duplicates (order kept).

    Accepted separators: comma, semicolon, spaces and new lines ("a.com, b.com", "a.com b.com",
    one target per line...). A target (IP, network, domain or URL) never contains any of them.
    """
    return list(dict.fromkeys(t for t in _SEPARATORS.split(raw or "") if t))


def validate_targets(raw: str) -> List[ScanTarget]:
    targets = split_targets(raw)
    if not targets:
        raise InvalidTargetError("Aucune cible fournie")
    errors, parsed = [], []
    for t in targets:
        try:
            parsed.append(parse_target(t))
        except InvalidTargetError as e:
            errors.append(str(e))
    if errors:
        raise InvalidTargetError("; ".join(errors))
    return parsed


COMMON_WEB_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888, 9443}
_UNIDENTIFIED = {"", "unknown", "tcpwrapped"}


def is_web_service(service_name: Optional[str], tunnel: Optional[str] = None, port=None) -> bool:
    name = (service_name or "").lower()
    if "http" in name or name in WEB_SERVICE_HINTS:
        return True
    # CDNs and reverse proxies often show up as "tcpwrapped"/"unknown" on their web ports
    try:
        return name in _UNIDENTIFIED and int(port) in COMMON_WEB_PORTS
    except (TypeError, ValueError):
        return False


def web_scheme(service_name: Optional[str], tunnel: Optional[str], port: int) -> str:
    name = (service_name or "").lower()
    if tunnel == "ssl" or "https" in name or name.startswith("ssl/") or port in (443, 8443, 9443):
        return "https"
    return "http"


def web_urls_from_ports(host: str, ports: Iterable[dict], path: str = "") -> List[str]:
    """Build the web URLs of a host from the open ports found by Nmap.

    `host` must be the hostname when the user targeted a domain, so that the Host header
    and the TLS SNI match the virtual host.
    """
    urls = []
    for p in ports or []:
        if not isinstance(p, dict) or p.get("state") != "open":
            continue
        try:
            port = int(p.get("port"))
        except (TypeError, ValueError):
            continue
        if is_web_service(p.get("service"), p.get("tunnel"), port):
            urls.append(build_url(web_scheme(p.get("service"), p.get("tunnel"), port), host, port, path))
    return list(dict.fromkeys(urls))


def open_ports(ports: Iterable[dict]) -> List[dict]:
    return [p for p in (ports or []) if isinstance(p, dict) and p.get("state") == "open"]
