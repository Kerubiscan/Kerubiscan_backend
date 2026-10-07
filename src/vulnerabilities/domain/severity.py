"""Single severity scale shared by every scan engine (CVSS v3 qualitative ratings)."""
from typing import Optional
from src.vulnerabilities.domain.models import VulnSeverity

_LABELS = {
    "critical": VulnSeverity.CRITICAL,
    "high": VulnSeverity.HIGH,
    "medium": VulnSeverity.MEDIUM,
    "moderate": VulnSeverity.MEDIUM,
    "low": VulnSeverity.LOW,
    "info": VulnSeverity.INFO,
    "informational": VulnSeverity.INFO,
    "log": VulnSeverity.INFO,
    "none": VulnSeverity.INFO,
}

_RANK = {VulnSeverity.INFO: 0, VulnSeverity.LOW: 1, VulnSeverity.MEDIUM: 2, VulnSeverity.HIGH: 3, VulnSeverity.CRITICAL: 4}


def to_cvss(value) -> Optional[float]:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def from_cvss(score: Optional[float]) -> Optional[VulnSeverity]:
    if score is None:
        return None
    if score >= 9.0:
        return VulnSeverity.CRITICAL
    if score >= 7.0:
        return VulnSeverity.HIGH
    if score >= 4.0:
        return VulnSeverity.MEDIUM
    if score > 0.0:
        return VulnSeverity.LOW
    return VulnSeverity.INFO


def from_label(label: Optional[str]) -> Optional[VulnSeverity]:
    if not label:
        return None
    return _LABELS.get(str(label).strip().split(" ")[0].lower())


def resolve(label: Optional[str] = None, cvss: Optional[float] = None, default: VulnSeverity = VulnSeverity.INFO) -> VulnSeverity:
    """Engine label first (it reflects the engine's own assessment), CVSS second, default last."""
    return from_label(label) or from_cvss(cvss) or default


def highest(a: VulnSeverity, b: VulnSeverity) -> VulnSeverity:
    return a if _RANK[a] >= _RANK[b] else b
