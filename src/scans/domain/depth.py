"""Scan depth, chosen when the scan is launched: how long the engines may spend on each target.

STANDARD is what every scan did before the choice existed (and what a scan without a value does):
choosing it, or nothing, changes nothing.
"""
from typing import Optional

RAPIDE = "RAPIDE"
STANDARD = "STANDARD"
APPROFONDI = "APPROFONDI"
DEPTHS = (RAPIDE, STANDARD, APPROFONDI)

# OWASP ZAP time budgets in minutes: (classic spider, AJAX spider, active scan) for a target.
# STANDARD = the budgets of zap_adapter (SPIDER_MAX_MINUTES, AJAX_SPIDER_MAX_MINUTES, ASCAN_MAX_MINUTES).
ZAP_BUDGETS = {
    RAPIDE: (5, 3, 20),
    STANDARD: (15, 10, 90),
    APPROFONDI: (30, 20, 240),
}

# Phase 1 of Nmap and Nuclei in RAPIDE: Nmap's most common ports instead of all 65 535
RAPID_TOP_PORTS = 1000


def parse_depth(value: Optional[str]) -> str:
    """The depth of a request: STANDARD when absent; ValueError when unknown."""
    key = (value or "").strip().upper()
    if not key:
        return STANDARD
    if key not in DEPTHS:
        raise ValueError(f"Durée de scan inconnue : {value!r} (attendu : {', '.join(DEPTHS)})")
    return key


def depth_of(value: Optional[str]) -> str:
    """The depth of a stored scan: STANDARD for scans created before the choice existed."""
    try:
        return parse_depth(value)
    except ValueError:
        return STANDARD
