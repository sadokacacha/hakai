"""
network/oui_lookup.py — MAC → vendor presentation layer.

The actual lookup is the single canonical `core.persistence.lookup_oui` (which
consults both static OUI tables and the optional mac-vendor-lookup library).
This module only adds the privacy-bit presentation that the controller's intel
callbacks expect. See P4-2 in audit.md — this used to carry a second static dict
(FALLBACK_OUI, now moved into persistence) and a second optional library
(ouilookup, removed as redundant).
"""

from __future__ import annotations

from core.netutil import randomized_mac
from core.persistence import lookup_oui


def is_randomized(mac: str) -> bool:
    """Checks the Locally Administered bit (second character of MAC)."""
    return randomized_mac(mac)


def get_vendor(mac: str) -> str:
    """
    Identify the manufacturer via the canonical OUI lookup, with a privacy-bit
    fallback. Returns a vendor string, '🎭 [PRIVATE_MAC]' for a randomised MAC,
    or 'Unknown Device'.
    """
    mac = mac.replace("-", ":")
    vendor = lookup_oui(mac)
    if vendor:
        return vendor
    if is_randomized(mac):
        return "🎭 [PRIVATE_MAC]"
    return "Unknown Device"
