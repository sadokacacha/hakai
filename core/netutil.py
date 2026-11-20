"""
core/netutil.py — Shared network-address validation (pure stdlib).

Centralises the IP/CIDR/DNS validation that was copy-pasted as a private
`_valid_ip` (and `_valid_cidr`/`_valid_dns`) across network/arp,
system/iptables_manager, core/protector, system/tc_manager, network/dns_spoof,
network/fingerprint, and system/network_manager. One definition, one behaviour.

This module imports only `ipaddress`, so it is a dependency leaf — safe to import
from any layer (core/network/system) without creating an import cycle.
"""

from __future__ import annotations

import ipaddress


def valid_ip(addr: str) -> bool:
    """True if addr is a valid IPv4 or IPv6 address literal."""
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return False
    return True


def valid_cidr(addr: str) -> bool:
    """True if addr is a host address with an optional prefix (e.g. 192.168.1.5/24)."""
    try:
        ipaddress.ip_interface(addr)
    except ValueError:
        return False
    return True


def valid_dns(dns: str) -> bool:
    """True if dns is a non-empty comma-separated list of valid IP addresses."""
    parts = [p.strip() for p in dns.split(",") if p.strip()]
    return bool(parts) and all(valid_ip(p) for p in parts)
