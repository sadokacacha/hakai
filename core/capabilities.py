"""
core/capabilities.py — cross-platform capability registry.

Lanwarden runs on Linux (full engine) and Windows (monitoring + diagnostics).
Instead of letting OS-specific code silently no-op, every feature that can be
unavailable is modelled here as a :class:`Capability` with a *reason* and a
*remedy*. The UI (and the startup banner) read this registry so the user is told
exactly why something is off — unsupported OS, missing dependency, or missing
elevation — and what to do about it.

This module performs only read-only probes (``shutil.which``, optional imports,
an elevation check). It never mutates system state and never raises: a failed
probe degrades to ``available = False`` with an explanatory reason.

Capabilities are grouped into categories:

* ``monitor``      — passive, safe: detection, discovery, traffic stats, sniffer.
* ``diagnostic``   — read-only helpers: recon / fingerprinting.
* ``interception`` — active, Linux-only manipulation (ARP cut, firewall, shaping).
  These are intentionally *not* reimplemented for Windows; on Windows they are
  reported as unsupported, never faked. Keeping them isolated here is the Phase-4
  rule from the cross-platform mission.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from functools import lru_cache

from core.osutil import IS_WINDOWS

MONITOR = "monitor"
DIAGNOSTIC = "diagnostic"
INTERCEPTION = "interception"


def is_elevated() -> bool:
    """True if the process has admin/root rights, on either OS. Never raises."""
    if IS_WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    try:
        import os

        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def _has_module(name: str) -> bool:
    """True if ``name`` can be imported, without importing it for real."""
    import importlib.util

    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _has_npcap() -> bool:
    """Best-effort check for Npcap/WinPcap (packet capture driver) on Windows."""
    if not IS_WINDOWS:
        return True  # Linux uses AF_PACKET; no external driver needed.
    import os

    root = os.environ.get("SystemRoot", r"C:\Windows")
    candidates = [
        os.path.join(root, "System32", "Npcap", "wpcap.dll"),
        os.path.join(root, "System32", "wpcap.dll"),
    ]
    return any(os.path.exists(p) for p in candidates)


@dataclass(frozen=True)
class Capability:
    """One feature's availability on the current platform, with a user remedy."""

    name: str
    title: str
    category: str
    available: bool
    supported_os: tuple[str, ...]  # subset of ("linux", "windows", "darwin")
    needs_elevation: bool = False
    missing_dep: str | None = None
    reason: str = ""
    remedy: str = ""

    @property
    def supported_on_this_os(self) -> bool:
        return _os_key() in self.supported_os


def _os_key() -> str:
    if IS_WINDOWS:
        return "windows"
    if sys.platform == "darwin":
        return "darwin"
    return "linux"


def _cap(
    name: str,
    title: str,
    category: str,
    *,
    supported_os: tuple[str, ...],
    needs_elevation: bool = False,
    dep: str | None = None,
    dep_present: bool = True,
    extra_ok: bool = True,
    unsupported_reason: str = "",
    unsupported_remedy: str = "",
    dep_remedy: str = "",
    elevation_remedy: str = "",
) -> Capability:
    """Assemble one Capability, deriving availability + the first blocking reason.

    Precedence of blockers (most fundamental first): OS → dependency → extra
    runtime requirement → elevation. The first unmet one sets reason/remedy.
    """
    on_os = _os_key() in supported_os
    elevated = (not needs_elevation) or is_elevated()
    available = on_os and dep_present and extra_ok and elevated

    missing_dep = dep if (dep is not None and not dep_present) else None
    reason = ""
    remedy = ""
    if not on_os:
        reason = unsupported_reason or f"not supported on {_os_key()}"
        remedy = unsupported_remedy or "use a supported platform"
    elif dep is not None and not dep_present:
        reason = f"missing dependency: {dep}"
        remedy = dep_remedy or f"install {dep}"
    elif not extra_ok:
        reason = unsupported_reason or "a runtime requirement is missing"
        remedy = unsupported_remedy or dep_remedy
    elif not elevated:
        reason = "requires administrator / root privileges"
        remedy = elevation_remedy or (
            "run as Administrator" if IS_WINDOWS else "run with sudo / as root"
        )

    return Capability(
        name=name,
        title=title,
        category=category,
        available=available,
        supported_os=supported_os,
        needs_elevation=needs_elevation,
        missing_dep=missing_dep,
        reason=reason,
        remedy=remedy,
    )


def probe_all() -> dict[str, Capability]:
    """Probe every known capability on the current OS. Read-only; never raises."""
    scapy_ok = _has_module("scapy")
    psutil_ok = _has_module("psutil")
    npcap_ok = _has_npcap()
    all_os = ("linux", "windows", "darwin")

    caps: list[Capability] = [
        # ── monitor ───────────────────────────────────────────────────────────
        _cap(
            "detection",
            "Network detection",
            MONITOR,
            supported_os=all_os,
        ),
        _cap(
            "discovery",
            "Device discovery",
            MONITOR,
            supported_os=all_os,
            dep="scapy",
            dep_present=scapy_ok,
            dep_remedy="pip install scapy  (the OS ARP table is used as a fallback)",
        ),
        _cap(
            "traffic_stats",
            "Traffic / bandwidth stats",
            MONITOR,
            supported_os=all_os,
            dep="psutil",
            dep_present=psutil_ok,
            dep_remedy="pip install psutil",
        ),
        _cap(
            "sniffer",
            "Passive packet sniffer",
            MONITOR,
            supported_os=all_os,
            dep="scapy",
            dep_present=scapy_ok,
            extra_ok=npcap_ok,
            unsupported_reason="Npcap packet-capture driver not found" if not npcap_ok else "",
            unsupported_remedy="install Npcap (https://npcap.com) in WinPcap-compatible mode",
            dep_remedy="pip install scapy",
        ),
        # ── diagnostic ────────────────────────────────────────────────────────
        _cap(
            "recon",
            "Deep recon / fingerprint",
            DIAGNOSTIC,
            supported_os=all_os,
            dep="nmap",
            dep_present=shutil.which("nmap") is not None,
            dep_remedy="install nmap for faster/deeper scans (sockets are used otherwise)",
        ),
        # ── interception (Linux-only by design — never faked on Windows) ───────
        _cap(
            "arp_cut",
            "ARP cut / blackout",
            INTERCEPTION,
            supported_os=("linux",),
            needs_elevation=True,
            unsupported_reason="active ARP manipulation needs Linux raw sockets",
            unsupported_remedy="run Lanwarden on Linux for interception features",
        ),
        _cap(
            "firewall",
            "Firewall / cut engine",
            INTERCEPTION,
            supported_os=("linux",),
            needs_elevation=True,
            dep="nft",
            dep_present=shutil.which("nft") is not None,
            unsupported_reason="the FORWARD/cut engine needs Linux nftables",
            unsupported_remedy="run on Linux with nftables",
            dep_remedy="install nftables (apt install nftables)",
        ),
        _cap(
            "shaping",
            "Bandwidth limiting",
            INTERCEPTION,
            supported_os=("linux",),
            needs_elevation=True,
            dep="tc",
            dep_present=shutil.which("tc") is not None,
            unsupported_reason="traffic shaping needs Linux tc (iproute2)",
            unsupported_remedy="run on Linux with iproute2",
            dep_remedy="install iproute2 (apt install iproute2)",
        ),
    ]
    return {c.name: c for c in caps}


@lru_cache(maxsize=1)
def _cached() -> dict[str, Capability]:
    return probe_all()


def get_capabilities(refresh: bool = False) -> dict[str, Capability]:
    """Return the capability map, cached after first probe. ``refresh`` re-probes."""
    if refresh:
        _cached.cache_clear()
    return _cached()


def unavailable(category: str | None = None) -> list[Capability]:
    """All capabilities that are not available, optionally filtered by category."""
    caps = get_capabilities().values()
    return [c for c in caps if not c.available and (category is None or c.category == category)]
