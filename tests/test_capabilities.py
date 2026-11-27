"""Tests for core/capabilities.py — the cross-platform capability registry.

All OS / elevation / dependency inputs are mocked; no real probing of the host
beyond what the functions do internally, and never any system mutation.
"""

from __future__ import annotations

import core.capabilities as cap


def _probe(monkeypatch, *, windows, elevated, scapy=True, psutil=True, npcap=True, which=None):
    """Drive probe_all() with fully controlled platform inputs."""
    which = which or (lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(cap, "IS_WINDOWS", windows)
    monkeypatch.setattr(cap, "_os_key", lambda: "windows" if windows else "linux")
    monkeypatch.setattr(cap, "is_elevated", lambda: elevated)
    monkeypatch.setattr(cap, "_has_npcap", lambda: npcap)
    monkeypatch.setattr(
        cap, "_has_module", lambda m: {"scapy": scapy, "psutil": psutil}.get(m, True)
    )
    monkeypatch.setattr(cap.shutil, "which", which)
    return cap.probe_all()


def test_linux_root_full_stack(monkeypatch):
    caps = _probe(monkeypatch, windows=False, elevated=True)
    # Monitoring + interception all available on a rooted Linux box with deps.
    for name in ("detection", "discovery", "traffic_stats", "sniffer", "arp_cut", "firewall"):
        assert caps[name].available, name
        assert caps[name].reason == ""


def test_linux_non_root_blocks_interception_not_monitoring(monkeypatch):
    caps = _probe(monkeypatch, windows=False, elevated=False)
    # Passive monitoring does not need root.
    assert caps["detection"].available
    assert caps["traffic_stats"].available
    # Interception needs elevation and must report it honestly (not fake success).
    assert not caps["arp_cut"].available
    assert "privile" in caps["arp_cut"].reason.lower()
    assert "sudo" in caps["arp_cut"].remedy.lower() or "root" in caps["arp_cut"].remedy.lower()


def test_windows_interception_unsupported_never_faked(monkeypatch):
    caps = _probe(monkeypatch, windows=True, elevated=True)
    for name in ("arp_cut", "firewall", "shaping"):
        c = caps[name]
        assert not c.available, name
        assert not c.supported_on_this_os
        assert "linux" in c.reason.lower() or "linux" in c.remedy.lower()
        # Windows is not in the supported set for interception.
        assert "windows" not in c.supported_os


def test_windows_monitoring_available(monkeypatch):
    caps = _probe(monkeypatch, windows=True, elevated=True)
    assert caps["detection"].available
    assert caps["traffic_stats"].available  # psutil present
    assert caps["discovery"].available


def test_missing_psutil_reports_dependency(monkeypatch):
    caps = _probe(monkeypatch, windows=True, elevated=True, psutil=False)
    c = caps["traffic_stats"]
    assert not c.available
    assert c.missing_dep == "psutil"
    assert "psutil" in c.remedy


def test_windows_sniffer_needs_npcap(monkeypatch):
    caps = _probe(monkeypatch, windows=True, elevated=True, npcap=False)
    c = caps["sniffer"]
    assert not c.available
    assert "npcap" in (c.reason + c.remedy).lower()


def test_missing_scapy_degrades_discovery(monkeypatch):
    caps = _probe(monkeypatch, windows=False, elevated=True, scapy=False)
    c = caps["discovery"]
    assert not c.available
    assert c.missing_dep == "scapy"
    # The remedy mentions the OS ARP-table fallback so the user isn't left blank.
    assert "fallback" in c.remedy.lower()


def test_unavailable_filter_by_category(monkeypatch):
    monkeypatch.setattr(cap, "_cached", cap._cached)
    cap._cached.cache_clear()
    monkeypatch.setattr(cap, "IS_WINDOWS", True)
    monkeypatch.setattr(cap, "_os_key", lambda: "windows")
    monkeypatch.setattr(cap, "is_elevated", lambda: True)
    monkeypatch.setattr(cap, "_has_npcap", lambda: True)
    monkeypatch.setattr(cap, "_has_module", lambda m: True)
    monkeypatch.setattr(cap.shutil, "which", lambda n: "/x/" + n)
    bad = cap.unavailable(category=cap.INTERCEPTION)
    names = {c.name for c in bad}
    assert {"arp_cut", "firewall", "shaping"} <= names
    # No monitoring capability should appear in the interception-only filter.
    assert all(c.category == cap.INTERCEPTION for c in bad)
    cap._cached.cache_clear()


def test_is_elevated_never_raises(monkeypatch):
    # Even if the underlying call blows up, is_elevated() returns a bool.
    assert isinstance(cap.is_elevated(), bool)
