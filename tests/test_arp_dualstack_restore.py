"""
Tests for the ARP audit fixes in network/arp.py (dual-stack + restore reliability).

Covers:
  A1  IPv6 Neighbor-Advertisement poison frames (targeted, unicast, no multicast)
      and their symmetric heal.
  A3  restore() still heals the ARP cache when _remove_drop raises, and
      restore_all() does not abort on a single failing target.
  A4  restore() re-resolves a MAC it never learned before healing.
  A6  ip_forward is captured before being forced on and restored on full teardown.
  A7  spoof()/cut() refuse to poison self or the gateway.
  A11 the watchdog stops once the last cut is restored.

Mocked: no real packets, processes, or sysctl are issued.
"""

from __future__ import annotations

import subprocess

import pytest

import network.arp as arp_mod
from network.arp import SCAPY6_OK, SCAPY_OK, ArpManager

pytestmark = pytest.mark.skipif(not SCAPY_OK, reason="scapy not installed")

TARGET_IP = "10.0.0.9"
GATEWAY_IP = "10.0.0.1"
TARGET_IP6 = "fe80::9"
GATEWAY_IP6 = "fe80::1"
TARGET_MAC = "aa:aa:aa:aa:aa:aa"
GW_MAC = "bb:bb:bb:bb:bb:bb"
MY_MAC = "cc:cc:cc:cc:cc:cc"
BROADCAST = "ff:ff:ff:ff:ff:ff"


# ── A1: IPv6 NA poison frames ────────────────────────────────────────────────


@pytest.mark.skipif(not SCAPY6_OK, reason="scapy IPv6 ND not available")
def test_na_frames_are_unicast_and_scoped():
    from scapy.all import Ether

    frames = ArpManager._build_na_frames(TARGET_IP6, GATEWAY_IP6, TARGET_MAC, GW_MAC, MY_MAC)
    assert len(frames) == 2, "expected a target half and a gateway half"
    for f in frames:
        dst = f[Ether].dst.lower()
        assert dst != BROADCAST and not dst.startswith("33:33"), "NA must not multicast"
        assert dst in (TARGET_MAC, GW_MAC)


@pytest.mark.skipif(not SCAPY6_OK, reason="scapy IPv6 ND not available")
def test_na_frames_claim_our_mac_for_both_ends():
    from scapy.all import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6

    frames = ArpManager._build_na_frames(TARGET_IP6, GATEWAY_IP6, TARGET_MAC, GW_MAC, MY_MAC)
    for f in frames:
        # Every poison NA advertises OUR MAC as the link-layer address.
        assert f[ICMPv6NDOptDstLLAddr].lladdr == MY_MAC
        assert f[ICMPv6ND_NA].O == 1  # override the victim's existing entry
    # To the target we impersonate the gateway's IPv6; to the gateway, the target.
    tgts = {f[ICMPv6ND_NA].tgt for f in frames}
    srcs = {f[IPv6].src for f in frames}
    assert GATEWAY_IP6 in tgts and TARGET_IP6 in tgts
    assert GATEWAY_IP6 in srcs and TARGET_IP6 in srcs


def test_na_frames_empty_without_ipv6_addresses():
    assert ArpManager._build_na_frames("", "", TARGET_MAC, GW_MAC, MY_MAC) == []
    assert ArpManager._build_na_frames(TARGET_IP6, "", TARGET_MAC, GW_MAC, MY_MAC) == []


@pytest.mark.skipif(not SCAPY6_OK, reason="scapy IPv6 ND not available")
def test_na_frames_skip_gateway_half_when_gw_mac_unknown():
    from scapy.all import Ether

    frames = ArpManager._build_na_frames(TARGET_IP6, GATEWAY_IP6, TARGET_MAC, "", MY_MAC)
    assert len(frames) == 1
    assert frames[0][Ether].dst.lower() == TARGET_MAC


# ── A7: never poison self or gateway ─────────────────────────────────────────


def test_spoof_refuses_self_and_gateway(monkeypatch):
    mgr = ArpManager()
    resolved: list = []
    monkeypatch.setattr(
        mgr, "_resolve_macs", lambda *a, **k: resolved.append(a) or (TARGET_MAC, GW_MAC, MY_MAC)
    )
    assert mgr.spoof(GATEWAY_IP, GATEWAY_IP, "eth0", "10.0.0.5") is False
    assert mgr.spoof("10.0.0.5", GATEWAY_IP, "eth0", "10.0.0.5") is False
    assert resolved == [], "must bail before resolving MACs for self/gateway"


# ── A3 / A4 / A6 / A11: restore reliability ──────────────────────────────────


def _prime_cut(mgr, monkeypatch, *, gw_mac=GW_MAC, with_v6=False):
    """Install one active cut with mocked send/resolve/forwarding."""
    monkeypatch.setattr(arp_mod, "sendp", lambda *a, **k: None)
    monkeypatch.setattr(mgr, "_resolve_macs", lambda *a, **k: (TARGET_MAC, gw_mac, MY_MAC))
    # Don't spawn real threads/procs for this cut.
    monkeypatch.setattr(mgr, "_start_flood", lambda *a, **k: None)
    monkeypatch.setattr(mgr, "_start_arpspoof", lambda *a, **k: None)
    monkeypatch.setattr(mgr, "_watchdog", lambda: None)
    monkeypatch.setattr(mgr, "_enable_forwarding", lambda: None)
    mgr.spoof(
        TARGET_IP,
        GATEWAY_IP,
        "eth0",
        "10.0.0.5",
        mode="cut",
        target_ip6=TARGET_IP6 if with_v6 else "",
        gateway_ip6=GATEWAY_IP6 if with_v6 else "",
    )


def test_restore_heals_even_when_remove_drop_raises(monkeypatch):
    mgr = ArpManager()
    _prime_cut(mgr, monkeypatch)

    class _BadNft:
        def uncut(self, ip):
            raise RuntimeError("nft broke")

    mgr.nft = _BadNft()
    healed: list = []
    monkeypatch.setattr(mgr, "_send_restore", lambda *a, **k: healed.append(a))

    mgr.restore(TARGET_IP)  # must not raise
    assert healed, "cache heal must run even though _remove_drop raised"
    assert TARGET_IP not in mgr._cut_ips


def test_restore_all_isolates_failures(monkeypatch):
    mgr = ArpManager()
    monkeypatch.setattr(arp_mod, "sendp", lambda *a, **k: None)
    mgr._cut_ips = {"10.0.0.2": {}, "10.0.0.3": {}}
    done: list = []

    orig = mgr.restore

    def _restore(ip):
        if ip == "10.0.0.2":
            raise RuntimeError("boom")
        done.append(ip)

    monkeypatch.setattr(mgr, "restore", _restore)
    mgr.restore_all()
    assert "10.0.0.3" in done, "a failing target must not abort the rest"
    _ = orig


def test_restore_reresolves_missing_gateway_mac(monkeypatch):
    # Cut succeeds with target MAC but NO gateway MAC; restore must re-resolve it
    # so the heal can be sent with real addresses.
    mgr = ArpManager()
    _prime_cut(mgr, monkeypatch, gw_mac="")
    assert mgr._cut_ips[TARGET_IP]["gw_mac"] == ""

    monkeypatch.setattr(mgr, "_resolve_macs", lambda *a, **k: (TARGET_MAC, GW_MAC, MY_MAC))
    seen: list = []
    monkeypatch.setattr(mgr, "_send_restore", lambda *a, **k: seen.append(a))

    mgr.restore(TARGET_IP)
    # _send_restore(ip, target_mac, gateway, gw_mac, my_mac, iface, t6, g6)
    assert seen and seen[0][3] == GW_MAC, "restore must heal with the re-resolved gateway MAC"


def test_forwarding_captured_and_restored(monkeypatch):
    mgr = ArpManager()
    writes: list = []

    def _run(cmd, *a, **k):
        writes.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "0\n", "")

    monkeypatch.setattr(arp_mod.subprocess, "run", _run)
    monkeypatch.setattr(arp_mod, "_IS_WINDOWS", False)
    monkeypatch.setattr(ArpManager, "_read_ip_forward", staticmethod(lambda: "0"))
    monkeypatch.setattr(arp_mod, "sendp", lambda *a, **k: None)
    monkeypatch.setattr(mgr, "_resolve_macs", lambda *a, **k: (TARGET_MAC, GW_MAC, MY_MAC))
    monkeypatch.setattr(mgr, "_start_flood", lambda *a, **k: None)
    monkeypatch.setattr(mgr, "_start_arpspoof", lambda *a, **k: None)
    monkeypatch.setattr(mgr, "_watchdog", lambda: None)

    mgr.spoof(TARGET_IP, GATEWAY_IP, "eth0", "10.0.0.5", mode="cut")
    assert ["sysctl", "-w", "net.ipv4.ip_forward=1"] in writes
    assert mgr._orig_ip_forward == "0"

    writes.clear()
    mgr.restore(TARGET_IP)
    assert ["sysctl", "-w", "net.ipv4.ip_forward=0"] in writes, "must restore captured value"
    assert mgr._orig_ip_forward is None


def test_watchdog_stops_after_last_restore(monkeypatch):
    mgr = ArpManager()
    _prime_cut(mgr, monkeypatch)
    mgr._watchdog_running = True
    monkeypatch.setattr(mgr, "_send_restore", lambda *a, **k: None)
    mgr.restore(TARGET_IP)
    assert mgr._watchdog_running is False, "watchdog must idle-stop once no cuts remain"
