"""
Tests for network/arp.py segment blackout (broadcast gateway poison).

Mocked: _resolve_macs, RawL2Sender, scapy sendp, and subprocess are patched, so
no real ARP/raw sends or `ip neigh` run. These pin the properties that keep the
OPERATOR online: the host's own neighbor entry for the gateway is pinned to the
REAL gateway MAC (never poisoned), and blackout_stop releases it and heals.
"""

from __future__ import annotations

import subprocess

import network.arp as arp_mod
from network.arp import ArpManager


def _cp():
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")


class _FakeRaw:
    available = False

    def __init__(self, iface):
        pass

    def send(self, b):
        return False

    def close(self):
        pass


def _patch(monkeypatch, mgr, gw_mac="aa:aa:aa:aa:aa:aa", my_mac="bb:bb:bb:bb:bb:bb"):
    monkeypatch.setattr(mgr, "_resolve_macs", lambda *a, **k: ("", gw_mac, my_mac))
    monkeypatch.setattr(arp_mod, "RawL2Sender", _FakeRaw)
    monkeypatch.setattr(arp_mod, "sendp", lambda *a, **k: None)
    cmds: list = []
    monkeypatch.setattr(arp_mod.subprocess, "run", lambda cmd, *a, **k: cmds.append(cmd) or _cp())
    return cmds


def test_blackout_pins_own_gateway_entry_to_real_mac(monkeypatch):
    mgr = ArpManager()
    cmds = _patch(monkeypatch, mgr)
    assert mgr.blackout_start("192.168.1.1", "eth0", "192.168.1.50") is True
    # Operator stays online: our own gateway neighbor is pinned PERMANENT to the
    # REAL gateway MAC (aa:…), not our own — i.e. our entry is NOT poisoned.
    assert [
        "ip",
        "neigh",
        "replace",
        "192.168.1.1",
        "lladdr",
        "aa:aa:aa:aa:aa:aa",
        "dev",
        "eth0",
        "nud",
        "permanent",
    ] in cmds
    mgr.blackout_stop()


def test_blackout_stop_heals_and_releases(monkeypatch):
    mgr = ArpManager()
    cmds = _patch(monkeypatch, mgr)
    mgr.blackout_start("192.168.1.1", "eth0", "192.168.1.50")
    cmds.clear()
    mgr.blackout_stop()
    # The pinned neighbor is released back to dynamic on stop.
    assert ["ip", "neigh", "del", "192.168.1.1", "dev", "eth0"] in cmds


def test_blackout_start_fails_without_macs(monkeypatch):
    mgr = ArpManager()
    monkeypatch.setattr(mgr, "_resolve_macs", lambda *a, **k: ("", "", ""))  # can't resolve
    cmds: list = []
    monkeypatch.setattr(arp_mod.subprocess, "run", lambda cmd, *a, **k: cmds.append(cmd) or _cp())
    assert mgr.blackout_start("192.168.1.1", "eth0", "192.168.1.50") is False
    assert cmds == [], "no neighbor pin and no poison when the gateway MAC is unknown"


def test_blackout_stop_is_idempotent(monkeypatch):
    mgr = ArpManager()
    _patch(monkeypatch, mgr)
    mgr.blackout_stop()  # never started — must not raise
    mgr.blackout_start("192.168.1.1", "eth0", "192.168.1.50")
    mgr.blackout_stop()
    mgr.blackout_stop()  # second stop — must not raise
