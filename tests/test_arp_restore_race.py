"""
Regression tests for network/arp.py — restore/watchdog race + input validation
(Phase-2 hunt). Mocked: no real packets, processes, or iptables are issued.

ARP-1  the watchdog can restart the Scapy flood / arpspoof binary for an IP that
       restore() has already removed from _cut_ips, leaking a poisoning thread or
       process that keeps spoofing *after* the device was "restored".
ARP-2  cut()/spoof() pass IPs straight to iptables/arpspoof (run as root) with no
       ipaddress validation, against the project convention.
"""

from __future__ import annotations

import subprocess

from network import arp
from network.arp import ArpManager


def test_start_arpspoof_no_leak_when_not_cut(monkeypatch):
    """ARP-1: _start_arpspoof must not spawn for an IP that is not an active
    target (i.e. restore() already popped it) — otherwise the process is never
    tracked and keeps poisoning."""
    mgr = ArpManager()
    monkeypatch.setattr(arp.shutil, "which", lambda name: "/usr/sbin/arpspoof")

    spawned: list = []

    class _FakePopen:
        def __init__(self, *a, **k):
            spawned.append(a)
            self.pid = 4321

    monkeypatch.setattr(arp.subprocess, "Popen", _FakePopen)

    # _cut_ips is empty → this IP is NOT an active cut target.
    mgr._start_arpspoof("10.0.0.9", "10.0.0.1", "eth0")

    assert spawned == [], "arpspoof spawned for an IP not in _cut_ips (process leak)"


def test_start_flood_no_leak_when_not_cut():
    """ARP-1: _start_flood must not register / start a flood for an IP that is
    not an active target."""
    mgr = ArpManager()

    mgr._start_flood(
        "10.0.0.9",
        "10.0.0.1",
        "eth0",
        "aa:aa:aa:aa:aa:aa",
        "bb:bb:bb:bb:bb:bb",
        "cc:cc:cc:cc:cc:cc",
        "10.0.0.5",
    )

    assert "10.0.0.9" not in mgr._flood_stops, "flood started for an IP not being cut (thread leak)"


def test_cut_rejects_invalid_ip(monkeypatch):
    """ARP-2: an invalid target IP must be rejected before any root command."""
    mgr = ArpManager()
    calls: list = []

    def _rec(cmd, *a, **k):
        calls.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(arp.subprocess, "run", _rec)

    assert mgr.cut("not-an-ip", "10.0.0.1", "eth0", "10.0.0.5") is False
    assert calls == [], "cut() issued a command for an invalid IP"


def test_cut_rejects_invalid_gateway(monkeypatch):
    mgr = ArpManager()
    calls: list = []
    monkeypatch.setattr(
        arp.subprocess,
        "run",
        lambda cmd, *a, **k: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", ""),
    )
    assert mgr.cut("10.0.0.9", "999.999.0.1", "eth0", "10.0.0.5") is False
    assert calls == []


def test_spoof_rejects_invalid_ip(monkeypatch):
    mgr = ArpManager()
    calls: list = []
    monkeypatch.setattr(
        arp.subprocess,
        "run",
        lambda cmd, *a, **k: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", ""),
    )
    assert mgr.spoof("bogus", "10.0.0.1", "eth0", "10.0.0.5") is False
    assert calls == []
