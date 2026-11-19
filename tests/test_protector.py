"""
Regression tests for core/protector.py (Phase-2 hunt).

PROT-1  the self-healing sentry parsed /proc/net/arp with parts[0]/parts[2] and
        no length guard, so a blank/short line raised IndexError that the broad
        except swallowed — aborting the rest of that scan cycle.
PROT-4  enable_arp_guard ignored the `ip neigh replace` exit code and reported a
        false "ACTIVE"; it also didn't validate the gateway address.

Mocked: subprocess is patched; no real `ip neigh` runs.
"""

from __future__ import annotations

import subprocess

from core import protector as prot_mod
from core.protector import Protector

_HEADER = "IP address       HW type     Flags       HW address            Mask     Device"


class _Net:
    def __init__(self, gateway="192.168.1.1", iface="eth0"):
        self.gateway = gateway
        self.iface = iface
        self.my_mac = "aa:aa:aa:aa:aa:aa"


class _Ctrl:
    def __init__(self, gateway="192.168.1.1"):
        self.net = _Net(gateway)


def _cp(rc: int):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout="", stderr="err")


# ── PROT-1: /proc/net/arp parsing ────────────────────────────────────────────


def test_gateway_unlocked_handles_malformed_lines():
    prot = Protector(_Ctrl(gateway="192.168.1.1"))
    text = "\n".join(
        [
            _HEADER,
            "",  # blank line before the gateway → must not crash or abort the scan
            "192.168.1.50   0x1   0x2   bb:bb:bb:bb:bb:bb   *   eth0",
            "192.168.1.1    0x1   0x2   11:22:33:44:55:66   *   eth0",  # gateway, NOT permanent
        ]
    )
    assert prot._gateway_is_unlocked(text) is True


def test_gateway_locked_returns_false():
    prot = Protector(_Ctrl(gateway="192.168.1.1"))
    text = "\n".join(
        [
            _HEADER,
            "192.168.1.1    0x1   0x6   11:22:33:44:55:66   *   eth0",  # 0x6 = permanent
        ]
    )
    assert prot._gateway_is_unlocked(text) is False


def test_gateway_absent_returns_false():
    prot = Protector(_Ctrl(gateway="192.168.1.1"))
    text = "\n".join([_HEADER, "10.0.0.2   0x1   0x2   cc:cc:cc:cc:cc:cc   *   eth0"])
    assert prot._gateway_is_unlocked(text) is False


# ── PROT-4: enable_arp_guard honesty ─────────────────────────────────────────


def test_enable_arp_guard_reports_command_failure(monkeypatch):
    prot = Protector(_Ctrl(gateway="192.168.1.1"))
    prot.gateway_mac = "11:22:33:44:55:66"  # skip MAC resolution
    monkeypatch.setattr(prot_mod.subprocess, "run", lambda *a, **k: _cp(1))
    assert prot.enable_arp_guard() is False
    assert prot.arp_guard_enabled is False, "must not claim ACTIVE when ip neigh failed"


def test_enable_arp_guard_success(monkeypatch):
    prot = Protector(_Ctrl(gateway="192.168.1.1"))
    prot.gateway_mac = "11:22:33:44:55:66"
    monkeypatch.setattr(prot_mod.subprocess, "run", lambda *a, **k: _cp(0))
    assert prot.enable_arp_guard() is True
    assert prot.arp_guard_enabled is True


def test_enable_arp_guard_rejects_invalid_gateway(monkeypatch):
    prot = Protector(_Ctrl(gateway="not-an-ip"))
    prot.gateway_mac = "11:22:33:44:55:66"
    calls: list = []
    monkeypatch.setattr(prot_mod.subprocess, "run", lambda *a, **k: calls.append(a) or _cp(0))
    assert prot.enable_arp_guard() is False
    assert calls == [], "no ip neigh command may run for an invalid gateway"
