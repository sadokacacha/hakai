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


# ── P7 #23: Kill-switch must leave the DROP in place, not self-undo ───────────


class _KillCtrl:
    """Controller stub that records whether stop() was called."""

    def __init__(self, gateway="192.168.1.1"):
        self.net = _Net(gateway)
        self.stopped = False

    def stop(self):
        self.stopped = True


def _record_run(calls):
    def _run(cmd, *a, **k):
        calls.append(list(cmd))
        # iptables -D (delete) returns 1 so disable_kill_switch's loop stops after one try.
        return _cp(1 if "-D" in cmd else 0)

    return _run


def test_kill_switch_trigger_inserts_drop_and_does_not_stop(monkeypatch):
    ctrl = _KillCtrl()
    prot = Protector(ctrl)
    calls: list = []
    monkeypatch.setattr(prot_mod.subprocess, "run", _record_run(calls))
    monkeypatch.setattr(prot_mod, "_IS_WINDOWS", False)

    first = prot._trigger_kill_switch()

    assert first is True
    assert prot._killswitch_tripped is True
    assert ctrl.stopped is False, "trigger must NOT call ctrl.stop() — that removed the DROP"
    inserts = [c for c in calls if "-I" in c and "lanwarden_killswitch" in c]
    assert len(inserts) == 1, "exactly one OUTPUT DROP inserted"


def test_kill_switch_trigger_is_idempotent(monkeypatch):
    prot = Protector(_KillCtrl())
    calls: list = []
    monkeypatch.setattr(prot_mod.subprocess, "run", _record_run(calls))
    monkeypatch.setattr(prot_mod, "_IS_WINDOWS", False)

    assert prot._trigger_kill_switch() is True
    assert prot._trigger_kill_switch() is False, "second trigger must not re-insert the DROP"
    inserts = [c for c in calls if "-I" in c and "lanwarden_killswitch" in c]
    assert len(inserts) == 1, "sentry fires per-packet; the DROP must be inserted only once"


def test_disable_kill_switch_resets_trip_and_removes_rule(monkeypatch):
    prot = Protector(_KillCtrl())
    calls: list = []
    monkeypatch.setattr(prot_mod.subprocess, "run", _record_run(calls))
    monkeypatch.setattr(prot_mod, "_IS_WINDOWS", False)

    prot._trigger_kill_switch()
    prot.disable_kill_switch()

    assert prot._killswitch_tripped is False
    assert prot.kill_switch_enabled is False
    deletes = [c for c in calls if "-D" in c and "lanwarden_killswitch" in c]
    assert len(deletes) >= 1, "disable must remove the lanwarden_killswitch DROP"
    # After a disarm the switch can trip again.
    assert prot._trigger_kill_switch() is True


# ── P9: kill-switch must not claim "armed" unless the DROP actually went in ───


def test_kill_switch_not_armed_when_insert_fails(monkeypatch):
    prot = Protector(_KillCtrl())
    monkeypatch.setattr(prot_mod, "_IS_WINDOWS", False)
    # iptables -I returns nonzero (e.g. ruleset locked / non-root) → NOT armed.
    monkeypatch.setattr(prot_mod.subprocess, "run", lambda *a, **k: _cp(1))

    assert prot._trigger_kill_switch() is False, "must report the truth when the DROP failed"
    assert prot._killswitch_tripped is False


def test_kill_switch_not_armed_on_windows(monkeypatch):
    prot = Protector(_KillCtrl())
    monkeypatch.setattr(prot_mod, "_IS_WINDOWS", True)
    calls: list = []
    monkeypatch.setattr(prot_mod.subprocess, "run", lambda *a, **k: calls.append(a) or _cp(0))

    assert prot._trigger_kill_switch() is False, "no OUTPUT DROP on Windows → not armed"
    assert prot._killswitch_tripped is False
    assert calls == [], "must not run iptables on Windows"
