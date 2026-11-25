"""
Regression tests for truthful device state in core/controller.py (P9).

The row state must not lie about reality:
- cut_device optimistically marked a device CUT, but if the ARP cut failed the
  worker left it showing 🔒 CUT / BLOCKED while it still had connectivity.
- limit_device marked a device LIMITED even when tc shaping failed.
- toggle_nuclear_stealth assigned an unchecked (possibly empty) MAC to
  self.net.my_mac, which is later .lower()'d in the traffic counter.

The cut worker runs on a thread; we patch controller.threading.Thread to run it
synchronously so the assertions are deterministic. No real iptables/tc/sysctl is
touched (subsystem methods are stubbed).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from core import controller as controller_mod
from core.controller import Controller
from core.device import Device
from system.netinfo import NetInfo


class _SyncThread:
    def __init__(self, target=None, args=(), daemon=None, name=None):
        self._target = target
        self._args = args

    def start(self):
        if self._target:
            self._target(*self._args)


def _ctrl(monkeypatch):
    ctrl = Controller(NetInfo(iface="eth0", gateway="192.168.1.1", my_ip="192.168.1.50"))
    monkeypatch.setattr(controller_mod.threading, "Thread", _SyncThread)
    # cut/limit now write the sqlite store; use a mock so tests don't touch the
    # real ~/.lanwarden DB.
    monkeypatch.setattr(controller_mod, "db", MagicMock())
    return ctrl


def _add_device(ctrl, ip="192.168.1.100"):
    dev = Device(ip, mac="aa:bb:cc:dd:ee:ff")
    ctrl.devices[ip] = dev
    return dev


def test_toggle_blackout_engages_and_lifts(monkeypatch):
    ctrl = _ctrl(monkeypatch)
    ctrl.nft = MagicMock()
    ctrl.arp.blackout_start = MagicMock(return_value=True)
    ctrl.arp.blackout_stop = MagicMock()

    assert ctrl.toggle_blackout(True) is True
    assert ctrl.blackout_active is True
    ctrl.nft.blackout.assert_any_call(True)
    ctrl.arp.blackout_start.assert_called_once()

    assert ctrl.toggle_blackout(False) is True
    assert ctrl.blackout_active is False
    ctrl.arp.blackout_stop.assert_called_once()
    ctrl.nft.blackout.assert_any_call(False)


def test_toggle_blackout_disarms_drop_if_poison_fails(monkeypatch):
    ctrl = _ctrl(monkeypatch)
    ctrl.nft = MagicMock()
    ctrl.arp.blackout_start = MagicMock(return_value=False)  # can't resolve gateway MAC

    assert ctrl.toggle_blackout(True) is False
    assert ctrl.blackout_active is False
    # the FORWARD drop must be lifted so we don't leave a half-armed blackout
    ctrl.nft.blackout.assert_any_call(False)


def test_toggle_blackout_needs_gateway(monkeypatch):
    ctrl = Controller(NetInfo(iface="eth0", gateway=""))
    monkeypatch.setattr(controller_mod, "db", MagicMock())
    assert ctrl.toggle_blackout(True) is False
    assert ctrl.blackout_active is False


def test_cut_device_reverts_state_when_arp_cut_fails(monkeypatch):
    ctrl = _ctrl(monkeypatch)
    dev = _add_device(ctrl)
    monkeypatch.setattr(ctrl.arp, "cut", lambda *a, **k: False)  # cut fails
    unmarked: list = []
    monkeypatch.setattr(ctrl.traffic, "unmark_cut", lambda ip: unmarked.append(ip))
    monkeypatch.setattr(ctrl.traffic, "mark_cut", lambda ip: None)

    ctrl.cut_device(dev.ip)

    assert dev.cut is False, "a failed cut must not leave the device marked CUT"
    assert dev.status == "online"
    assert unmarked == [dev.ip], "the speed-display cut-mark must be cleared on failure"


def test_cut_device_keeps_state_when_arp_cut_succeeds(monkeypatch):
    ctrl = _ctrl(monkeypatch)
    dev = _add_device(ctrl)
    monkeypatch.setattr(ctrl.arp, "cut", lambda *a, **k: True)
    monkeypatch.setattr(ctrl.xdp, "add_drop", lambda ip: None)
    monkeypatch.setattr(ctrl.traffic, "mark_cut", lambda ip: None)

    ctrl.cut_device(dev.ip)

    assert dev.cut is True
    assert dev.status == "cut"


def test_limit_device_not_marked_when_tc_fails(monkeypatch):
    ctrl = _ctrl(monkeypatch)
    dev = _add_device(ctrl)
    monkeypatch.setattr(ctrl.tc, "limit", lambda ip, kb: False)

    assert ctrl.limit_device(dev.ip, 500) is False
    assert dev.limited is False, "must not render a limit that tc never applied"


def test_limit_device_marked_when_tc_succeeds(monkeypatch):
    ctrl = _ctrl(monkeypatch)
    dev = _add_device(ctrl)
    monkeypatch.setattr(ctrl.tc, "limit", lambda ip, kb: True)

    assert ctrl.limit_device(dev.ip, 500) is True
    assert dev.limited is True
    assert dev.limit_kb == 500


def test_nuclear_stealth_does_not_corrupt_mac_on_cloak_failure(monkeypatch):
    ctrl = _ctrl(monkeypatch)
    ctrl.net.my_mac = "11:22:33:44:55:66"
    # Cloak fails → returns an empty MAC; self.net.my_mac must be preserved.
    monkeypatch.setattr(controller_mod, "engage_mirage_cloak", lambda iface: ("[FAIL]", ""))
    monkeypatch.setattr(controller_mod, "apply_stack_masquerade", lambda state: "")
    monkeypatch.setattr(ctrl.protector, "enable_arp_guard", lambda log=None: True)

    ctrl.toggle_nuclear_stealth(True)

    assert ctrl.net.my_mac == "11:22:33:44:55:66", "an empty cloak MAC must not overwrite my_mac"


# ── /wire: dormant interception features wired to reachable controls ──────────


def test_monitor_device_spoofs_a_valid_target(monkeypatch):
    ctrl = _ctrl(monkeypatch)
    dev = _add_device(ctrl)
    calls: list = []
    monkeypatch.setattr(ctrl.arp, "spoof", lambda *a, **k: calls.append(a))

    assert ctrl.monitor_device(dev.ip, log=lambda *a: None) is True
    assert calls == [(dev.ip, ctrl.net.gateway, ctrl.net.iface, ctrl.net.my_ip)]


def test_monitor_device_refuses_gateway_and_self(monkeypatch):
    ctrl = _ctrl(monkeypatch)
    calls: list = []
    monkeypatch.setattr(ctrl.arp, "spoof", lambda *a, **k: calls.append(a))
    # gateway
    ctrl.devices[ctrl.net.gateway] = Device(ctrl.net.gateway)
    assert ctrl.monitor_device(ctrl.net.gateway) is False
    # self
    me = _add_device(ctrl, ip="192.168.1.50")
    me.status = "self"
    assert ctrl.monitor_device(me.ip) is False
    assert calls == [], "no interception may target the gateway or self"


def test_toggle_dns_spoof_propagates_start_result(monkeypatch):
    ctrl = _ctrl(monkeypatch)
    dev = _add_device(ctrl)

    monkeypatch.setattr(ctrl.dns, "start_spoof", lambda ip: True)
    assert ctrl.toggle_dns_spoof(dev.ip, True) is True

    monkeypatch.setattr(ctrl.dns, "start_spoof", lambda ip: False)
    assert ctrl.toggle_dns_spoof(dev.ip, True) is False, (
        "must report the truth when REDIRECT failed"
    )


def test_toggle_dns_spoof_off_calls_stop(monkeypatch):
    ctrl = _ctrl(monkeypatch)
    dev = _add_device(ctrl)
    stopped: list = []
    monkeypatch.setattr(ctrl.dns, "stop_spoof", lambda ip: stopped.append(ip))

    assert ctrl.toggle_dns_spoof(dev.ip, False) is True
    assert stopped == [dev.ip]


def test_toggle_dns_spoof_refuses_gateway(monkeypatch):
    ctrl = _ctrl(monkeypatch)
    ctrl.devices[ctrl.net.gateway] = Device(ctrl.net.gateway)
    started: list = []
    monkeypatch.setattr(ctrl.dns, "start_spoof", lambda ip: started.append(ip) or True)

    assert ctrl.toggle_dns_spoof(ctrl.net.gateway, True) is False
    assert started == [], "must not redirect the gateway's own DNS"
