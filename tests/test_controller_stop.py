"""
Regression tests for core/controller.py shutdown (Phase-2 hunt).

CTL-1  Controller.stop() ran cleanup as a flat sequence: if any step raised
       (e.g. xdp.unload() via bcc), every later step — including the kernel/NIC
       restore_network() — was skipped, leaving host state unrestored. stop()
       also had no reentrancy guard.

Mocked: every side-effectful subsystem call and restore_network is patched, so
these tests touch no real iptables/tc/sysctl state.
"""

from __future__ import annotations

from core.controller import Controller
from system import netinfo
from system.netinfo import NetInfo

# Subsystem teardown methods that would otherwise issue real iptables/tc/sysctl.
_SIDE_EFFECTS = [
    ("arp", "restore_all"),
    ("arp", "stop_watchdog"),
    ("dns", "stop_all"),
    ("xdp", "unload"),
    ("traffic", "stop"),
    ("protector", "stop"),
    ("tc", "teardown"),
    ("ipt", "cleanup"),
    ("ipv6", "stop"),
    ("scanner", "stop_passive_discovery"),
]


def _build(monkeypatch):
    ctrl = Controller(NetInfo(iface="eth0"))
    for attr, meth in _SIDE_EFFECTS:
        monkeypatch.setattr(getattr(ctrl, attr), meth, lambda: None)
    calls: list = []
    monkeypatch.setattr(netinfo, "restore_network", lambda net: calls.append(net) or True)
    return ctrl, calls


def test_stop_runs_restore_even_if_a_step_raises(monkeypatch):
    ctrl, calls = _build(monkeypatch)

    def boom():
        raise RuntimeError("xdp boom")

    monkeypatch.setattr(ctrl.xdp, "unload", boom)

    ctrl.stop()  # must not propagate the RuntimeError

    assert len(calls) == 1, "restore_network must still run when an earlier cleanup step raises"


def test_stop_is_idempotent(monkeypatch):
    ctrl, calls = _build(monkeypatch)
    ctrl.stop()
    ctrl.stop()
    assert len(calls) == 1, "stop() called twice must restore exactly once"
