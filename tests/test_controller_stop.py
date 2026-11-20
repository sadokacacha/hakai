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

from core import controller as controller_mod
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
    # The evasion restores added to stop() call out to sysctl/ip/nft — stub them
    # so these tests stay hermetic (no real system state touched).
    evasion: dict = {"masq": 0, "cham": 0, "fw": 0}
    monkeypatch.setattr(
        controller_mod,
        "apply_stack_masquerade",
        lambda state: evasion.__setitem__("masq", evasion["masq"] + 1),
    )
    monkeypatch.setattr(
        controller_mod,
        "toggle_chameleon",
        lambda iface, state: evasion.__setitem__("cham", evasion["cham"] + 1),
    )
    monkeypatch.setattr(
        ctrl.firewall, "toggle_stealth", lambda state: evasion.__setitem__("fw", evasion["fw"] + 1)
    )
    calls: list = []
    monkeypatch.setattr(netinfo, "restore_network", lambda net: calls.append(net) or True)
    return ctrl, calls, evasion


def test_stop_runs_restore_even_if_a_step_raises(monkeypatch):
    ctrl, calls, _ = _build(monkeypatch)

    def boom():
        raise RuntimeError("xdp boom")

    monkeypatch.setattr(ctrl.xdp, "unload", boom)

    ctrl.stop()  # must not propagate the RuntimeError

    assert len(calls) == 1, "restore_network must still run when an earlier cleanup step raises"


def test_stop_is_idempotent(monkeypatch):
    ctrl, calls, _ = _build(monkeypatch)
    ctrl.stop()
    ctrl.stop()
    assert len(calls) == 1, "stop() called twice must restore exactly once"


def test_stop_reverts_the_evasion_subsystems(monkeypatch):
    # P9: masquerade sysctls, the chameleon MTU/MSS rule, and the ghost-firewall
    # nft table are independently toggleable and used to leak on a normal close
    # because stop() didn't revert them.
    ctrl, calls, evasion = _build(monkeypatch)

    ctrl.stop()

    assert len(calls) == 1
    assert evasion["masq"] == 1, "stop() must revert stack masquerade"
    assert evasion["cham"] == 1, "stop() must revert the chameleon MTU/MSS shift"
    assert evasion["fw"] == 1, "stop() must tear down the ghost-firewall nft table"


def test_stop_reverts_evasion_even_if_an_earlier_step_raises(monkeypatch):
    ctrl, calls, evasion = _build(monkeypatch)
    monkeypatch.setattr(ctrl.tc, "teardown", lambda: (_ for _ in ()).throw(RuntimeError("tc boom")))

    ctrl.stop()

    assert evasion == {"masq": 1, "cham": 1, "fw": 1}, "evasion restores are isolated steps"
    assert len(calls) == 1
