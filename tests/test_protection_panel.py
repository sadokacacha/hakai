"""
Regression tests for ui/protection_panel._probe_state (PP-1).

The modal's button-state refresh used to run its sysctl / ip-link probe
subprocesses synchronously on the Tk thread, freezing the dialog. The state
gathering is now a Tk-free function (`_probe_state`) that a worker thread calls;
this pins that it touches no widgets, probes the right things, and degrades to
"off" on a subprocess failure instead of propagating and breaking the handler.
"""

from __future__ import annotations

import subprocess
import types

from ui.protection_panel import _probe_state


def _fake_ctrl(arp=False, ks=False, stealth=False, fw=False, iface="eth0"):
    return types.SimpleNamespace(
        protector=types.SimpleNamespace(arp_guard_enabled=arp, kill_switch_enabled=ks),
        stealth_active=stealth,
        firewall=types.SimpleNamespace(active=fw),
        net=types.SimpleNamespace(iface=iface),
    )


def test_probe_state_reads_controller_and_subprocess_proxies():
    calls: list[list[str]] = []

    def fake_run(cmd, capture_output, text):
        calls.append(cmd)
        if cmd[0] == "sysctl":
            return subprocess.CompletedProcess(
                cmd, 0, stdout="net.ipv4.ip_default_ttl = 128\n", stderr=""
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="2: wlan0: <...> mtu 1492 ...", stderr="")

    ctrl = _fake_ctrl(arp=True, ks=False, stealth=True, fw=True, iface="wlan0")
    state = _probe_state(ctrl, run=fake_run)

    assert state == {
        "arp": True,
        "ks": False,
        "stealth": True,
        "fw": True,
        "mask": True,
        "cham": True,
    }
    # Probed the right TTL key and the controller's own interface.
    assert ["sysctl", "net.ipv4.ip_default_ttl"] in calls
    assert ["ip", "link", "show", "wlan0"] in calls


def test_probe_state_inactive_proxies_read_off():
    def fake_run(cmd, capture_output, text):
        # TTL 64 (not 128) and MTU 1500 (not 1492) => both proxies OFF.
        return subprocess.CompletedProcess(cmd, 0, stdout="ttl = 64\nmtu 1500", stderr="")

    state = _probe_state(_fake_ctrl(), run=fake_run)
    assert state["mask"] is False
    assert state["cham"] is False
    assert state["arp"] is False


def test_probe_state_survives_subprocess_failure():
    def boom(cmd, capture_output, text):
        raise OSError("no such binary")

    # Must not raise; failed probes degrade to False, controller attrs still read.
    state = _probe_state(_fake_ctrl(arp=True, fw=True), run=boom)
    assert state["mask"] is False
    assert state["cham"] is False
    assert state["arp"] is True
    assert state["fw"] is True
